/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
#include "nm-default.h"
#include "nm-trusttunnel-editor.h"
#include "nm-trusttunnel-config.h"

#include <gtk/gtk.h>

static void trusttunnel_editor_interface_init (NMVpnEditorInterface *iface_class);

#if GTK_CHECK_VERSION (4, 0, 0)
#define entry_get_text(entry) gtk_editable_get_text (GTK_EDITABLE (entry))
#define entry_set_text(entry, value) gtk_editable_set_text (GTK_EDITABLE (entry), value)
#else
#define entry_get_text(entry) gtk_entry_get_text (GTK_ENTRY (entry))
#define entry_set_text(entry, value) gtk_entry_set_text (GTK_ENTRY (entry), value)
#endif

typedef struct {
	GtkWidget *widget;
	GtkWidget *gateway_entry;
	GtkWidget *protocol_combo;
	GtkWidget *sni_entry;
	GtkWidget *client_random_entry;
	GtkWidget *cert_entry;
	GtkWidget *cert_domain_entry;
	char *cert_pem;
	GtkBuilder *builder;
	GtkWidget *username_entry;
	GtkWidget *password_entry;
} TrusttunnelEditorPrivate;

G_DEFINE_TYPE_EXTENDED (TrusttunnelEditor, trusttunnel_editor, G_TYPE_OBJECT, 0,
                        G_ADD_PRIVATE (TrusttunnelEditor)
                        G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_EDITOR,
                                               trusttunnel_editor_interface_init))

#define TRUSTTUNNEL_EDITOR_GET_PRIVATE(o) \
	((TrusttunnelEditorPrivate *) trusttunnel_editor_get_instance_private (TRUSTTUNNEL_EDITOR (o)))

static GObject *
get_widget (NMVpnEditor *iface)
{
	TrusttunnelEditorPrivate *priv = TRUSTTUNNEL_EDITOR_GET_PRIVATE (iface);
	return G_OBJECT (priv->widget);
}

static void
set_data_item (NMSettingVpn *s_vpn, const char *key, const char *value)
{
	if (value && *value)
		nm_setting_vpn_add_data_item (s_vpn, key, value);
	else
		nm_setting_vpn_remove_data_item (s_vpn, key);
}



/* GTK4 signature for "notify::selected"; the extra GParamSpec argument
 * must not land in entry_changed_cb's user data slot. */
static void
entry_changed_notify_cb (GObject *dropdown G_GNUC_UNUSED,
                         GParamSpec *pspec G_GNUC_UNUSED, gpointer user_data)
{
	g_signal_emit_by_name (user_data, "changed");
}

/* Protocol ids in display order; they are the values the daemon
 * expects in upstream_protocol. */
static const char *const protocol_ids[] = { "http3", "http2" };

#define N_PROTOCOLS G_N_ELEMENTS (protocol_ids)

static const char *
protocol_get_active (TrusttunnelEditorPrivate *priv)
{
#if GTK_CHECK_VERSION (4, 0, 0)
	guint idx = gtk_drop_down_get_selected (GTK_DROP_DOWN (priv->protocol_combo));

	return (idx < N_PROTOCOLS) ? protocol_ids[idx] : "http2";
#else
	return gtk_combo_box_get_active_id (GTK_COMBO_BOX (priv->protocol_combo));
#endif
}

static void
protocol_set_active (TrusttunnelEditorPrivate *priv, const char *protocol)
{
	int i;

	for (i = 0; i < (int) N_PROTOCOLS; i++) {
		if (g_strcmp0 (protocol, protocol_ids[i]) == 0)
			break;
	}
	if (i == (int) N_PROTOCOLS)
		i = 1; /* http2 — the default */

#if GTK_CHECK_VERSION (4, 0, 0)
	gtk_drop_down_set_selected (GTK_DROP_DOWN (priv->protocol_combo), (guint) i);
#else
	gtk_combo_box_set_active_id (GTK_COMBO_BOX (priv->protocol_combo),
	                             protocol_ids[i]);
#endif
}

static gboolean
update_connection (NMVpnEditor *iface, NMConnection *connection, GError **error)
{
	TrusttunnelEditorPrivate *priv = TRUSTTUNNEL_EDITOR_GET_PRIVATE (iface);
	NMSettingVpn *s_vpn;
	const char *gateway;
	g_autofree char *host = NULL;
	guint16 port = 0;

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (!s_vpn) {
		s_vpn = (NMSettingVpn *) nm_setting_vpn_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_vpn));
	}

	g_object_set (s_vpn,
	              NM_SETTING_VPN_SERVICE_TYPE, NM_DBUS_SERVICE_TRUSTTUNNEL,
	              NULL);

	gateway = entry_get_text (priv->gateway_entry);
	if (!nm_trusttunnel_config_parse_gateway (gateway, &host, &port)) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             _("Invalid gateway \"%s\": expected host or host:port"),
		             gateway);
		return FALSE;
	}

	/* The certificate domain overrides the TLS server name; it takes a
	 * bare host or address, never a port. */
	{
		const char *cert_domain = entry_get_text (priv->cert_domain_entry);
		guint16 cert_port = 0;

		if (cert_domain && *cert_domain &&
		    (!nm_trusttunnel_config_parse_gateway (cert_domain, NULL, &cert_port) ||
		     cert_port != 0)) {
			g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Invalid certificate domain \"%s\": expected a host "
			               "without a port"),
			             cert_domain);
			return FALSE;
		}
	}

	/* Same format as the TrustTunnel Flutter client: hex, optionally
	 * "hex/hex" with equal lengths; empty is allowed. */
	{
		const char *client_random = entry_get_text (priv->client_random_entry);

		if (!nm_trusttunnel_config_is_valid_client_random (client_random)) {
			g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             _("Invalid client random \"%s\": expected hex, optionally "
			               "\"hex/hex\" with equal lengths"),
			             client_random);
			return FALSE;
		}
	}

	/* The host doubles as the TLS server name; the port, when given, is
	 * kept in its own data item — even the default 443, so that what the
	 * user typed stays visible in the editor. */
	set_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_SERVER, host);
	set_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_ADDRESS, host);
	if (port)
		set_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_PORT, g_strdup_printf ("%u", port));
	else
		nm_setting_vpn_remove_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_PORT);

	set_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_PROTOCOL,
	               protocol_get_active (priv));

	set_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_CUSTOM_SNI,
	               entry_get_text (priv->sni_entry));
	set_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_CLIENT_RANDOM,
	               entry_get_text (priv->client_random_entry));

	set_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_CERT_PEM, priv->cert_pem);

	{
		const char *cert_domain = entry_get_text (priv->cert_domain_entry);

		/* The TLS server name used for certificate verification; when not
		 * given, the gateway host is used. */
		set_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_SERVER,
		               (cert_domain && *cert_domain) ? cert_domain : host);
	}

	set_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_USERNAME,
	               entry_get_text (priv->username_entry));

	/* The password is an agent-owned secret: it is not stored in the
	 * connection file; NetworkManager asks secret agents (GNOME keyring,
	 * via our auth dialog) for it on activation. The field text typed in
	 * the editor is passed to NM as a secret. Drop any legacy plain data
	 * item so the two never diverge. */
	nm_setting_vpn_remove_secret (s_vpn, NM_TRUSTTUNNEL_KEY_PASSWORD);
	set_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_PASSWORD, NULL);
	{
		g_autofree char *flags = g_strdup_printf ("%u",
		                                          (guint) NM_SETTING_SECRET_FLAG_AGENT_OWNED);

		set_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_PASSWORD_FLAGS, flags);
	}
	{
		const char *password = entry_get_text (priv->password_entry);

		if (password && *password)
			nm_setting_vpn_add_secret (s_vpn, NM_TRUSTTUNNEL_KEY_PASSWORD, password);
	}

	return TRUE;
}

static void
entry_changed_cb (GtkEditable *editable, gpointer user_data)
{
	TrusttunnelEditor *self = TRUSTTUNNEL_EDITOR (user_data);

	/* NMVpnEditor consumers (nm-connection-editor, gnome-control-center)
	 * enable their Apply button when this signal is emitted. */
	g_signal_emit_by_name (self, "changed");
}

static GtkWidget *
get_toplevel_window (GtkWidget *widget)
{
#if GTK_CHECK_VERSION (4, 0, 0)
	return GTK_WIDGET (gtk_widget_get_root (widget));
#else
	return gtk_widget_get_toplevel (widget);
#endif
}

static void
cert_apply_file (TrusttunnelEditor *self, const char *path)
{
	TrusttunnelEditorPrivate *priv = TRUSTTUNNEL_EDITOR_GET_PRIVATE (self);
	gchar *contents = NULL;
	gsize len = 0;
	GError *error = NULL;

	if (!g_file_get_contents (path, &contents, &len, &error)) {
		g_warning ("failed to read the certificate: %s", error->message);
		g_error_free (error);
		return;
	}

	if (!strstr (contents, "-----BEGIN")) {
		g_warning ("\"%s\" does not look like a PEM file", path);
		g_free (contents);
		return;
	}

	g_free (priv->cert_pem);
	priv->cert_pem = contents;
	entry_set_text (priv->cert_entry, path);
	g_signal_emit_by_name (self, "changed");
}

#if GTK_CHECK_VERSION (4, 0, 0)

static void
cert_open_cb (GObject *source, GAsyncResult *result, gpointer user_data)
{
	TrusttunnelEditor *self = TRUSTTUNNEL_EDITOR (user_data);
	GtkFileDialog *dialog = GTK_FILE_DIALOG (source);
	GFile *file;
	GError *error = NULL;

	file = gtk_file_dialog_open_finish (dialog, result, &error);
	if (file) {
		char *path = g_file_get_path (file);

		if (path)
			cert_apply_file (self, path);
		g_free (path);
		g_object_unref (file);
	} else if (!g_error_matches (error, GTK_DIALOG_ERROR, GTK_DIALOG_ERROR_DISMISSED)) {
		g_warning ("certificate chooser failed: %s", error->message);
	}
	g_clear_error (&error);
	g_object_unref (dialog);
}

static void
cert_choose_cb (TrusttunnelEditor *self)
{
	TrusttunnelEditorPrivate *priv = TRUSTTUNNEL_EDITOR_GET_PRIVATE (self);
	GtkFileDialog *dialog = gtk_file_dialog_new ();

	gtk_file_dialog_open (dialog,
	                      GTK_WINDOW (get_toplevel_window (priv->cert_entry)),
	                      NULL,
	                      cert_open_cb,
	                      self);
}

#else

static void
cert_choose_cb (TrusttunnelEditor *self)
{
	TrusttunnelEditorPrivate *priv = TRUSTTUNNEL_EDITOR_GET_PRIVATE (self);
	GtkWidget *dialog;
	gchar *path;

	dialog = gtk_file_chooser_dialog_new (_("Select certificate file"),
	                                      GTK_WINDOW (get_toplevel_window (priv->cert_entry)),
	                                      GTK_FILE_CHOOSER_ACTION_OPEN,
	                                      _("_Cancel"), GTK_RESPONSE_CANCEL,
	                                      _("_Open"), GTK_RESPONSE_ACCEPT,
	                                      NULL);
	if (gtk_dialog_run (GTK_DIALOG (dialog)) == GTK_RESPONSE_ACCEPT) {
		path = gtk_file_chooser_get_filename (GTK_FILE_CHOOSER (dialog));
		if (path)
			cert_apply_file (self, path);
		g_free (path);
	}
	gtk_widget_destroy (dialog);
}

#endif

static void
cert_clear_cb (TrusttunnelEditor *self)
{
	TrusttunnelEditorPrivate *priv = TRUSTTUNNEL_EDITOR_GET_PRIVATE (self);

	g_clear_pointer (&priv->cert_pem, g_free);
	entry_set_text (priv->cert_entry, "");
	g_signal_emit_by_name (self, "changed");
}

static void
init_editor_ui (TrusttunnelEditor *self, NMConnection *connection)
{
	TrusttunnelEditorPrivate *priv = TRUSTTUNNEL_EDITOR_GET_PRIVATE (self);
	NMSettingVpn *s_vpn = nm_connection_get_setting_vpn (connection);
	GtkBuilder *builder;
	GError *error = NULL;
	GtkWidget *choose;
	GtkWidget *clear;

	if (!s_vpn) {
		s_vpn = (NMSettingVpn *) nm_setting_vpn_new ();
		g_object_set (s_vpn,
		              NM_SETTING_VPN_SERVICE_TYPE, NM_DBUS_SERVICE_TRUSTTUNNEL,
		              NULL);
		nm_connection_add_setting (connection, NM_SETTING (s_vpn));
	}

	builder = gtk_builder_new ();
	if (!gtk_builder_add_from_resource (builder,
	                                    "/org/freedesktop/network-manager-trusttunnel/nm-trusttunnel-dialog.ui",
	                                    &error)) {
		g_warning ("failed to load the editor UI: %s", error->message);
		g_clear_error (&error);
		g_object_unref (builder);
		return;
	}

#define GET_WIDGET(name) priv->name = GTK_WIDGET (gtk_builder_get_object (builder, #name))
	GET_WIDGET (gateway_entry);
	GET_WIDGET (cert_domain_entry);
	GET_WIDGET (sni_entry);
	GET_WIDGET (username_entry);
	GET_WIDGET (password_entry);
	GET_WIDGET (protocol_combo);
	GET_WIDGET (client_random_entry);
	GET_WIDGET (cert_entry);
	choose = GTK_WIDGET (gtk_builder_get_object (builder, "cert_choose_button"));
	clear = GTK_WIDGET (gtk_builder_get_object (builder, "cert_clear_button"));
	priv->widget = GTK_WIDGET (gtk_builder_get_object (builder, "widget"));
	/* The builder owns the widget tree; keep it for the editor's lifetime
	 * (dispose frees it), exactly like NetworkManager-openvpn does. */
	priv->builder = builder;
#undef GET_WIDGET

	/* Hard cap on the client random, matching the TrustTunnel Flutter
	 * client; the content itself is validated on save. */
	gtk_entry_set_max_length (GTK_ENTRY (priv->client_random_entry),
	                          NM_TRUSTTUNNEL_MAX_FIELD_LENGTH);

	/* Protocol items: the ids are the values the daemon expects in
	 * upstream_protocol. GTK3 shows them in a GtkComboBoxText; GTK4
	 * uses the modern GtkDropDown — same ids, same order. */
#if GTK_CHECK_VERSION (4, 0, 0)
	{
		GtkDropDown *dropdown = GTK_DROP_DOWN (priv->protocol_combo);
		GtkStringList *list;
		GtkExpression *expr;

		list = gtk_string_list_new ((const char *const[]) { "QUIC", "HTTP/2", NULL });
		gtk_drop_down_set_model (dropdown, G_LIST_MODEL (list));
		g_object_unref (list);

		expr = gtk_property_expression_new (GTK_TYPE_STRING_OBJECT, NULL, "string");
		gtk_drop_down_set_expression (dropdown, expr);
		gtk_expression_unref (expr);

		gtk_drop_down_set_selected (dropdown, 1u); /* HTTP/2 */
	}
#else
	gtk_combo_box_text_append (GTK_COMBO_BOX_TEXT (priv->protocol_combo), "http3", "QUIC");
	gtk_combo_box_text_append (GTK_COMBO_BOX_TEXT (priv->protocol_combo), "http2", "HTTP/2");
	gtk_combo_box_set_active_id (GTK_COMBO_BOX (priv->protocol_combo), "http2");
#endif

	g_signal_connect_swapped (choose, "clicked", G_CALLBACK (cert_choose_cb), self);

	{
		const char *addr = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_ADDRESS);
		const char *val;
		guint16 port = 0;
		g_autofree char *gateway = NULL;

		if (!addr || !*addr)
			addr = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_SERVER);

		/* Show the port whenever the user gave one, including 443. */
		val = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_PORT);
		if (val && *val) {
			guint64 parsed = g_ascii_strtoull (val, NULL, 10);

			if (parsed > 0 && parsed <= G_MAXUINT16)
				port = (guint16) parsed;
		}
		if (port) {
			if (addr && *addr) {
				if (addr[0] != '[' && strchr (addr, ':'))
					gateway = g_strdup_printf ("[%s]:%u", addr, port);
				else
					gateway = g_strdup_printf ("%s:%u", addr, port);
			}
		}

		if (addr && *addr)
			entry_set_text (priv->gateway_entry, gateway ? gateway : addr);

		val = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_PROTOCOL);
		protocol_set_active (priv, val);

		val = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_CUSTOM_SNI);
		if (val)
			entry_set_text (priv->sni_entry, val);

		val = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_CLIENT_RANDOM);
		if (val)
			entry_set_text (priv->client_random_entry, val);

		val = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_CERT_PEM);
		if (val && *val) {
			priv->cert_pem = g_strdup (val);
			entry_set_text (priv->cert_entry, _("(certificate stored in profile)"));
		}

		val = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_SERVER);
		if (val && *val) {
			const char *addr = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_ADDRESS);

			if (g_strcmp0 (val, addr) != 0)
				entry_set_text (priv->cert_domain_entry, val);
		}

		val = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_USERNAME);
		if (val)
			entry_set_text (priv->username_entry, val);

		/* The password may live in vpn.secrets (the agent-owned storage
		 * shown when NM hands the secrets over) with a plain data item
		 * only as a legacy fallback. */
		val = nm_setting_vpn_get_secret (s_vpn, NM_TRUSTTUNNEL_KEY_PASSWORD);
		if (!val)
			val = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_PASSWORD);
		if (val)
			entry_set_text (priv->password_entry, val);
	}

	/* Connect only after populating, so that filling the initial values is
	 * not reported as a user modification. */
	g_signal_connect (priv->gateway_entry, "changed", G_CALLBACK (entry_changed_cb), self);
#if GTK_CHECK_VERSION (4, 0, 0)
	g_signal_connect (priv->protocol_combo, "notify::selected",
	                  G_CALLBACK (entry_changed_notify_cb), self);
#else
	g_signal_connect (priv->protocol_combo, "changed",
	                  G_CALLBACK (entry_changed_cb), self);
#endif
	g_signal_connect (priv->sni_entry, "changed", G_CALLBACK (entry_changed_cb), self);
	g_signal_connect (priv->client_random_entry, "changed", G_CALLBACK (entry_changed_cb), self);
	g_signal_connect (priv->username_entry, "changed", G_CALLBACK (entry_changed_cb), self);
	g_signal_connect (priv->password_entry, "changed", G_CALLBACK (entry_changed_cb), self);
	g_signal_connect (priv->cert_domain_entry, "changed", G_CALLBACK (entry_changed_cb), self);
}

NMVpnEditor *
trusttunnel_editor_new (NMConnection *connection, GError **error)
{
	TrusttunnelEditor *editor = g_object_new (TRUSTTUNNEL_TYPE_EDITOR, NULL);
	init_editor_ui (editor, connection);
	return NM_VPN_EDITOR (editor);
}

static void
trusttunnel_editor_init (TrusttunnelEditor *plugin)
{
}

static void
trusttunnel_editor_dispose (GObject *object)
{
	TrusttunnelEditorPrivate *priv = TRUSTTUNNEL_EDITOR_GET_PRIVATE (object);

	g_clear_pointer (&priv->builder, g_object_unref);

	G_OBJECT_CLASS (trusttunnel_editor_parent_class)->dispose (object);
}

static void
trusttunnel_editor_class_init (TrusttunnelEditorClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	object_class->dispose = trusttunnel_editor_dispose;
}

static void
trusttunnel_editor_interface_init (NMVpnEditorInterface *iface_class)
{
	iface_class->get_widget = get_widget;
	iface_class->update_connection = update_connection;
}

G_MODULE_EXPORT NMVpnEditor *
nm_vpn_editor_factory_trusttunnel (NMVpnEditorPlugin *editor_plugin,
                                   NMConnection *connection,
                                   GError **error)
{
	return trusttunnel_editor_new (connection, error);
}

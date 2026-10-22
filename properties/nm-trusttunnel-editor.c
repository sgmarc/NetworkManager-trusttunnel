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
	char *cert_pem;
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
	               gtk_combo_box_get_active_id (GTK_COMBO_BOX (priv->protocol_combo)));

	set_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_CUSTOM_SNI,
	               entry_get_text (priv->sni_entry));
	set_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_CLIENT_RANDOM,
	               entry_get_text (priv->client_random_entry));

	set_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_CERT_PEM, priv->cert_pem);

	set_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_USERNAME,
	               entry_get_text (priv->username_entry));

	/* Keep it simple for the first prototype: the password is a plain data
	 * item, exactly like `nmcli ... vpn.data "password=..."` stores it.
	 * Drop any legacy stored secret so the two never diverge. */
	set_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_PASSWORD,
	               entry_get_text (priv->password_entry));
	nm_setting_vpn_remove_secret (s_vpn, NM_TRUSTTUNNEL_KEY_PASSWORD);

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

static void
box_append (GtkBox *box, GtkWidget *child)
{
#if GTK_CHECK_VERSION (4, 0, 0)
	gtk_box_append (box, child);
#else
	gtk_box_pack_start (box, child, TRUE, TRUE, 0);
#endif
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
	GtkWidget *grid;
	GtkWidget *label;
	int row = 0;

	if (!s_vpn) {
		s_vpn = (NMSettingVpn *) nm_setting_vpn_new ();
		g_object_set (s_vpn,
		              NM_SETTING_VPN_SERVICE_TYPE, NM_DBUS_SERVICE_TRUSTTUNNEL,
		              NULL);
		nm_connection_add_setting (connection, NM_SETTING (s_vpn));
	}

	grid = gtk_grid_new ();
	gtk_grid_set_row_spacing (GTK_GRID (grid), 10);
	gtk_grid_set_column_spacing (GTK_GRID (grid), 12);
#if !GTK_CHECK_VERSION (4, 0, 0)
	gtk_container_set_border_width (GTK_CONTAINER (grid), 12);
#endif

	label = gtk_label_new (_("Gateway:"));
	gtk_widget_set_halign (label, GTK_ALIGN_START);
	priv->gateway_entry = gtk_entry_new ();
	gtk_entry_set_placeholder_text (GTK_ENTRY (priv->gateway_entry), _("host or host:port"));
	gtk_grid_attach (GTK_GRID (grid), label, 0, row, 1, 1);
	gtk_grid_attach (GTK_GRID (grid), priv->gateway_entry, 1, row, 1, 1);
	row++;

	label = gtk_label_new (_("Protocol:"));
	gtk_widget_set_halign (label, GTK_ALIGN_START);
	priv->protocol_combo = gtk_combo_box_text_new ();
	gtk_combo_box_text_append (GTK_COMBO_BOX_TEXT (priv->protocol_combo), "http3", "QUIC");
	gtk_combo_box_text_append (GTK_COMBO_BOX_TEXT (priv->protocol_combo), "http2", "HTTP/2");
	gtk_combo_box_set_active_id (GTK_COMBO_BOX (priv->protocol_combo), "http2");
	gtk_grid_attach (GTK_GRID (grid), label, 0, row, 1, 1);
	gtk_grid_attach (GTK_GRID (grid), priv->protocol_combo, 1, row, 1, 1);
	row++;

	label = gtk_label_new (_("Custom SNI:"));
	gtk_widget_set_halign (label, GTK_ALIGN_START);
	priv->sni_entry = gtk_entry_new ();
	gtk_grid_attach (GTK_GRID (grid), label, 0, row, 1, 1);
	gtk_grid_attach (GTK_GRID (grid), priv->sni_entry, 1, row, 1, 1);
	row++;

	label = gtk_label_new (_("Client random:"));
	gtk_widget_set_halign (label, GTK_ALIGN_START);
	priv->client_random_entry = gtk_entry_new ();
	gtk_grid_attach (GTK_GRID (grid), label, 0, row, 1, 1);
	gtk_grid_attach (GTK_GRID (grid), priv->client_random_entry, 1, row, 1, 1);
	row++;

	label = gtk_label_new (_("Certificate:"));
	gtk_widget_set_halign (label, GTK_ALIGN_START);
	{
		GtkWidget *box = gtk_box_new (GTK_ORIENTATION_HORIZONTAL, 6);
		GtkWidget *choose = gtk_button_new_with_mnemonic (_("Choose _file…"));
		GtkWidget *clear = gtk_button_new_with_mnemonic (_("_Clear"));

		priv->cert_entry = gtk_entry_new ();
		gtk_editable_set_editable (GTK_EDITABLE (priv->cert_entry), FALSE);
		gtk_entry_set_placeholder_text (GTK_ENTRY (priv->cert_entry), _("system storage"));
		gtk_widget_set_hexpand (priv->cert_entry, TRUE);
		box_append (GTK_BOX (box), priv->cert_entry);
		box_append (GTK_BOX (box), choose);
		box_append (GTK_BOX (box), clear);
		g_signal_connect_swapped (choose, "clicked", G_CALLBACK (cert_choose_cb), self);
		g_signal_connect_swapped (clear, "clicked", G_CALLBACK (cert_clear_cb), self);
		gtk_grid_attach (GTK_GRID (grid), label, 0, row, 1, 1);
		gtk_grid_attach (GTK_GRID (grid), box, 1, row, 1, 1);
		row++;
	}

	label = gtk_label_new (_("Username:"));
	gtk_widget_set_halign (label, GTK_ALIGN_START);
	priv->username_entry = gtk_entry_new ();
	gtk_grid_attach (GTK_GRID (grid), label, 0, row, 1, 1);
	gtk_grid_attach (GTK_GRID (grid), priv->username_entry, 1, row, 1, 1);
	row++;

	label = gtk_label_new (_("Password:"));
	gtk_widget_set_halign (label, GTK_ALIGN_START);
	priv->password_entry = gtk_entry_new ();
	gtk_entry_set_visibility (GTK_ENTRY (priv->password_entry), FALSE);
	gtk_grid_attach (GTK_GRID (grid), label, 0, row, 1, 1);
	gtk_grid_attach (GTK_GRID (grid), priv->password_entry, 1, row, 1, 1);
	row++;

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
		gtk_combo_box_set_active_id (GTK_COMBO_BOX (priv->protocol_combo),
		                             g_strcmp0 (val, "http3") == 0 ? "http3" : "http2");

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

		val = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_USERNAME);
		if (val)
			entry_set_text (priv->username_entry, val);

		val = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_PASSWORD);
		if (!val)
			val = nm_setting_vpn_get_secret (s_vpn, NM_TRUSTTUNNEL_KEY_PASSWORD);
		if (val)
			entry_set_text (priv->password_entry, val);
	}

	/* Connect only after populating, so that filling the initial values is
	 * not reported as a user modification. */
	g_signal_connect (priv->gateway_entry, "changed", G_CALLBACK (entry_changed_cb), self);
	g_signal_connect (priv->protocol_combo, "changed", G_CALLBACK (entry_changed_cb), self);
	g_signal_connect (priv->sni_entry, "changed", G_CALLBACK (entry_changed_cb), self);
	g_signal_connect (priv->client_random_entry, "changed", G_CALLBACK (entry_changed_cb), self);
	g_signal_connect (priv->username_entry, "changed", G_CALLBACK (entry_changed_cb), self);
	g_signal_connect (priv->password_entry, "changed", G_CALLBACK (entry_changed_cb), self);

#if GTK_CHECK_VERSION (4, 0, 0)
	gtk_widget_set_visible (grid, TRUE);
#else
	gtk_widget_show_all (grid);
#endif
	priv->widget = grid;
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
trusttunnel_editor_class_init (TrusttunnelEditorClass *req_class)
{
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

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
	GtkWidget *dns_view;
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

static char *
dns_view_get_text (TrusttunnelEditorPrivate *priv)
{
	GtkTextBuffer *buffer = gtk_text_view_get_buffer (GTK_TEXT_VIEW (priv->dns_view));
	GtkTextIter start, end;

	gtk_text_buffer_get_bounds (buffer, &start, &end);
	return gtk_text_buffer_get_text (buffer, &start, &end, FALSE);
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

	{
		g_autofree char *dns_text = dns_view_get_text (priv);
		g_auto(GStrv) lines = g_strsplit (dns_text, "\n", -1);
		g_autoptr(GPtrArray) list = g_ptr_array_new_with_free_func (g_free);
		guint i;

		for (i = 0; lines[i]; i++) {
			char *item = g_strstrip (lines[i]);

			if (*item)
				g_ptr_array_add (list, g_strdup (item));
		}
		g_ptr_array_add (list, NULL);

		if (list->len > 1) {
			set_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_DNS_SERVERS,
			               g_strjoinv (",", (char **) list->pdata));
		} else {
			nm_setting_vpn_remove_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_DNS_SERVERS);
		}
	}

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
dns_buffer_changed_cb (GtkTextBuffer *buffer, gpointer user_data)
{
	TrusttunnelEditor *self = TRUSTTUNNEL_EDITOR (user_data);

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

	label = gtk_label_new (_("DNS servers:"));
	gtk_widget_set_halign (label, GTK_ALIGN_START);
	gtk_widget_set_valign (label, GTK_ALIGN_START);
	priv->dns_view = gtk_text_view_new ();
	gtk_text_view_set_accepts_tab (GTK_TEXT_VIEW (priv->dns_view), FALSE);
	gtk_widget_set_size_request (priv->dns_view, -1, 60);
	gtk_grid_attach (GTK_GRID (grid), label, 0, row, 1, 1);
	gtk_grid_attach (GTK_GRID (grid), priv->dns_view, 1, row, 1, 1);
	row++;

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

		val = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_DNS_SERVERS);
		if (val && *val) {
			g_auto(GStrv) list = g_strsplit (val, ",", -1);
			g_autofree char *text = g_strjoinv ("\n", list);

			gtk_text_buffer_set_text (gtk_text_view_get_buffer (GTK_TEXT_VIEW (priv->dns_view)),
			                          text, -1);
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
	g_signal_connect (gtk_text_view_get_buffer (GTK_TEXT_VIEW (priv->dns_view)),
	                  "changed", G_CALLBACK (dns_buffer_changed_cb), self);
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

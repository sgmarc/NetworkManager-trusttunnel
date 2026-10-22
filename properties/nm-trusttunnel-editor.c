/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
#include "nm-default.h"
#include "nm-trusttunnel-editor.h"

#include <gtk/gtk.h>

static void trusttunnel_editor_interface_init (NMVpnEditorInterface *iface_class);

typedef struct {
	GtkWidget *widget;
	GtkWidget *server_entry;
	GtkWidget *username_entry;
	GtkWidget *password_entry;
	GtkWidget *protocol_combo;
	GtkWidget *client_binary_entry;
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

static gboolean
update_connection (NMVpnEditor *iface, NMConnection *connection, GError **error)
{
	TrusttunnelEditorPrivate *priv = TRUSTTUNNEL_EDITOR_GET_PRIVATE (iface);
	NMSettingVpn *s_vpn;
	const char *str;

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (!s_vpn) {
		s_vpn = (NMSettingVpn *) nm_setting_vpn_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_vpn));
	}

	g_object_set (s_vpn,
	              NM_SETTING_VPN_SERVICE_TYPE, NM_DBUS_SERVICE_TRUSTTUNNEL,
	              NULL);

	str = gtk_entry_get_text (GTK_ENTRY (priv->server_entry));
	if (str && strlen (str) > 0) {
		nm_setting_vpn_add_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_SERVER, str);
	} else {
		nm_setting_vpn_remove_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_SERVER);
	}

	str = gtk_entry_get_text (GTK_ENTRY (priv->username_entry));
	if (str && strlen (str) > 0) {
		nm_setting_vpn_add_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_USERNAME, str);
	} else {
		nm_setting_vpn_remove_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_USERNAME);
	}

	str = gtk_entry_get_text (GTK_ENTRY (priv->password_entry));
	if (str && strlen (str) > 0) {
		nm_setting_vpn_add_secret (s_vpn, NM_TRUSTTUNNEL_KEY_PASSWORD, str);
	} else {
		nm_setting_vpn_remove_secret (s_vpn, NM_TRUSTTUNNEL_KEY_PASSWORD);
	}

	str = gtk_combo_box_text_get_active_text (GTK_COMBO_BOX_TEXT (priv->protocol_combo));
	if (str && strlen (str) > 0) {
		nm_setting_vpn_add_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_PROTOCOL, str);
	} else {
		nm_setting_vpn_remove_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_PROTOCOL);
	}

	str = gtk_entry_get_text (GTK_ENTRY (priv->client_binary_entry));
	if (str && strlen (str) > 0) {
		nm_setting_vpn_add_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_CLIENT_BINARY, str);
	} else {
		nm_setting_vpn_remove_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_CLIENT_BINARY);
	}

	return TRUE;
}

static void
init_editor_ui (TrusttunnelEditor *self, NMConnection *connection)
{
	TrusttunnelEditorPrivate *priv = TRUSTTUNNEL_EDITOR_GET_PRIVATE (self);
	NMSettingVpn *s_vpn = nm_connection_get_setting_vpn (connection);

	GtkWidget *grid = gtk_grid_new ();
	gtk_grid_set_row_spacing (GTK_GRID (grid), 10);
	gtk_grid_set_column_spacing (GTK_GRID (grid), 12);
	gtk_container_set_border_width (GTK_CONTAINER (grid), 12);

	int row = 0;

	/* Server / Hostname */
	GtkWidget *lbl_srv = gtk_label_new (_("Server:"));
	gtk_widget_set_halign (lbl_srv, GTK_ALIGN_START);
	priv->server_entry = gtk_entry_new ();
	gtk_grid_attach (GTK_GRID (grid), lbl_srv, 0, row, 1, 1);
	gtk_grid_attach (GTK_GRID (grid), priv->server_entry, 1, row, 1, 1);
	row++;

	/* Username */
	GtkWidget *lbl_user = gtk_label_new (_("Username:"));
	gtk_widget_set_halign (lbl_user, GTK_ALIGN_START);
	priv->username_entry = gtk_entry_new ();
	gtk_grid_attach (GTK_GRID (grid), lbl_user, 0, row, 1, 1);
	gtk_grid_attach (GTK_GRID (grid), priv->username_entry, 1, row, 1, 1);
	row++;

	/* Password */
	GtkWidget *lbl_pass = gtk_label_new (_("Password:"));
	gtk_widget_set_halign (lbl_pass, GTK_ALIGN_START);
	priv->password_entry = gtk_entry_new ();
	gtk_entry_set_visibility (GTK_ENTRY (priv->password_entry), FALSE);
	gtk_grid_attach (GTK_GRID (grid), lbl_pass, 0, row, 1, 1);
	gtk_grid_attach (GTK_GRID (grid), priv->password_entry, 1, row, 1, 1);
	row++;

	/* Protocol */
	GtkWidget *lbl_proto = gtk_label_new (_("Protocol:"));
	gtk_widget_set_halign (lbl_proto, GTK_ALIGN_START);
	priv->protocol_combo = gtk_combo_box_text_new ();
	gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (priv->protocol_combo), "http2");
	gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT (priv->protocol_combo), "quic");
	gtk_combo_box_set_active (GTK_COMBO_BOX (priv->protocol_combo), 0);
	gtk_grid_attach (GTK_GRID (grid), lbl_proto, 0, row, 1, 1);
	gtk_grid_attach (GTK_GRID (grid), priv->protocol_combo, 1, row, 1, 1);
	row++;

	/* Client Binary Path */
	GtkWidget *lbl_bin = gtk_label_new (_("Client Binary Path:"));
	gtk_widget_set_halign (lbl_bin, GTK_ALIGN_START);
	priv->client_binary_entry = gtk_entry_new ();
	gtk_entry_set_placeholder_text (GTK_ENTRY (priv->client_binary_entry), "trusttunnel_client (default in PATH)");
	gtk_grid_attach (GTK_GRID (grid), lbl_bin, 0, row, 1, 1);
	gtk_grid_attach (GTK_GRID (grid), priv->client_binary_entry, 1, row, 1, 1);
	row++;

	/* Populate existing values */
	if (s_vpn) {
		const char *val;
		val = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_SERVER);
		if (val) gtk_entry_set_text (GTK_ENTRY (priv->server_entry), val);

		val = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_USERNAME);
		if (val) gtk_entry_set_text (GTK_ENTRY (priv->username_entry), val);

		val = nm_setting_vpn_get_secret (s_vpn, NM_TRUSTTUNNEL_KEY_PASSWORD);
		if (val) gtk_entry_set_text (GTK_ENTRY (priv->password_entry), val);

		val = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_PROTOCOL);
		if (val && g_ascii_strcasecmp (val, "quic") == 0) {
			gtk_combo_box_set_active (GTK_COMBO_BOX (priv->protocol_combo), 1);
		} else {
			gtk_combo_box_set_active (GTK_COMBO_BOX (priv->protocol_combo), 0);
		}

		val = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_CLIENT_BINARY);
		if (val) gtk_entry_set_text (GTK_ENTRY (priv->client_binary_entry), val);
	}

	gtk_widget_show_all (grid);
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

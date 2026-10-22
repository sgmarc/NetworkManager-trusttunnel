/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
#include "nm-default.h"
#include "nm-trusttunnel-editor.h"

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
	GtkWidget *server_entry;
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

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (!s_vpn) {
		s_vpn = (NMSettingVpn *) nm_setting_vpn_new ();
		nm_connection_add_setting (connection, NM_SETTING (s_vpn));
	}

	g_object_set (s_vpn,
	              NM_SETTING_VPN_SERVICE_TYPE, NM_DBUS_SERVICE_TRUSTTUNNEL,
	              NULL);

	set_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_SERVER,
	               entry_get_text (priv->server_entry));
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

	label = gtk_label_new (_("Server:"));
	gtk_widget_set_halign (label, GTK_ALIGN_START);
	priv->server_entry = gtk_entry_new ();
	gtk_grid_attach (GTK_GRID (grid), label, 0, row, 1, 1);
	gtk_grid_attach (GTK_GRID (grid), priv->server_entry, 1, row, 1, 1);
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
		const char *val = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_SERVER);
		if (val)
			entry_set_text (priv->server_entry, val);

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
	g_signal_connect (priv->server_entry, "changed", G_CALLBACK (entry_changed_cb), self);
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

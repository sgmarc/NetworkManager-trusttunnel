/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
#include "nm-default.h"
#include "nm-trusttunnel-editor-plugin.h"
#include "nm-utils/nm-vpn-plugin-utils.h"

#define TRUSTTUNNEL_PLUGIN_NAME    _("TrustTunnel")
#define TRUSTTUNNEL_PLUGIN_DESC    _("Client for TrustTunnel protocol (HTTP/2, QUIC)")
#define TRUSTTUNNEL_PLUGIN_SERVICE NM_DBUS_SERVICE_TRUSTTUNNEL

enum {
	PROP_0,
	PROP_NAME,
	PROP_DESC,
	PROP_SERVICE
};

static void trusttunnel_editor_plugin_interface_init (NMVpnEditorPluginInterface *iface_class);

G_DEFINE_TYPE_EXTENDED (TrusttunnelEditorPlugin, trusttunnel_editor_plugin, G_TYPE_OBJECT, 0,
                        G_IMPLEMENT_INTERFACE (NM_TYPE_VPN_EDITOR_PLUGIN,
                                               trusttunnel_editor_plugin_interface_init))

static guint32
get_capabilities (NMVpnEditorPlugin *iface)
{
	return (NM_VPN_EDITOR_PLUGIN_CAPABILITY_IMPORT |
	        NM_VPN_EDITOR_PLUGIN_CAPABILITY_EXPORT |
	        NM_VPN_EDITOR_PLUGIN_CAPABILITY_IPV6);
}

static NMConnection *
import (NMVpnEditorPlugin *iface, const char *path, GError **error)
{
	NMConnection *connection = NULL;
	NMSettingConnection *s_con;
	NMSettingVpn *s_vpn;
	char *basename;

	connection = nm_simple_connection_new ();
	s_con = (NMSettingConnection *) nm_setting_connection_new ();
	s_vpn = (NMSettingVpn *) nm_setting_vpn_new ();

	basename = g_path_get_basename (path);
	g_object_set (s_con,
	              NM_SETTING_CONNECTION_ID, basename,
	              NM_SETTING_CONNECTION_TYPE, NM_SETTING_VPN_SETTING_NAME,
	              NULL);
	g_free (basename);

	g_object_set (s_vpn,
	              NM_SETTING_VPN_SERVICE_TYPE, NM_DBUS_SERVICE_TRUSTTUNNEL,
	              NULL);

	nm_setting_vpn_add_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_CONFIG_FILE, path);

	nm_connection_add_setting (connection, NM_SETTING (s_con));
	nm_connection_add_setting (connection, NM_SETTING (s_vpn));

	return connection;
}

static gboolean
export (NMVpnEditorPlugin *iface,
        const char *path,
        NMConnection *connection,
        GError **error)
{
	NMSettingVpn *s_vpn = nm_connection_get_setting_vpn (connection);
	if (!s_vpn) {
		g_set_error (error, NMV_EDITOR_PLUGIN_ERROR, NMV_EDITOR_PLUGIN_ERROR_FAILED,
		             "No VPN settings found");
		return FALSE;
	}
	const char *config_file = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_CONFIG_FILE);
	if (config_file && g_file_test (config_file, G_FILE_TEST_EXISTS)) {
		char *content = NULL;
		gsize len = 0;
		if (g_file_get_contents (config_file, &content, &len, error)) {
			gboolean ret = g_file_set_contents (path, content, len, error);
			g_free (content);
			return ret;
		}
		return FALSE;
	}
	return TRUE;
}

static char *
get_suggested_filename (NMVpnEditorPlugin *iface, NMConnection *connection)
{
	NMSettingConnection *s_con = nm_connection_get_setting_connection (connection);
	if (!s_con)
		return NULL;
	return g_strdup_printf ("%s.toml", nm_setting_connection_get_id (s_con));
}

static NMVpnEditor *
_call_editor_factory (gpointer factory,
                      NMVpnEditorPlugin *editor_plugin,
                      NMConnection *connection,
                      gpointer user_data,
                      GError **error)
{
	return ((NMVpnEditorFactory) factory) (editor_plugin, connection, error);
}

static NMVpnEditor *
get_editor (NMVpnEditorPlugin *iface, NMConnection *connection, GError **error)
{
	return nm_vpn_plugin_utils_load_editor ("libnm-gtk3-vpn-plugin-trusttunnel-editor.so",
	                                        "nm_vpn_editor_factory_trusttunnel",
	                                        _call_editor_factory,
	                                        iface,
	                                        connection,
	                                        NULL,
	                                        error);
}

static void
get_property (GObject *object, guint prop_id, GValue *value, GParamSpec *pspec)
{
	switch (prop_id) {
	case PROP_NAME:
		g_value_set_string (value, TRUSTTUNNEL_PLUGIN_NAME);
		break;
	case PROP_DESC:
		g_value_set_string (value, TRUSTTUNNEL_PLUGIN_DESC);
		break;
	case PROP_SERVICE:
		g_value_set_string (value, TRUSTTUNNEL_PLUGIN_SERVICE);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
trusttunnel_editor_plugin_class_init (TrusttunnelEditorPluginClass *req_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (req_class);

	object_class->get_property = get_property;

	g_object_class_override_property (object_class, PROP_NAME, NM_VPN_EDITOR_PLUGIN_NAME);
	g_object_class_override_property (object_class, PROP_DESC, NM_VPN_EDITOR_PLUGIN_DESCRIPTION);
	g_object_class_override_property (object_class, PROP_SERVICE, NM_VPN_EDITOR_PLUGIN_SERVICE);
}

static void
trusttunnel_editor_plugin_init (TrusttunnelEditorPlugin *plugin)
{
}

static void
trusttunnel_editor_plugin_interface_init (NMVpnEditorPluginInterface *iface_class)
{
	iface_class->get_editor = get_editor;
	iface_class->get_capabilities = get_capabilities;
	iface_class->import_from_file = import;
	iface_class->export_to_file = export;
	iface_class->get_suggested_filename = get_suggested_filename;
}

G_MODULE_EXPORT NMVpnEditorPlugin *
nm_vpn_editor_plugin_factory (GError **error)
{
	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	return g_object_new (TRUSTTUNNEL_TYPE_EDITOR_PLUGIN, NULL);
}

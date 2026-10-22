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
	/* Import and export are temporarily unavailable: both used to pass a file
	 * path to the root service, which must not read user supplied files. They
	 * will return once the TOML is parsed and validated in the user session. */
	return NM_VPN_EDITOR_PLUGIN_CAPABILITY_IPV6;
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
}

G_MODULE_EXPORT NMVpnEditorPlugin *
nm_vpn_editor_plugin_factory (GError **error)
{
	if (error)
		g_return_val_if_fail (*error == NULL, NULL);

	return g_object_new (TRUSTTUNNEL_TYPE_EDITOR_PLUGIN, NULL);
}

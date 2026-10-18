/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
#ifndef NM_TRUSTTUNNEL_SERVICE_H
#define NM_TRUSTTUNNEL_SERVICE_H

#include <glib-object.h>
#include <NetworkManager.h>

#define NM_TYPE_TRUSTTUNNEL_PLUGIN            (nm_trusttunnel_plugin_get_type ())
#define NM_TRUSTTUNNEL_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), NM_TYPE_TRUSTTUNNEL_PLUGIN, NMTrusttunnelPlugin))
#define NM_TRUSTTUNNEL_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), NM_TYPE_TRUSTTUNNEL_PLUGIN, NMTrusttunnelPluginClass))
#define NM_IS_TRUSTTUNNEL_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), NM_TYPE_TRUSTTUNNEL_PLUGIN))
#define NM_IS_TRUSTTUNNEL_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), NM_TYPE_TRUSTTUNNEL_PLUGIN))
#define NM_TRUSTTUNNEL_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), NM_TYPE_TRUSTTUNNEL_PLUGIN, NMTrusttunnelPluginClass))

typedef struct {
	NMVpnServicePlugin parent;
} NMTrusttunnelPlugin;

typedef struct {
	NMVpnServicePluginClass parent;
} NMTrusttunnelPluginClass;

GType nm_trusttunnel_plugin_get_type (void);

NMTrusttunnelPlugin *nm_trusttunnel_plugin_new (const char *bus_name);

#endif /* NM_TRUSTTUNNEL_SERVICE_H */

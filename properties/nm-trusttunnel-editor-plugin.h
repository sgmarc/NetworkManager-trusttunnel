/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
#ifndef NM_TRUSTTUNNEL_EDITOR_PLUGIN_H
#define NM_TRUSTTUNNEL_EDITOR_PLUGIN_H

#include <glib-object.h>

#define TRUSTTUNNEL_TYPE_EDITOR_PLUGIN            (trusttunnel_editor_plugin_get_type ())
#define TRUSTTUNNEL_EDITOR_PLUGIN(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), TRUSTTUNNEL_TYPE_EDITOR_PLUGIN, TrusttunnelEditorPlugin))
#define TRUSTTUNNEL_EDITOR_PLUGIN_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), TRUSTTUNNEL_TYPE_EDITOR_PLUGIN, TrusttunnelEditorPluginClass))
#define TRUSTTUNNEL_IS_EDITOR_PLUGIN(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), TRUSTTUNNEL_TYPE_EDITOR_PLUGIN))
#define TRUSTTUNNEL_IS_EDITOR_PLUGIN_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), TRUSTTUNNEL_TYPE_EDITOR_PLUGIN))
#define TRUSTTUNNEL_EDITOR_PLUGIN_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), TRUSTTUNNEL_TYPE_EDITOR_PLUGIN, TrusttunnelEditorPluginClass))

typedef struct {
	GObject parent;
} TrusttunnelEditorPlugin;

typedef struct {
	GObjectClass parent;
} TrusttunnelEditorPluginClass;

GType trusttunnel_editor_plugin_get_type (void);

typedef NMVpnEditor *(*NMVpnEditorFactory) (NMVpnEditorPlugin *editor_plugin,
                                            NMConnection *connection,
                                            GError **error);

#endif /* NM_TRUSTTUNNEL_EDITOR_PLUGIN_H */

/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
#ifndef NM_TRUSTTUNNEL_EDITOR_H
#define NM_TRUSTTUNNEL_EDITOR_H

#include <glib-object.h>
#include <NetworkManager.h>

#define TRUSTTUNNEL_TYPE_EDITOR            (trusttunnel_editor_get_type ())
#define TRUSTTUNNEL_EDITOR(obj)            (G_TYPE_CHECK_INSTANCE_CAST ((obj), TRUSTTUNNEL_TYPE_EDITOR, TrusttunnelEditor))
#define TRUSTTUNNEL_EDITOR_CLASS(klass)    (G_TYPE_CHECK_CLASS_CAST ((klass), TRUSTTUNNEL_TYPE_EDITOR, TrusttunnelEditorClass))
#define TRUSTTUNNEL_IS_EDITOR(obj)         (G_TYPE_CHECK_INSTANCE_TYPE ((obj), TRUSTTUNNEL_TYPE_EDITOR))
#define TRUSTTUNNEL_IS_EDITOR_CLASS(klass) (G_TYPE_CHECK_CLASS_TYPE ((klass), TRUSTTUNNEL_TYPE_EDITOR))
#define TRUSTTUNNEL_EDITOR_GET_CLASS(obj)  (G_TYPE_INSTANCE_GET_CLASS ((obj), TRUSTTUNNEL_TYPE_EDITOR, TrusttunnelEditorClass))

typedef struct {
	GObject parent;
} TrusttunnelEditor;

typedef struct {
	GObjectClass parent;
} TrusttunnelEditorClass;

GType trusttunnel_editor_get_type (void);

NMVpnEditor *trusttunnel_editor_new (NMConnection *connection, GError **error);

#endif /* NM_TRUSTTUNNEL_EDITOR_H */

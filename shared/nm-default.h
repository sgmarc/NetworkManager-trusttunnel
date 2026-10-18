/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
#ifndef __NM_DEFAULT_H__
#define __NM_DEFAULT_H__

#include <config.h>
#include <glib.h>
#include <glib/gi18n.h>
#include <gio/gio.h>
#include <NetworkManager.h>

#include "nm-service-defines.h"

#define NMV_EDITOR_PLUGIN_ERROR                  NM_CONNECTION_ERROR
#define NMV_EDITOR_PLUGIN_ERROR_FAILED           NM_CONNECTION_ERROR_FAILED
#define NMV_EDITOR_PLUGIN_ERROR_INVALID_PROPERTY NM_CONNECTION_ERROR_INVALID_PROPERTY
#define NMV_EDITOR_PLUGIN_ERROR_MISSING_PROPERTY NM_CONNECTION_ERROR_MISSING_PROPERTY
#define NMV_EDITOR_PLUGIN_ERROR_FILE_NOT_VPN     NM_CONNECTION_ERROR_FAILED
#define NMV_EDITOR_PLUGIN_ERROR_FILE_NOT_READABLE NM_CONNECTION_ERROR_FAILED
#define NMV_EDITOR_PLUGIN_ERROR_FILE_INVALID     NM_CONNECTION_ERROR_FAILED

#endif /* __NM_DEFAULT_H__ */

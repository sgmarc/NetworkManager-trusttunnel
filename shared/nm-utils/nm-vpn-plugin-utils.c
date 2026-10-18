/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
#include "nm-default.h"
#include "nm-vpn-plugin-utils.h"

#include <dlfcn.h>

NMVpnEditor *
nm_vpn_plugin_utils_load_editor (const char *module_name,
                                 const char *factory_name,
                                 NMVpnPluginUtilsEditorFactory editor_factory,
                                 NMVpnEditorPlugin *editor_plugin,
                                 NMConnection *connection,
                                 gpointer user_data,
                                 GError **error)
{
	static struct {
		gpointer factory;
		void *dl_module;
		char *module_name;
		char *factory_name;
	} cached = { 0 };
	NMVpnEditor *editor;
	char *module_path = NULL;
	char *dirname = NULL;
	Dl_info plugin_info;

	g_return_val_if_fail (module_name, NULL);
	g_return_val_if_fail (factory_name && factory_name[0], NULL);
	g_return_val_if_fail (editor_factory, NULL);
	g_return_val_if_fail (NM_IS_VPN_EDITOR_PLUGIN (editor_plugin), NULL);
	g_return_val_if_fail (NM_IS_CONNECTION (connection), NULL);
	g_return_val_if_fail (!error || !*error, NULL);

	if (!g_path_is_absolute (module_name)) {
		if (dladdr (editor_factory, &plugin_info) && plugin_info.dli_fname) {
			dirname = g_path_get_dirname (plugin_info.dli_fname);
			module_path = g_build_filename (dirname, module_name, NULL);
			g_free (dirname);
		}
	}

	if (!module_path)
		module_path = g_strdup (module_name);

	if (cached.dl_module &&
	    g_strcmp0 (cached.module_name, module_path) == 0 &&
	    g_strcmp0 (cached.factory_name, factory_name) == 0) {
		g_free (module_path);
		return editor_factory (cached.factory, editor_plugin, connection, user_data, error);
	}

	void *dl_module = dlopen (module_path, RTLD_LAZY | RTLD_LOCAL);
	if (!dl_module) {
		g_set_error (error,
		             NMV_EDITOR_PLUGIN_ERROR,
		             NMV_EDITOR_PLUGIN_ERROR_FAILED,
		             "Failed to load %s: %s", module_path, dlerror ());
		g_free (module_path);
		return NULL;
	}

	gpointer factory = dlsym (dl_module, factory_name);
	if (!factory) {
		g_set_error (error,
		             NMV_EDITOR_PLUGIN_ERROR,
		             NMV_EDITOR_PLUGIN_ERROR_FAILED,
		             "Failed to find %s in %s: %s", factory_name, module_path, dlerror ());
		dlclose (dl_module);
		g_free (module_path);
		return NULL;
	}

	if (cached.dl_module) {
		dlclose (cached.dl_module);
		g_free (cached.module_name);
		g_free (cached.factory_name);
	}

	cached.dl_module = dl_module;
	cached.factory = factory;
	cached.module_name = module_path;
	cached.factory_name = g_strdup (factory_name);

	editor = editor_factory (cached.factory, editor_plugin, connection, user_data, error);
	return editor;
}

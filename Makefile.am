AUTOMAKE_OPTIONS = foreign subdir-objects

dbusservicedir = $(datadir)/dbus-1/system.d
dbusservice_DATA = nm-trusttunnel-service.conf

nmvpnservicedir = $(NM_VPN_SERVICE_DIR)
nmvpnservice_DATA = nm-trusttunnel-service.name

# The plugin directory in the .name file is left empty by default, so that
# NetworkManager resolves the plugin relative to its own plugin directory.
# With --enable-absolute-paths the absolute installation path is written
# instead, which is handy for development builds.
# The .name file also states that the daemon keeps a single session, so
# NetworkManager must not activate two connections of this type at once.
nm-trusttunnel-service.name: $(srcdir)/nm-trusttunnel-service.name.in
	$(AM_V_GEN) sed -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' \
	    -e 's|[@]PLUGINDIR[@]/|@NM_PLUGIN_DIR_NAME_FILE@|g' \
	    $< >$@

CLEANFILES = $(nmvpnservice_DATA)

AM_CPPFLAGS = \
	$(LIBNM_CFLAGS) \
	$(GIO_CFLAGS) \
	-I$(top_srcdir) \
	-I$(top_srcdir)/shared

###############################################################################
# Shared code
###############################################################################

noinst_LTLIBRARIES = shared/libnm-trusttunnel-core.la

shared_libnm_trusttunnel_core_la_SOURCES = \
	shared/nm-trusttunnel-config.c \
	shared/nm-trusttunnel-config.h \
	shared/nm-service-defines.h

shared_libnm_trusttunnel_core_la_CFLAGS = \
	$(LIBNM_CFLAGS)

shared_libnm_trusttunnel_core_la_LIBADD = \
	$(LIBNM_LIBS)

###############################################################################
# Backend VPN daemon
###############################################################################

libexec_PROGRAMS = nm-trusttunnel-service \
	auth-dialog/nm-trusttunnel-auth-dialog

auth_dialog_nm_trusttunnel_auth_dialog_SOURCES = \
	auth-dialog/main.c

auth_dialog_nm_trusttunnel_auth_dialog_CPPFLAGS = \
	$(GIO_CFLAGS) \
	-I$(top_srcdir) \
	-I$(top_srcdir)/shared

auth_dialog_nm_trusttunnel_auth_dialog_LDADD = \
	$(GIO_LIBS)

nm_trusttunnel_service_SOURCES = \
	src/nm-trusttunnel-service.c \
	src/nm-trusttunnel-service.h \
	shared/nm-service-defines.h

nm_trusttunnel_service_LDADD = \
	shared/libnm-trusttunnel-core.la \
	$(LIBNM_LIBS) \
	$(GIO_LIBS)

###############################################################################
# Plugin properties library
###############################################################################

plugindir = $(libdir)/NetworkManager
plugin_LTLIBRARIES = properties/libnm-vpn-plugin-trusttunnel.la

properties_libnm_vpn_plugin_trusttunnel_la_SOURCES = \
	shared/nm-utils/nm-vpn-plugin-utils.c \
	shared/nm-utils/nm-vpn-plugin-utils.h \
	properties/nm-trusttunnel-editor-plugin.c \
	properties/nm-trusttunnel-editor-plugin.h

properties_libnm_vpn_plugin_trusttunnel_la_CFLAGS = \
	$(LIBNM_CFLAGS)

properties_libnm_vpn_plugin_trusttunnel_la_LIBADD = \
	$(LIBNM_LIBS)

properties_libnm_vpn_plugin_trusttunnel_la_LDFLAGS = \
	-avoid-version -module

###############################################################################
# GNOME Editor library
###############################################################################

if WITH_GNOME
plugin_LTLIBRARIES += properties/libnm-gtk3-vpn-plugin-trusttunnel-editor.la

properties_libnm_gtk3_vpn_plugin_trusttunnel_editor_la_SOURCES = \
	properties/nm-trusttunnel-editor.c \
	properties/nm-trusttunnel-editor.h

properties_libnm_gtk3_vpn_plugin_trusttunnel_editor_la_CFLAGS = \
	$(GTK_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_CFLAGS)

properties_libnm_gtk3_vpn_plugin_trusttunnel_editor_la_LIBADD = \
	$(GTK_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_LIBS) \
	shared/libnm-trusttunnel-core.la

properties_libnm_gtk3_vpn_plugin_trusttunnel_editor_la_LDFLAGS = \
	-avoid-version -module
endif

# The GTK4 editor is built from the same sources as the GTK3 one and is used
# by GTK4-based consumers such as gnome-control-center. The plugin stub in
# nm-trusttunnel-editor-plugin.c picks the matching library at runtime.
if WITH_GTK4
plugin_LTLIBRARIES += properties/libnm-gtk4-vpn-plugin-trusttunnel-editor.la

properties_libnm_gtk4_vpn_plugin_trusttunnel_editor_la_SOURCES = \
	properties/nm-trusttunnel-editor.c \
	properties/nm-trusttunnel-editor.h

properties_libnm_gtk4_vpn_plugin_trusttunnel_editor_la_CFLAGS = \
	$(GTK4_CFLAGS) \
	$(LIBNM_CFLAGS) \
	$(LIBNMA_GTK4_CFLAGS)

properties_libnm_gtk4_vpn_plugin_trusttunnel_editor_la_LIBADD = \
	$(GTK4_LIBS) \
	$(LIBNM_LIBS) \
	$(LIBNMA_GTK4_LIBS) \
	shared/libnm-trusttunnel-core.la

properties_libnm_gtk4_vpn_plugin_trusttunnel_editor_la_LDFLAGS = \
	-avoid-version -module
endif


# The GTK4 editor is built from the same sources as the GTK3 one. It is added
# together with the migration of the user interface to a GtkBuilder file,
# because the current editor uses GTK3 only API.

###############################################################################
# Tests
###############################################################################

check_PROGRAMS = tests/test-config

TESTS = $(check_PROGRAMS)

tests_test_config_SOURCES = \
	tests/test-config.c

tests_test_config_CFLAGS = \
	$(LIBNM_CFLAGS)

tests_test_config_LDADD = \
	shared/libnm-trusttunnel-core.la \
	$(LIBNM_LIBS)

EXTRA_DIST = \
	nm-trusttunnel-service.name.in \
	nm-trusttunnel-service.conf \
	autogen.sh \
	shared/nm-default.h

AUTOMAKE_OPTIONS = foreign subdir-objects

dbusservicedir = $(datadir)/dbus-1/system.d
dbusservice_DATA = nm-trusttunnel-service.conf

nmvpnservicedir = $(NM_VPN_SERVICE_DIR)
nmvpnservice_DATA = nm-trusttunnel-service.name

nm-trusttunnel-service.name: $(srcdir)/nm-trusttunnel-service.name.in
	sed -e 's|[@]LIBEXECDIR[@]|$(libexecdir)|g' \
	    -e 's|[@]PLUGINDIR[@]|$(libdir)/NetworkManager|g' \
	    $< >$@

CLEANFILES = $(nmvpnservice_DATA)

AM_CPPFLAGS = \
	$(LIBNM_CFLAGS) \
	$(GIO_CFLAGS) \
	-I$(top_srcdir) \
	-I$(top_srcdir)/shared

libexec_PROGRAMS = nm-trusttunnel-service

nm_trusttunnel_service_SOURCES = \
	src/nm-trusttunnel-service.c \
	src/nm-trusttunnel-service.h \
	shared/nm-service-defines.h

nm_trusttunnel_service_LDADD = \
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
	$(LIBNMA_LIBS)

properties_libnm_gtk3_vpn_plugin_trusttunnel_editor_la_LDFLAGS = \
	-avoid-version -module
endif

EXTRA_DIST = \
	nm-trusttunnel-service.name.in \
	nm-trusttunnel-service.conf \
	autogen.sh

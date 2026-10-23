AC_PREREQ(2.70)

AC_INIT(NetworkManager-trusttunnel, 0.1.0, https://github.com/AdguardTeam/TrustTunnelClient, NetworkManager-trusttunnel)
AM_INIT_AUTOMAKE([1.9 subdir-objects tar-ustar no-dist-gzip dist-xz foreign])
AM_MAINTAINER_MODE

AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_HEADERS([config.h])

AC_USE_SYSTEM_EXTENSIONS

dnl Require programs
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL
LT_INIT([disable-static])

dnl Required headers
AC_CHECK_HEADERS(fcntl.h paths.h sys/ioctl.h sys/time.h syslog.h unistd.h)

AC_TYPE_MODE_T
AC_TYPE_PID_T

AC_FUNC_MEMCMP
AC_CHECK_FUNCS(select socket uname)

ACLOCAL_AMFLAGS="\${ACLOCAL_FLAGS}"
if test -n "$ac_macro_dir"; then
    ACLOCAL_AMFLAGS="-I $ac_macro_dir $ACLOCAL_AMFLAGS"
fi
AC_SUBST([ACLOCAL_AMFLAGS])

dnl Options
AC_ARG_WITH(gnome, AS_HELP_STRING([--without-gnome], [Build without GNOME support]))
AM_CONDITIONAL(WITH_GNOME, test x"$with_gnome" != xno)
if test x"$with_gnome" = xno; then
    with_gnome=no
else
    with_gnome=yes
fi

AC_ARG_WITH(gtk4, AS_HELP_STRING([--with-gtk4], [Build with GTK4 / libnma-gtk4 support]), [], [with_gtk4=no])
AM_CONDITIONAL(WITH_GTK4, test x"$with_gtk4" = xyes)

AC_ARG_ENABLE(absolute-paths, AS_HELP_STRING([--enable-absolute-paths], [Use absolute paths in .name files]))

GETTEXT_PACKAGE=NetworkManager-trusttunnel
AC_SUBST(GETTEXT_PACKAGE)
AC_DEFINE_UNQUOTED(GETTEXT_PACKAGE, "$GETTEXT_PACKAGE", [Gettext package])

PKG_CHECK_MODULES(GIO, gio-unix-2.0 >= 2.32)
AC_SUBST(GIO_CFLAGS)
AC_SUBST(GIO_LIBS)

PKG_CHECK_MODULES(LIBNM, libnm >= 1.2.0)
AC_SUBST(LIBNM_CFLAGS)
AC_SUBST(LIBNM_LIBS)

if test x"$with_gnome" != xno; then
AC_PATH_PROG(GLIB_COMPILE_RESOURCES, glib-compile-resources)

    PKG_CHECK_MODULES(GTK, gtk+-3.0 >= 3.4)
    PKG_CHECK_MODULES(LIBNMA, libnma >= 1.2.0)
fi

if test x"$with_gtk4" = xyes; then
    PKG_CHECK_MODULES(GTK4, gtk4 >= 4.0)
    PKG_CHECK_MODULES(LIBNMA_GTK4, libnma-gtk4 >= 1.8.33)
fi

NM_VPN_SERVICE_DIR=`$PKG_CONFIG --define-variable prefix='\${prefix}' --variable vpnservicedir libnm`
if test -z "$NM_VPN_SERVICE_DIR"; then
    NM_VPN_SERVICE_DIR="${libdir}/NetworkManager/VPN"
fi
AC_SUBST(NM_VPN_SERVICE_DIR)

NM_PLUGIN_DIR="${libdir}/NetworkManager"
AC_SUBST(NM_PLUGIN_DIR)

if test x"$enable_absolute_paths" = xyes; then
    NM_PLUGIN_DIR_NAME_FILE="${NM_PLUGIN_DIR}/"
else
    enable_absolute_paths=no
    NM_PLUGIN_DIR_NAME_FILE=""
fi
AC_SUBST(NM_PLUGIN_DIR_NAME_FILE)

AC_CONFIG_FILES([
Makefile
])
AC_OUTPUT

echo ""
echo "Configuration summary:"
echo "  GNOME support: $with_gnome"
echo "  GTK4 support:  $with_gtk4"
echo "  Absolute paths: $enable_absolute_paths"
echo "  VPN dir:       `echo $NM_VPN_SERVICE_DIR | sed "s|\\\${prefix}|$prefix|g"`"
echo "  Plugin dir:    `echo $NM_PLUGIN_DIR | sed "s|\\\${prefix}|$prefix|g"`"
echo ""

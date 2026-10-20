/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* test-config.c - unit tests for the TrustTunnel configuration model */

#include <glib.h>
#include <glib/gstdio.h>
#include <string.h>

#include "nm-trusttunnel-config.h"
#include "nm-service-defines.h"

static NMSettingVpn *
new_vpn_setting (void)
{
	NMSettingVpn *s_vpn = (NMSettingVpn *) nm_setting_vpn_new ();

	g_object_set (s_vpn,
	              NM_SETTING_VPN_SERVICE_TYPE, NM_DBUS_SERVICE_TRUSTTUNNEL,
	              NULL);
	nm_setting_vpn_add_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_SERVER, "vpn.example.com");
	nm_setting_vpn_add_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_USERNAME, "user");
	nm_setting_vpn_add_secret (s_vpn, NM_TRUSTTUNNEL_KEY_PASSWORD, "secret");

	return s_vpn;
}

static char *
build_toml_for (NMSettingVpn *s_vpn, GError **error)
{
	NMTTrusttunnelConfig *config = nm_trusttunnel_config_from_settings (s_vpn, error);
	char *toml;

	if (!config)
		return NULL;

	toml = nm_trusttunnel_config_to_toml (config, error);
	nm_trusttunnel_config_free (config);

	return toml;
}

static void
test_default_toml (void)
{
	NMSettingVpn *s_vpn = new_vpn_setting ();
	GError *error = NULL;
	char *toml;

	toml = build_toml_for (s_vpn, &error);
	g_assert_no_error (error);
	g_assert_nonnull (toml);

	g_assert_nonnull (strstr (toml, "vpn_mode = \"general\""));
	g_assert_nonnull (strstr (toml, "[endpoint]"));
	g_assert_nonnull (strstr (toml, "hostname = \"vpn.example.com\""));
	g_assert_nonnull (strstr (toml, "addresses = [\"vpn.example.com:443\"]"));
	g_assert_nonnull (strstr (toml, "username = \"user\""));
	g_assert_nonnull (strstr (toml, "password = \"secret\""));
	g_assert_nonnull (strstr (toml, "upstream_protocol = \"http2\""));
	g_assert_nonnull (strstr (toml, "has_ipv6 = true"));
	g_assert_nonnull (strstr (toml, "managed = false"));
	g_assert_nonnull (strstr (toml, "included_routes = []"));
	g_assert_nonnull (strstr (toml, "excluded_routes = []"));

	/* "name" is not a key the daemon understands. */
	g_assert_null (strstr (toml, "\nname = "));
	g_assert_null (strstr (toml, "\nname="));

	g_free (toml);
	g_object_unref (s_vpn);
}

static void
test_dns_servers (void)
{
	NMSettingVpn *s_vpn = new_vpn_setting ();
	GError *error = NULL;
	char *toml;

	/* A leading empty element must not produce a broken array. */
	nm_setting_vpn_add_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_DNS_SERVERS, ",1.1.1.1,8.8.8.8");

	toml = build_toml_for (s_vpn, &error);
	g_assert_no_error (error);
	g_assert_nonnull (strstr (toml, "dns_upstreams = [\"1.1.1.1\", \"8.8.8.8\"]"));
	g_assert_null (strstr (toml, "[,"));

	g_free (toml);
	g_object_unref (s_vpn);
}

static void
test_escaping (void)
{
	NMSettingVpn *s_vpn = new_vpn_setting ();
	GError *error = NULL;
	char *toml;

	nm_setting_vpn_add_secret (s_vpn, NM_TRUSTTUNNEL_KEY_PASSWORD, "a\"b\\c");

	toml = build_toml_for (s_vpn, &error);
	g_assert_no_error (error);
	g_assert_nonnull (strstr (toml, "password = \"a\\\"b\\\\c\""));

	g_free (toml);
	g_object_unref (s_vpn);
}

static void
test_ipv6_address (void)
{
	NMSettingVpn *s_vpn = new_vpn_setting ();
	GError *error = NULL;
	char *toml;

	nm_setting_vpn_add_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_ADDRESS, "2001:db8::1");
	nm_setting_vpn_add_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_PORT, "8443");

	toml = build_toml_for (s_vpn, &error);
	g_assert_no_error (error);
	g_assert_nonnull (strstr (toml, "addresses = [\"[2001:db8::1]:8443\"]"));

	g_free (toml);
	g_object_unref (s_vpn);
}

static void
test_protocol (void)
{
	NMSettingVpn *s_vpn = new_vpn_setting ();
	GError *error = NULL;
	char *toml;

	/* "quic" is a legacy alias for "http3". */
	nm_setting_vpn_add_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_PROTOCOL, "quic");

	toml = build_toml_for (s_vpn, &error);
	g_assert_no_error (error);
	g_assert_nonnull (strstr (toml, "upstream_protocol = \"http3\""));

	g_free (toml);
	g_object_unref (s_vpn);
}

static void
test_required_fields (void)
{
	NMSettingVpn *s_vpn;
	GError *error = NULL;
	char *toml;

	s_vpn = new_vpn_setting ();
	nm_setting_vpn_remove_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_SERVER);
	toml = build_toml_for (s_vpn, &error);
	g_assert_null (toml);
	g_assert_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS);
	g_clear_error (&error);
	g_object_unref (s_vpn);

	s_vpn = new_vpn_setting ();
	nm_setting_vpn_remove_secret (s_vpn, NM_TRUSTTUNNEL_KEY_PASSWORD);
	toml = build_toml_for (s_vpn, &error);
	g_assert_null (toml);
	g_assert_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS);
	g_clear_error (&error);
	g_object_unref (s_vpn);
}

static void
test_invalid_port (void)
{
	NMSettingVpn *s_vpn = new_vpn_setting ();
	GError *error = NULL;
	char *toml;

	nm_setting_vpn_add_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_PORT, "not-a-port");

	toml = build_toml_for (s_vpn, &error);
	g_assert_null (toml);
	g_assert_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS);
	g_clear_error (&error);

	g_object_unref (s_vpn);
}

static void
test_invalid_protocol (void)
{
	NMSettingVpn *s_vpn = new_vpn_setting ();
	GError *error = NULL;
	char *toml;

	nm_setting_vpn_add_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_PROTOCOL, "http1");
	toml = build_toml_for (s_vpn, &error);
	g_assert_null (toml);
	g_assert_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS);
	g_clear_error (&error);
	g_object_unref (s_vpn);

	/* "quic" is a legacy alias for "http3" and stays accepted. */
	s_vpn = new_vpn_setting ();
	nm_setting_vpn_add_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_PROTOCOL, "quic");
	toml = build_toml_for (s_vpn, &error);
	g_assert_no_error (error);
	g_assert_nonnull (strstr (toml, "upstream_protocol = \"http3\""));
	g_free (toml);
	g_object_unref (s_vpn);
}

static void
test_invalid_allow_ipv6 (void)
{
	NMSettingVpn *s_vpn = new_vpn_setting ();
	GError *error = NULL;
	char *toml;

	nm_setting_vpn_add_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_ALLOW_IPV6, "maybe");
	toml = build_toml_for (s_vpn, &error);
	g_assert_null (toml);
	g_assert_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS);
	g_clear_error (&error);
	g_object_unref (s_vpn);

	/* "no" is a valid spelling of false. */
	s_vpn = new_vpn_setting ();
	nm_setting_vpn_add_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_ALLOW_IPV6, "no");
	toml = build_toml_for (s_vpn, &error);
	g_assert_no_error (error);
	g_assert_nonnull (strstr (toml, "has_ipv6 = false"));
	g_free (toml);
	g_object_unref (s_vpn);
}

static char *
write_temp_config (const char *content)
{
	char *dir = g_dir_make_tmp ("nm-trusttunnel-test-XXXXXX", NULL);
	char *path = g_build_filename (dir, "config.toml", NULL);

	g_assert_true (g_file_set_contents (path, content, -1, NULL));
	g_free (dir);

	return path;
}

static void
remove_temp_config (char *path)
{
	char *dir;

	if (!path)
		return;

	dir = g_path_get_dirname (path);
	g_unlink (path);
	g_rmdir (dir);
	g_free (dir);
	g_free (path);
}

static void
test_config_file_without_listener (void)
{
	char *path = write_temp_config ("[endpoint]\nhostname = \"vpn.example.com\"\n");
	GError *error = NULL;
	char *toml;

	toml = nm_trusttunnel_config_file_to_toml (path, &error);
	g_assert_no_error (error);
	g_assert_nonnull (strstr (toml, "[listener.tun]"));
	g_assert_nonnull (strstr (toml, "managed = false"));
	g_assert_nonnull (strstr (toml, "included_routes = []"));

	g_free (toml);
	remove_temp_config (path);
}

static void
test_config_file_managed (void)
{
	char *path = write_temp_config ("[endpoint]\nhostname = \"vpn.example.com\"\n"
	                                "[listener.tun]\nmanaged = true\nincluded_routes = []\n");
	GError *error = NULL;
	char *toml;

	toml = nm_trusttunnel_config_file_to_toml (path, &error);
	g_assert_null (toml);
	g_assert_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS);
	g_clear_error (&error);

	remove_temp_config (path);
}

static void
test_config_file_included_routes (void)
{
	char *path = write_temp_config ("[endpoint]\nhostname = \"vpn.example.com\"\n"
	                                "[listener.tun]\nmanaged = false\n"
	                                "included_routes = [\"0.0.0.0/0\"]\n");
	GError *error = NULL;
	char *toml;

	toml = nm_trusttunnel_config_file_to_toml (path, &error);
	g_assert_null (toml);
	g_assert_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS);
	g_clear_error (&error);

	remove_temp_config (path);
}

static void
test_config_file_socks (void)
{
	char *path = write_temp_config ("[endpoint]\nhostname = \"vpn.example.com\"\n"
	                                "[listener.socks]\naddress = \"127.0.0.1:1080\"\n");
	GError *error = NULL;
	char *toml;

	toml = nm_trusttunnel_config_file_to_toml (path, &error);
	g_assert_null (toml);
	g_assert_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS);
	g_clear_error (&error);

	remove_temp_config (path);
}

static void
test_config_file_unmanaged_is_accepted (void)
{
	char *path = write_temp_config ("[endpoint]\nhostname = \"vpn.example.com\"\n"
	                                "[listener.tun]\nmanaged = false\nincluded_routes = []\n");
	GError *error = NULL;
	char *toml;

	toml = nm_trusttunnel_config_file_to_toml (path, &error);
	g_assert_no_error (error);
	g_assert_nonnull (toml);
	/* The file is used as is, the listener is not duplicated. */
	g_assert_null (strstr (toml, "[listener]\n[listener.tun]"));

	g_free (toml);
	remove_temp_config (path);
}

static void
test_config_file_without_managed (void)
{
	/* The daemon defaults "managed" to true, a file without the key must be
	 * rejected instead of silently switching to the managed mode. */
	char *path = write_temp_config ("[endpoint]\nhostname = \"vpn.example.com\"\n"
	                                "[listener.tun]\nincluded_routes = []\n");
	GError *error = NULL;
	char *toml;

	toml = nm_trusttunnel_config_file_to_toml (path, &error);
	g_assert_null (toml);
	g_assert_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS);
	g_clear_error (&error);

	remove_temp_config (path);
}

static void
test_config_file_quoted_managed (void)
{
	/* A quoted value is a string, the daemon would read it as true. */
	char *path = write_temp_config ("[endpoint]\nhostname = \"vpn.example.com\"\n"
	                                "[listener.tun]\nmanaged = 'true'\nincluded_routes = []\n");
	GError *error = NULL;
	char *toml;

	toml = nm_trusttunnel_config_file_to_toml (path, &error);
	g_assert_null (toml);
	g_assert_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS);
	g_clear_error (&error);

	remove_temp_config (path);
}

static void
test_config_file_empty_routes_with_spaces (void)
{
	char *path = write_temp_config ("[endpoint]\nhostname = \"vpn.example.com\"\n"
	                                "[listener.tun]\nmanaged = false\nincluded_routes = [ ]\n");
	GError *error = NULL;
	char *toml;

	toml = nm_trusttunnel_config_file_to_toml (path, &error);
	g_assert_no_error (error);
	g_assert_nonnull (toml);

	g_free (toml);
	remove_temp_config (path);
}

static void
test_log_level (void)
{
	NMSettingVpn *s_vpn = new_vpn_setting ();
	GError *error = NULL;
	char *toml;

	nm_setting_vpn_add_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_LOG_LEVEL, "debug");
	toml = build_toml_for (s_vpn, &error);
	g_assert_no_error (error);
	g_assert_nonnull (strstr (toml, "loglevel = \"debug\""));
	g_free (toml);
	g_clear_error (&error);

	nm_setting_vpn_add_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_LOG_LEVEL, "verbose");
	toml = build_toml_for (s_vpn, &error);
	g_assert_null (toml);
	g_assert_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS);
	g_clear_error (&error);

	g_object_unref (s_vpn);
}

int
main (int argc, char **argv)
{
	g_test_init (&argc, &argv, NULL);

	g_test_add_func ("/config/default-toml", test_default_toml);
	g_test_add_func ("/config/dns-servers", test_dns_servers);
	g_test_add_func ("/config/escaping", test_escaping);
	g_test_add_func ("/config/ipv6-address", test_ipv6_address);
	g_test_add_func ("/config/protocol", test_protocol);
	g_test_add_func ("/config/required-fields", test_required_fields);
	g_test_add_func ("/config/invalid-port", test_invalid_port);
	g_test_add_func ("/config/invalid-protocol", test_invalid_protocol);
	g_test_add_func ("/config/invalid-allow-ipv6", test_invalid_allow_ipv6);
	g_test_add_func ("/config/file-without-listener", test_config_file_without_listener);
	g_test_add_func ("/config/file-managed", test_config_file_managed);
	g_test_add_func ("/config/file-included-routes", test_config_file_included_routes);
	g_test_add_func ("/config/file-socks", test_config_file_socks);
	g_test_add_func ("/config/file-unmanaged", test_config_file_unmanaged_is_accepted);
	g_test_add_func ("/config/file-without-managed", test_config_file_without_managed);
	g_test_add_func ("/config/file-quoted-managed", test_config_file_quoted_managed);
	g_test_add_func ("/config/file-empty-routes", test_config_file_empty_routes_with_spaces);
	g_test_add_func ("/config/log-level", test_log_level);

	return g_test_run ();
}

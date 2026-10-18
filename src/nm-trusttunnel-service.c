/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-trusttunnel-service.c - NetworkManager TrustTunnel VPN Plugin Daemon */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <glib.h>
#include <gio/gio.h>
#include <NetworkManager.h>

#include "nm-trusttunnel-service.h"
#include "shared/nm-service-defines.h"

typedef struct {
	GDBusProxy *proxy;
	gulong signal_handler_id;
	guint connect_timeout_id;
	char *server_address;
	gboolean connected;
} NMTrusttunnelPluginPrivate;

G_DEFINE_TYPE_WITH_PRIVATE (NMTrusttunnelPlugin, nm_trusttunnel_plugin, NM_TYPE_VPN_SERVICE_PLUGIN)

#define NM_TRUSTTUNNEL_PLUGIN_GET_PRIVATE(o) \
	((NMTrusttunnelPluginPrivate *) nm_trusttunnel_plugin_get_instance_private (NM_TRUSTTUNNEL_PLUGIN (o)))

static GMainLoop *loop = NULL;

static char *
toml_escape (const char *str)
{
	if (!str)
		return g_strdup ("");

	GString *res = g_string_sized_new (strlen (str) + 16);
	const unsigned char *p = (const unsigned char *) str;

	while (*p) {
		switch (*p) {
		case '\\':
			g_string_append (res, "\\\\");
			break;
		case '"':
			g_string_append (res, "\\\"");
			break;
		case '\b':
			g_string_append (res, "\\b");
			break;
		case '\t':
			g_string_append (res, "\\t");
			break;
		case '\n':
			g_string_append (res, "\\n");
			break;
		case '\f':
			g_string_append (res, "\\f");
			break;
		case '\r':
			g_string_append (res, "\\r");
			break;
		default:
			if (*p < 0x20) {
				g_string_append_printf (res, "\\u%04x", *p);
			} else {
				g_string_append_c (res, *p);
			}
			break;
		}
		p++;
	}

	return g_string_free (res, FALSE);
}

static char *
generate_config_toml (NMSettingVpn *s_vpn, GError **error)
{
	const char *config_file = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_CONFIG_FILE);

	if (config_file && *config_file) {
		char *content = NULL;
		if (!g_file_get_contents (config_file, &content, NULL, error)) {
			return NULL;
		}

		/* Ensure unmanaged mode is used when a custom config file is imported */
		if (strstr (content, "[listener.tun]") == NULL) {
			GString *s = g_string_new (content);
			g_free (content);
			g_string_append (s, "\n[listener]\n[listener.tun]\nmanaged = false\nincluded_routes = []\nexcluded_routes = []\n");
			return g_string_free (s, FALSE);
		}
		return content;
	}

	const char *server = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_SERVER);
	const char *address = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_ADDRESS);
	const char *port_str = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_PORT);
	const char *username = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_USERNAME);
	const char *password = nm_setting_vpn_get_secret (s_vpn, NM_TRUSTTUNNEL_KEY_PASSWORD);
	if (!password || !*password) {
		password = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_PASSWORD);
	}
	const char *protocol = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_PROTOCOL);
	const char *custom_sni = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_CUSTOM_SNI);
	const char *dns_servers = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_DNS_SERVERS);
	const char *allow_ipv6 = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_ALLOW_IPV6);
	const char *cert_pem = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_CERT_PEM);
	const char *log_level = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_LOG_LEVEL);

	if (!server || !username || !password) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "Missing required fields (server, username or password)");
		return NULL;
	}

	int port = port_str ? atoi (port_str) : NM_TRUSTTUNNEL_DEFAULT_PORT;
	if (port <= 0 || port > 65535) {
		port = NM_TRUSTTUNNEL_DEFAULT_PORT;
	}

	const char *proto = protocol ? protocol : "http2";
	if (g_ascii_strcasecmp (proto, "quic") == 0) {
		proto = "http3";
	}

	if (!log_level || !*log_level) {
		log_level = NM_TRUSTTUNNEL_DEFAULT_LOG_LEVEL;
	}

	char *esc_server = toml_escape (server);
	char *esc_username = toml_escape (username);
	char *esc_password = toml_escape (password);
	char *esc_custom_sni = toml_escape (custom_sni ? custom_sni : "");

	GString *toml = g_string_new (NULL);
	g_string_append_printf (toml, "loglevel = \"%s\"\n", log_level);
	g_string_append (toml, "vpn_mode = \"general\"\n");
	g_string_append (toml, "killswitch_enabled = false\n");
	g_string_append (toml, "post_quantum_group_enabled = true\n");
	g_string_append (toml, "exclusions = []\n\n");

	g_string_append (toml, "[endpoint]\n");
	g_string_append_printf (toml, "name = \"%s\"\n", esc_server);
	g_string_append_printf (toml, "hostname = \"%s\"\n", esc_server);

	const char *target_addr = (address && *address) ? address : server;
	g_string_append (toml, "addresses = [\"");
	if (strchr (target_addr, ':') != NULL) {
		const char *c = target_addr;
		int colon_count = 0;
		while (*c) {
			if (*c == ':')
				colon_count++;
			c++;
		}
		if (colon_count > 1 && target_addr[0] != '[') {
			g_string_append_printf (toml, "[%s]:%d", target_addr, port);
		} else {
			g_string_append (toml, target_addr);
		}
	} else {
		g_string_append_printf (toml, "%s:%d", target_addr, port);
	}
	g_string_append (toml, "\"]\n");

	g_string_append_printf (toml, "has_ipv6 = %s\n",
	                        (allow_ipv6 && g_ascii_strcasecmp (allow_ipv6, "true") == 0) ? "true" : "false");
	g_string_append_printf (toml, "username = \"%s\"\n", esc_username);
	g_string_append_printf (toml, "password = \"%s\"\n", esc_password);

	if (esc_custom_sni && *esc_custom_sni) {
		g_string_append_printf (toml, "custom_sni = \"%s\"\n", esc_custom_sni);
	}

	if (cert_pem && *cert_pem) {
		char **lines = g_strsplit (cert_pem, "\r\n", -1);
		char *joined = g_strjoinv ("\n", lines);
		g_strfreev (lines);
		g_string_append_printf (toml, "certificate = \"\"\"%s\"\"\"\n", joined);
		g_free (joined);
	}

	g_string_append_printf (toml, "upstream_protocol = \"%s\"\n", proto);

	if (dns_servers && *dns_servers) {
		g_string_append (toml, "dns_upstreams = [");
		char **dns_list = g_strsplit (dns_servers, ",", -1);
		for (int i = 0; dns_list[i]; i++) {
			char *clean = g_strstrip (dns_list[i]);
			if (*clean) {
				char *esc_dns = toml_escape (clean);
				g_string_append_printf (toml, "%s\"%s\"", (i > 0 ? ", " : ""), esc_dns);
				g_free (esc_dns);
			}
		}
		g_strfreev (dns_list);
		g_string_append (toml, "]\n");
	} else {
		g_string_append (toml, "dns_upstreams = [\"46.243.231.30\", \"46.243.231.31\"]\n");
	}

	g_string_append (toml, "\n[listener]\n");
	g_string_append (toml, "[listener.tun]\n");
	g_string_append (toml, "managed = false\n");
	g_string_append (toml, "included_routes = []\n");
	g_string_append (toml, "excluded_routes = []\n");

	g_free (esc_server);
	g_free (esc_username);
	g_free (esc_password);
	g_free (esc_custom_sni);

	return g_string_free (toml, FALSE);
}

static void
handle_network_ready (NMTrusttunnelPlugin *plugin, GVariant *parameters)
{
	NMTrusttunnelPluginPrivate *priv = NM_TRUSTTUNNEL_PLUGIN_GET_PRIVATE (plugin);
	const char *iface = NULL;
	const char *ipv4_addr_str = NULL;
	guint32 ipv4_prefix = 0;
	const char *ipv6_addr_str = NULL;
	guint32 ipv6_prefix = 0;
	guint32 mtu = 0;
	GVariant *dns_variant = NULL;
	GVariantBuilder config;
	GVariantBuilder ip4config;
	struct in_addr v4_addr;
	gboolean has_ip4 = FALSE;
	struct in6_addr v6_addr;
	gboolean has_ip6 = FALSE;

	g_variant_get (parameters, "(&s&su&suu@as)",
	               &iface,
	               &ipv4_addr_str,
	               &ipv4_prefix,
	               &ipv6_addr_str,
	               &ipv6_prefix,
	               &mtu,
	               &dns_variant);

	g_message ("NetworkReady received: iface=%s, ipv4=%s/%u, ipv6=%s/%u, mtu=%u",
	           iface ? iface : "(null)",
	           ipv4_addr_str ? ipv4_addr_str : "(null)",
	           ipv4_prefix,
	           ipv6_addr_str ? ipv6_addr_str : "(null)",
	           ipv6_prefix,
	           mtu);

	if (priv->connect_timeout_id) {
		g_source_remove (priv->connect_timeout_id);
		priv->connect_timeout_id = 0;
	}

	g_variant_builder_init (&config, G_VARIANT_TYPE_VARDICT);

	if (iface && *iface) {
		g_variant_builder_add (&config, "{sv}",
		                       NM_VPN_PLUGIN_CONFIG_TUNDEV,
		                       g_variant_new_string (iface));
	}

	if (mtu > 0) {
		g_variant_builder_add (&config, "{sv}",
		                       NM_VPN_PLUGIN_CONFIG_MTU,
		                       g_variant_new_uint32 (mtu));
	}

	if (priv->server_address) {
		struct in_addr ext_gw;
		if (inet_pton (AF_INET, priv->server_address, &ext_gw) == 1) {
			g_variant_builder_add (&config, "{sv}",
			                       NM_VPN_PLUGIN_CONFIG_EXT_GATEWAY,
			                       g_variant_new_uint32 (ext_gw.s_addr));
		}
	}

	if (ipv4_addr_str && *ipv4_addr_str && inet_pton (AF_INET, ipv4_addr_str, &v4_addr) == 1) {
		has_ip4 = TRUE;
	}
	g_variant_builder_add (&config, "{sv}",
	                       NM_VPN_PLUGIN_CONFIG_HAS_IP4,
	                       g_variant_new_boolean (has_ip4));

	if (ipv6_addr_str && *ipv6_addr_str && inet_pton (AF_INET6, ipv6_addr_str, &v6_addr) == 1) {
		has_ip6 = TRUE;
	}
	g_variant_builder_add (&config, "{sv}",
	                       NM_VPN_PLUGIN_CONFIG_HAS_IP6,
	                       g_variant_new_boolean (has_ip6));

	nm_vpn_service_plugin_set_config (NM_VPN_SERVICE_PLUGIN (plugin),
	                                  g_variant_builder_end (&config));

	gsize n_dns = 0;
	const gchar **dns_strv = g_variant_get_strv (dns_variant, &n_dns);

	if (has_ip4) {
		g_variant_builder_init (&ip4config, G_VARIANT_TYPE_VARDICT);

		g_variant_builder_add (&ip4config, "{sv}",
		                       NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS,
		                       g_variant_new_uint32 (v4_addr.s_addr));

		guint32 prefix = (ipv4_prefix > 0 && ipv4_prefix <= 32) ? ipv4_prefix : 32;
		g_variant_builder_add (&ip4config, "{sv}",
		                       NM_VPN_PLUGIN_IP4_CONFIG_PREFIX,
		                       g_variant_new_uint32 (prefix));

		if (prefix == 32) {
			g_variant_builder_add (&ip4config, "{sv}",
			                       NM_VPN_PLUGIN_IP4_CONFIG_PTP,
			                       g_variant_new_uint32 (v4_addr.s_addr));
		}

		if (dns_strv && n_dns > 0) {
			GVariantBuilder dns_builder;
			gboolean has_dns = FALSE;
			g_variant_builder_init (&dns_builder, G_VARIANT_TYPE ("au"));

			for (gsize i = 0; i < n_dns; i++) {
				struct in_addr dns_addr;
				if (inet_pton (AF_INET, dns_strv[i], &dns_addr) == 1) {
					g_variant_builder_add (&dns_builder, "u", dns_addr.s_addr);
					has_dns = TRUE;
				}
			}

			if (has_dns) {
				g_variant_builder_add (&ip4config, "{sv}",
				                       NM_VPN_PLUGIN_IP4_CONFIG_DNS,
				                       g_variant_builder_end (&dns_builder));
			} else {
				g_variant_builder_clear (&dns_builder);
			}
		}

		nm_vpn_service_plugin_set_ip4_config (NM_VPN_SERVICE_PLUGIN (plugin),
		                                      g_variant_builder_end (&ip4config));
	}

	if (has_ip6) {
		GVariantBuilder ip6config;
		g_variant_builder_init (&ip6config, G_VARIANT_TYPE_VARDICT);

		GVariant *v6_addr_var = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
		                                                   &v6_addr,
		                                                   sizeof (v6_addr),
		                                                   1);
		g_variant_builder_add (&ip6config, "{sv}",
		                       NM_VPN_PLUGIN_IP6_CONFIG_ADDRESS,
		                       v6_addr_var);

		guint32 p6 = (ipv6_prefix > 0 && ipv6_prefix <= 128) ? ipv6_prefix : 128;
		g_variant_builder_add (&ip6config, "{sv}",
		                       NM_VPN_PLUGIN_IP6_CONFIG_PREFIX,
		                       g_variant_new_uint32 (p6));

		if (p6 == 128) {
			GVariant *v6_ptp_var = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
			                                                  &v6_addr,
			                                                  sizeof (v6_addr),
			                                                  1);
			g_variant_builder_add (&ip6config, "{sv}",
			                       NM_VPN_PLUGIN_IP6_CONFIG_PTP,
			                       v6_ptp_var);
		}

		if (dns_strv && n_dns > 0) {
			GVariantBuilder dns6_builder;
			gboolean has_dns6 = FALSE;
			g_variant_builder_init (&dns6_builder, G_VARIANT_TYPE ("aay"));

			for (gsize i = 0; i < n_dns; i++) {
				struct in6_addr dns6_addr;
				if (inet_pton (AF_INET6, dns_strv[i], &dns6_addr) == 1) {
					GVariant *dns6_var = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE,
					                                                &dns6_addr,
					                                                sizeof (dns6_addr),
					                                                1);
					g_variant_builder_add_value (&dns6_builder, dns6_var);
					has_dns6 = TRUE;
				}
			}

			if (has_dns6) {
				g_variant_builder_add (&ip6config, "{sv}",
				                       NM_VPN_PLUGIN_IP6_CONFIG_DNS,
				                       g_variant_builder_end (&dns6_builder));
			} else {
				g_variant_builder_clear (&dns6_builder);
			}
		}

		nm_vpn_service_plugin_set_ip6_config (NM_VPN_SERVICE_PLUGIN (plugin),
		                                      g_variant_builder_end (&ip6config));
	}

	g_free (dns_strv);
	g_variant_unref (dns_variant);

	priv->connected = TRUE;
}

static void
handle_state_changed (NMTrusttunnelPlugin *plugin, GVariant *parameters)
{
	NMTrusttunnelPluginPrivate *priv = NM_TRUSTTUNNEL_PLUGIN_GET_PRIVATE (plugin);
	gint32 new_state = 0;

	g_variant_get (parameters, "(i)", &new_state);
	g_message ("StateChanged signal received: state=%d", new_state);

	if (new_state == 0 /* DISCONNECTED */) {
		if (priv->connect_timeout_id) {
			g_source_remove (priv->connect_timeout_id);
			priv->connect_timeout_id = 0;
		}

		if (priv->connected) {
			g_message ("trusttunneld disconnected while session was active");
			priv->connected = FALSE;
			nm_vpn_service_plugin_disconnect (NM_VPN_SERVICE_PLUGIN (plugin), NULL);
		} else {
			g_warning ("trusttunneld disconnected before connection was established");
			nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin),
			                               NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
		}
	}
}

static void
on_dbus_signal (GDBusProxy *proxy,
                const gchar *sender_name,
                const gchar *signal_name,
                GVariant *parameters,
                gpointer user_data)
{
	NMTrusttunnelPlugin *plugin = NM_TRUSTTUNNEL_PLUGIN (user_data);

	if (g_strcmp0 (signal_name, "NetworkReady") == 0) {
		handle_network_ready (plugin, parameters);
	} else if (g_strcmp0 (signal_name, "StateChanged") == 0) {
		handle_state_changed (plugin, parameters);
	}
}

static gboolean
connect_timeout_cb (gpointer user_data)
{
	NMTrusttunnelPlugin *plugin = NM_TRUSTTUNNEL_PLUGIN (user_data);
	NMTrusttunnelPluginPrivate *priv = NM_TRUSTTUNNEL_PLUGIN_GET_PRIVATE (plugin);

	priv->connect_timeout_id = 0;
	g_warning ("Timeout waiting for NetworkReady signal from trusttunneld");

	if (priv->proxy) {
		g_dbus_proxy_call (priv->proxy, "Stop", NULL, G_DBUS_CALL_FLAGS_NONE, -1, NULL, NULL, NULL);
	}

	nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin),
	                               NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
	return G_SOURCE_REMOVE;
}

static gboolean
real_connect (NMVpnServicePlugin *plugin,
              NMConnection *connection,
              GError **error)
{
	NMTrusttunnelPluginPrivate *priv = NM_TRUSTTUNNEL_PLUGIN_GET_PRIVATE (plugin);
	NMSettingVpn *s_vpn;
	char *toml_config = NULL;
	GVariant *start_res = NULL;
	guint32 err_code = 0;

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (!s_vpn) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "Connection missing VPN setting");
		return FALSE;
	}

	toml_config = generate_config_toml (s_vpn, error);
	if (!toml_config) {
		return FALSE;
	}

	/* Resolve external gateway address if possible */
	const char *gw_candidate = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_ADDRESS);
	if (!gw_candidate || !*gw_candidate) {
		gw_candidate = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_SERVER);
	}
	if (gw_candidate && *gw_candidate) {
		char *host_part = g_strdup (gw_candidate);
		if (host_part[0] == '[' && strchr (host_part, ']') != NULL) {
			char *end_bracket = strchr (host_part, ']');
			*end_bracket = '\0';
			memmove (host_part, host_part + 1, strlen (host_part));
		} else {
			char *colon = strrchr (host_part, ':');
			if (colon) {
				*colon = '\0';
			}
		}

		struct in_addr test_v4;
		if (inet_pton (AF_INET, host_part, &test_v4) == 1) {
			priv->server_address = g_strdup (host_part);
		} else {
			GResolver *resolver = g_resolver_get_default ();
			GList *addresses = g_resolver_lookup_by_name (resolver, host_part, NULL, NULL);
			if (addresses) {
				for (GList *l = addresses; l; l = l->next) {
					GInetAddress *addr = G_INET_ADDRESS (l->data);
					if (g_inet_address_get_family (addr) == G_SOCKET_FAMILY_IPV4) {
						priv->server_address = g_inet_address_to_string (addr);
						g_message ("Resolved VPN server %s -> %s", host_part, priv->server_address);
						break;
					}
				}
				g_resolver_free_addresses (addresses);
			}
			g_object_unref (resolver);
		}
		g_free (host_part);
	}

	/* Connect to trusttunneld via system D-Bus */
	if (!priv->proxy) {
		priv->proxy = g_dbus_proxy_new_for_bus_sync (G_BUS_TYPE_SYSTEM,
		                                             G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
		                                             NULL,
		                                             NM_TRUSTTUNNEL_DBUS_SERVICE,
		                                             NM_TRUSTTUNNEL_DBUS_PATH,
		                                             NM_TRUSTTUNNEL_DBUS_INTERFACE,
		                                             NULL,
		                                             error);
		if (!priv->proxy) {
			g_free (toml_config);
			return FALSE;
		}

		priv->signal_handler_id = g_signal_connect (priv->proxy,
		                                            "g-signal",
		                                            G_CALLBACK (on_dbus_signal),
		                                            plugin);
	}

	g_message ("Sending Start command to trusttunneld...");
	start_res = g_dbus_proxy_call_sync (priv->proxy,
	                                    "Start",
	                                    g_variant_new ("(s)", toml_config),
	                                    G_DBUS_CALL_FLAGS_NONE,
	                                    -1,
	                                    NULL,
	                                    error);
	g_free (toml_config);

	if (!start_res) {
		g_warning ("Failed to invoke Start on trusttunneld: %s", (*error)->message);
		return FALSE;
	}

	g_variant_get (start_res, "(u)", &err_code);
	g_variant_unref (start_res);

	if (err_code != 0) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_LAUNCH_FAILED,
		             "trusttunneld rejected Start request with error code %u", err_code);
		return FALSE;
	}

	/* Arm connection timeout (30 seconds) */
	priv->connect_timeout_id = g_timeout_add_seconds (30, connect_timeout_cb, plugin);

	return TRUE;
}

static gboolean
real_disconnect (NMVpnServicePlugin *plugin, GError **err)
{
	NMTrusttunnelPluginPrivate *priv = NM_TRUSTTUNNEL_PLUGIN_GET_PRIVATE (plugin);

	g_message ("real_disconnect: stopping TrustTunnel connection");

	if (priv->connect_timeout_id) {
		g_source_remove (priv->connect_timeout_id);
		priv->connect_timeout_id = 0;
	}

	if (priv->proxy) {
		GError *error = NULL;
		GVariant *res = g_dbus_proxy_call_sync (priv->proxy,
		                                        "Stop",
		                                        NULL,
		                                        G_DBUS_CALL_FLAGS_NONE,
		                                        3000,
		                                        NULL,
		                                        &error);
		if (res) {
			g_variant_unref (res);
		} else {
			g_warning ("Failed to invoke Stop on trusttunneld: %s", error ? error->message : "unknown");
			g_clear_error (&error);
		}

		if (priv->signal_handler_id) {
			g_signal_handler_disconnect (priv->proxy, priv->signal_handler_id);
			priv->signal_handler_id = 0;
		}
		g_clear_object (&priv->proxy);
	}

	g_clear_pointer (&priv->server_address, g_free);
	priv->connected = FALSE;

	return TRUE;
}

static gboolean
real_need_secrets (NMVpnServicePlugin *plugin,
                   NMConnection *connection,
                   const char **setting_name,
                   GError **error)
{
	NMSettingVpn *s_vpn = nm_connection_get_setting_vpn (connection);
	if (!s_vpn) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "Missing VPN settings");
		return FALSE;
	}

	const char *config_file = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_CONFIG_FILE);
	if (config_file && *config_file) {
		return FALSE;
	}

	const char *pw = nm_setting_vpn_get_secret (s_vpn, NM_TRUSTTUNNEL_KEY_PASSWORD);
	if (!pw || !*pw) {
		pw = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_PASSWORD);
	}
	if (!pw || !*pw) {
		*setting_name = NM_SETTING_VPN_SETTING_NAME;
		return TRUE;
	}

	return FALSE;
}

static void
nm_trusttunnel_plugin_init (NMTrusttunnelPlugin *plugin)
{
}

static void
nm_trusttunnel_plugin_finalize (GObject *object)
{
	NMTrusttunnelPlugin *plugin = NM_TRUSTTUNNEL_PLUGIN (object);
	NMTrusttunnelPluginPrivate *priv = NM_TRUSTTUNNEL_PLUGIN_GET_PRIVATE (plugin);

	if (priv->connect_timeout_id) {
		g_source_remove (priv->connect_timeout_id);
		priv->connect_timeout_id = 0;
	}

	if (priv->signal_handler_id && priv->proxy) {
		g_signal_handler_disconnect (priv->proxy, priv->signal_handler_id);
		priv->signal_handler_id = 0;
	}

	g_clear_object (&priv->proxy);
	g_clear_pointer (&priv->server_address, g_free);

	G_OBJECT_CLASS (nm_trusttunnel_plugin_parent_class)->finalize (object);
}

static void
nm_trusttunnel_plugin_class_init (NMTrusttunnelPluginClass *plugin_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (plugin_class);
	NMVpnServicePluginClass *parent_class = NM_VPN_SERVICE_PLUGIN_CLASS (plugin_class);

	object_class->finalize = nm_trusttunnel_plugin_finalize;

	parent_class->connect = real_connect;
	parent_class->disconnect = real_disconnect;
	parent_class->need_secrets = real_need_secrets;
}

NMTrusttunnelPlugin *
nm_trusttunnel_plugin_new (const char *bus_name)
{
	GError *error = NULL;
	NMTrusttunnelPlugin *plugin;

	plugin = (NMTrusttunnelPlugin *) g_initable_new (NM_TYPE_TRUSTTUNNEL_PLUGIN,
	                                                 NULL,
	                                                 &error,
	                                                 NM_VPN_SERVICE_PLUGIN_DBUS_SERVICE_NAME,
	                                                 bus_name,
	                                                 NM_VPN_SERVICE_PLUGIN_DBUS_WATCH_PEER,
	                                                 TRUE,
	                                                 NULL);
	if (!plugin) {
		g_warning ("Failed to create TrustTunnel plugin instance: %s", error->message);
		g_error_free (error);
	}
	return plugin;
}

static void
signal_handler (int signo)
{
	if (signo == SIGINT || signo == SIGTERM) {
		if (loop)
			g_main_loop_quit (loop);
	}
}

static void
quit_mainloop (NMTrusttunnelPlugin *plugin, gpointer user_data)
{
	GMainLoop *mloop = (GMainLoop *) user_data;
	if (mloop && g_main_loop_is_running (mloop)) {
		g_main_loop_quit (mloop);
	}
}

int
main (int argc, char **argv)
{
	NMTrusttunnelPlugin *plugin;
	char *bus_name = NM_DBUS_SERVICE_TRUSTTUNNEL;
	gboolean persist = FALSE;
	gboolean debug = FALSE;
	GOptionContext *opt_ctx = NULL;
	GError *error = NULL;
	gulong quit_handler_id = 0;

	GOptionEntry options[] = {
		{ "persist", 0, 0, G_OPTION_ARG_NONE, &persist, "Don't quit when VPN connection terminates", NULL },
		{ "debug", 0, 0, G_OPTION_ARG_NONE, &debug, "Enable verbose debug logging", NULL },
		{ "bus-name", 0, 0, G_OPTION_ARG_STRING, &bus_name, "D-Bus name to use for this instance", NULL },
		{ NULL }
	};

	opt_ctx = g_option_context_new (NULL);
	g_option_context_set_ignore_unknown_options (opt_ctx, FALSE);
	g_option_context_set_help_enabled (opt_ctx, TRUE);
	g_option_context_add_main_entries (opt_ctx, options, NULL);

	if (!g_option_context_parse (opt_ctx, &argc, &argv, &error)) {
		g_printerr ("Error parsing command line options: %s\n", error->message);
		g_option_context_free (opt_ctx);
		g_clear_error (&error);
		return 1;
	}
	g_option_context_free (opt_ctx);

	signal (SIGINT, signal_handler);
	signal (SIGTERM, signal_handler);
	signal (SIGPIPE, SIG_IGN);

	loop = g_main_loop_new (NULL, FALSE);

	plugin = nm_trusttunnel_plugin_new (bus_name);
	if (!plugin) {
		g_main_loop_unref (loop);
		return 1;
	}

	if (!persist) {
		quit_handler_id = g_signal_connect (plugin, "quit", G_CALLBACK (quit_mainloop), loop);
	}

	g_message ("NetworkManager TrustTunnel service started (service: %s)", bus_name);
	g_main_loop_run (loop);

	if (quit_handler_id) {
		g_signal_handler_disconnect (plugin, quit_handler_id);
	}

	g_object_unref (plugin);
	g_main_loop_unref (loop);

	return 0;
}

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
#include "shared/nm-trusttunnel-config.h"

typedef struct {
	GDBusProxy *proxy;
	gulong signal_handler_id;
	gulong name_owner_handler_id;
	guint connect_timeout_id;
	guint retry_timeout_id;
	guint generation;
	GCancellable *cancellable;
	char *endpoint_address;
	char *server_address;
	char **dns_servers;
	char *pending_toml;
	gboolean connected;
	gboolean aborted;
	gboolean stop_requested;
	gboolean start_retried;
	gboolean stopping_for_retry;
	gboolean allow_ipv6;
	gboolean has_ip4;
	gboolean has_ip6;
	gboolean sent_ip4;
	gboolean sent_ip6;
} NMTrusttunnelPluginPrivate;

G_DEFINE_TYPE_WITH_PRIVATE (NMTrusttunnelPlugin, nm_trusttunnel_plugin, NM_TYPE_VPN_SERVICE_PLUGIN)

#define NM_TRUSTTUNNEL_PLUGIN_GET_PRIVATE(o) \
	((NMTrusttunnelPluginPrivate *) nm_trusttunnel_plugin_get_instance_private (NM_TRUSTTUNNEL_PLUGIN (o)))

static GMainLoop *loop = NULL;

/* State for an asynchronous call. It keeps the plugin alive and records the
 * connect generation the call belongs to, so a reply from an attempt that was
 * already aborted cannot modify the current session. */
typedef struct {
	NMTrusttunnelPlugin *plugin;
	guint generation;
} AsyncCall;

static AsyncCall *
async_call_new (NMTrusttunnelPlugin *plugin, guint generation)
{
	AsyncCall *call = g_new0 (AsyncCall, 1);

	call->plugin = g_object_ref (plugin);
	call->generation = generation;
	return call;
}

static void
async_call_free (AsyncCall *call)
{
	g_object_unref (call->plugin);
	g_free (call);
}

static gboolean
async_call_is_current (AsyncCall *call)
{
	NMTrusttunnelPluginPrivate *priv = NM_TRUSTTUNNEL_PLUGIN_GET_PRIVATE (call->plugin);

	return call->generation == priv->generation && !priv->aborted;
}

static void start_session (NMTrusttunnelPlugin *plugin);
static void resolve_endpoint (NMTrusttunnelPlugin *plugin);

/* Ask the daemon to release the session. This is used on abort paths where the
 * regular cancellable may already be cancelled, so it intentionally passes no
 * cancellable: the Stop request must actually reach the daemon. */
static void
send_stop_request (GDBusProxy *proxy)
{
	g_dbus_proxy_call (proxy,
	                   "Stop",
	                   NULL,
	                   G_DBUS_CALL_FLAGS_NONE,
	                   NM_TRUSTTUNNEL_DBUS_TIMEOUT_SEC * 1000,
	                   NULL,
	                   NULL,
	                   NULL);
}

static gboolean
retry_start_cb (gpointer user_data)
{
	NMTrusttunnelPlugin *plugin = NM_TRUSTTUNNEL_PLUGIN (user_data);
	NMTrusttunnelPluginPrivate *priv = NM_TRUSTTUNNEL_PLUGIN_GET_PRIVATE (plugin);

	priv->retry_timeout_id = 0;
	start_session (plugin);

	return G_SOURCE_REMOVE;
}

static void
clear_connect_timeout (NMTrusttunnelPluginPrivate *priv)
{
	if (priv->connect_timeout_id) {
		g_source_remove (priv->connect_timeout_id);
		priv->connect_timeout_id = 0;
	}
}

static void
clear_retry_timeout (NMTrusttunnelPluginPrivate *priv)
{
	if (priv->retry_timeout_id) {
		g_source_remove (priv->retry_timeout_id);
		priv->retry_timeout_id = 0;
	}
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
	gboolean has_ip4;
	struct in6_addr v6_addr;
	gboolean has_ip6;
	const gchar **ready_dns = NULL;
	gsize n_ready_dns = 0;
	const gchar *const *dns_list;
	gsize n_dns;

	/* The watchdog, a failed attempt or a disconnect make the session
	 * terminal. A NetworkReady that was already queued cannot be allowed to
	 * configure addresses for a connection that NetworkManager considers
	 * failed or gone. */
	if (priv->aborted) {
		g_message ("Ignoring NetworkReady after the session was aborted");
		return;
	}
	if (priv->connected) {
		g_message ("Ignoring repeated NetworkReady for an active session");
		return;
	}

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

	/* The address flags announced in the configuration must match exactly the
	 * address configurations that are sent to NetworkManager. libnm moves the
	 * plugin to NM_VPN_SERVICE_STATE_STARTED only when has_ip4 == got_ip4 and
	 * has_ip6 == got_ip6, otherwise the connection stays in "connecting"
	 * forever. */
	has_ip4 = ipv4_addr_str && *ipv4_addr_str && inet_pton (AF_INET, ipv4_addr_str, &v4_addr) == 1;
	has_ip6 = ipv6_addr_str && *ipv6_addr_str
	          && inet_pton (AF_INET6, ipv6_addr_str, &v6_addr) == 1
	          && priv->allow_ipv6;

	if (!has_ip4 && !has_ip6) {
		g_warning ("trusttunneld did not provide any usable address");
		g_variant_unref (dns_variant);
		clear_connect_timeout (priv);
		priv->aborted = TRUE;
		nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin),
		                               NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
		return;
	}

	priv->has_ip4 = has_ip4;
	priv->has_ip6 = has_ip6;

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
		/* The external gateway is the address of the VPN endpoint, NetworkManager
		 * uses it in its route calculations. The peer of a TUN device is unknown,
		 * so no PTP is reported at all. */
		if (inet_pton (AF_INET, priv->server_address, &ext_gw) == 1) {
			g_variant_builder_add (&config, "{sv}",
			                       NM_VPN_PLUGIN_CONFIG_EXT_GATEWAY,
			                       g_variant_new_uint32 (ext_gw.s_addr));
		}
	}

	g_variant_builder_add (&config, "{sv}",
	                       NM_VPN_PLUGIN_CONFIG_HAS_IP4,
	                       g_variant_new_boolean (has_ip4));
	g_variant_builder_add (&config, "{sv}",
	                       NM_VPN_PLUGIN_CONFIG_HAS_IP6,
	                       g_variant_new_boolean (has_ip6));

	nm_vpn_service_plugin_set_config (NM_VPN_SERVICE_PLUGIN (plugin),
	                                  g_variant_builder_end (&config));

	ready_dns = g_variant_get_strv (dns_variant, &n_ready_dns);
	if (n_ready_dns > 0) {
		dns_list = (const gchar *const *) ready_dns;
		n_dns = n_ready_dns;
	} else if (priv->dns_servers && priv->dns_servers[0]) {
		/* The daemon intentionally reports no DNS in unmanaged mode, so the
		 * profile's dns-servers setting is the next authority. */
		g_message ("trusttunneld did not report DNS, using the profile settings");
		dns_list = (const gchar *const *) priv->dns_servers;
		n_dns = g_strv_length (priv->dns_servers);
	} else {
		g_message ("trusttunneld did not report DNS, using the built-in resolvers");
		dns_list = nm_trusttunnel_config_default_dns_servers ();
		n_dns = g_strv_length ((gchar **) dns_list);
	}

	if (has_ip4) {
		g_variant_builder_init (&ip4config, G_VARIANT_TYPE_VARDICT);

		g_variant_builder_add (&ip4config, "{sv}",
		                       NM_VPN_PLUGIN_IP4_CONFIG_ADDRESS,
		                       g_variant_new_uint32 (v4_addr.s_addr));

		guint32 prefix = (ipv4_prefix > 0 && ipv4_prefix <= 32) ? ipv4_prefix : 32;
		g_variant_builder_add (&ip4config, "{sv}",
		                       NM_VPN_PLUGIN_IP4_CONFIG_PREFIX,
		                       g_variant_new_uint32 (prefix));

		if (dns_list && n_dns > 0) {
			GVariantBuilder dns_builder;
			gboolean has_dns = FALSE;
			g_variant_builder_init (&dns_builder, G_VARIANT_TYPE ("au"));

			for (gsize i = 0; i < n_dns; i++) {
				struct in_addr dns_addr;
				if (inet_pton (AF_INET, dns_list[i], &dns_addr) == 1) {
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
		priv->sent_ip4 = TRUE;
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

		if (dns_list && n_dns > 0) {
			GVariantBuilder dns6_builder;
			gboolean has_dns6 = FALSE;
			g_variant_builder_init (&dns6_builder, G_VARIANT_TYPE ("aay"));

			for (gsize i = 0; i < n_dns; i++) {
				struct in6_addr dns6_addr;
				if (inet_pton (AF_INET6, dns_list[i], &dns6_addr) == 1) {
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
		priv->sent_ip6 = TRUE;
	}

	g_free (ready_dns);
	g_variant_unref (dns_variant);

	/* All announced addresses are configured now, libnm switches the plugin to
	 * NM_VPN_SERVICE_STATE_STARTED. The watchdog is only released here: as
	 * long as an address configuration is missing the connection would never
	 * become active. */
	if (priv->sent_ip4 == priv->has_ip4 && priv->sent_ip6 == priv->has_ip6) {
		clear_connect_timeout (priv);
		priv->stopping_for_retry = FALSE;
		priv->connected = TRUE;
	}
}

static void
handle_state_changed (NMTrusttunnelPlugin *plugin, GVariant *parameters)
{
	NMTrusttunnelPluginPrivate *priv = NM_TRUSTTUNNEL_PLUGIN_GET_PRIVATE (plugin);
	gint32 new_state = 0;

	if (priv->aborted) {
		g_message ("Ignoring StateChanged after the session was aborted");
		return;
	}

	g_variant_get (parameters, "(i)", &new_state);
	g_message ("StateChanged signal received: state=%d", new_state);

	switch (new_state) {
	case NM_TRUSTTUNNEL_STATE_DISCONNECTED:
		if (priv->stop_requested) {
			/* The plugin stopped the session itself after the timeout, the
			 * failure has already been reported to NetworkManager. */
			g_message ("trusttunneld reports the session stopped");
			break;
		}

		if (priv->stopping_for_retry) {
			/* This is the session the plugin stopped itself to repeat the
			 * Start request. The daemon stops the session asynchronously and
			 * releases it only afterwards, so the request is repeated with
			 * a short delay, once the session is really gone. */
			g_message ("trusttunneld reports the session stopped, the request is repeated");
			clear_retry_timeout (priv);
			priv->retry_timeout_id = g_timeout_add (NM_TRUSTTUNNEL_RETRY_DELAY_MS,
			                                       retry_start_cb,
			                                       plugin);
			break;
		}

		clear_connect_timeout (priv);
		/* The session is over regardless of whether it had become active.
		 * Mark it terminal before reporting, so any signal that is already
		 * queued behind this one is ignored. */
		priv->aborted = TRUE;

		if (priv->connected) {
			g_message ("trusttunneld disconnected while the session was active");
			priv->connected = FALSE;
			nm_vpn_service_plugin_disconnect (NM_VPN_SERVICE_PLUGIN (plugin), NULL);
		} else {
			g_warning ("trusttunneld disconnected before the connection was established");
			nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin),
			                               NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
		}
		break;
	case NM_TRUSTTUNNEL_STATE_CONNECTING:
		g_message ("trusttunneld is connecting to the endpoint");
		break;
	case NM_TRUSTTUNNEL_STATE_CONNECTED:
		g_message ("trusttunneld established the tunnel");
		break;
	case NM_TRUSTTUNNEL_STATE_WAITING_RECOVERY:
		g_message ("trusttunneld is waiting for the connection to be recovered");
		break;
	case NM_TRUSTTUNNEL_STATE_RECOVERING:
		g_message ("trusttunneld is recovering the connection");
		break;
	case NM_TRUSTTUNNEL_STATE_WAITING_NETWORK:
		g_message ("trusttunneld is waiting for network connectivity");
		break;
	default:
		g_warning ("trusttunneld reported an unknown session state %d", new_state);
		break;
	}
}

static void
on_dbus_signal (GDBusProxy *proxy G_GNUC_UNUSED,
                const gchar *sender_name G_GNUC_UNUSED,
                const gchar *signal_name,
                GVariant *parameters,
                gpointer user_data)
{
	NMTrusttunnelPlugin *plugin = NM_TRUSTTUNNEL_PLUGIN (user_data);

	if (g_strcmp0 (signal_name, "NetworkReady") == 0) {
		handle_network_ready (plugin, parameters);
	} else if (g_strcmp0 (signal_name, "StateChanged") == 0) {
		handle_state_changed (plugin, parameters);
	} else {
		g_debug ("Ignoring signal \"%s\" from trusttunneld", signal_name);
	}
}

static void
on_name_owner_changed (GDBusProxy *proxy, GParamSpec *pspec G_GNUC_UNUSED, gpointer user_data)
{
	NMTrusttunnelPlugin *plugin = NM_TRUSTTUNNEL_PLUGIN (user_data);
	NMTrusttunnelPluginPrivate *priv = NM_TRUSTTUNNEL_PLUGIN_GET_PRIVATE (plugin);

	if (priv->aborted || g_dbus_proxy_get_name_owner (proxy) != NULL)
		return;

	/* The daemon vanished while the session was starting or active. No
	 * StateChanged will arrive in that case, so report the failure here. */
	g_warning ("trusttunneld disappeared from the bus");
	clear_connect_timeout (priv);
	clear_retry_timeout (priv);
	priv->aborted = TRUE;
	priv->generation++;

	if (priv->connected) {
		priv->connected = FALSE;
		nm_vpn_service_plugin_disconnect (NM_VPN_SERVICE_PLUGIN (plugin), NULL);
	} else {
		nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin),
		                               NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
	}
}

static void
on_proxy_ready (GObject *source G_GNUC_UNUSED, GAsyncResult *result, gpointer user_data)
{
	AsyncCall *call = user_data;
	NMTrusttunnelPlugin *plugin = call->plugin;
	NMTrusttunnelPluginPrivate *priv = NM_TRUSTTUNNEL_PLUGIN_GET_PRIVATE (plugin);
	GError *error = NULL;
	GDBusProxy *proxy;

	proxy = g_dbus_proxy_new_for_bus_finish (result, &error);
	if (!proxy) {
		if (async_call_is_current (call)) {
			g_warning ("Failed to connect to trusttunneld: %s",
			           error ? error->message : "unknown");
			clear_connect_timeout (priv);
			priv->aborted = TRUE;
			nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin),
			                               NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
		}
		g_clear_error (&error);
		async_call_free (call);
		return;
	}

	if (!async_call_is_current (call)) {
		g_object_unref (proxy);
		async_call_free (call);
		return;
	}

	priv->proxy = proxy;
	priv->signal_handler_id = g_signal_connect (priv->proxy,
	                                            "g-signal",
	                                            G_CALLBACK (on_dbus_signal),
	                                            plugin);
	priv->name_owner_handler_id = g_signal_connect (priv->proxy,
	                                                "notify::g-name-owner",
	                                                G_CALLBACK (on_name_owner_changed),
	                                                plugin);

	resolve_endpoint (plugin);
	async_call_free (call);
}

static gboolean
connect_timeout_cb (gpointer user_data)
{
	NMTrusttunnelPlugin *plugin = NM_TRUSTTUNNEL_PLUGIN (user_data);
	NMTrusttunnelPluginPrivate *priv = NM_TRUSTTUNNEL_PLUGIN_GET_PRIVATE (plugin);

	priv->connect_timeout_id = 0;
	/* Abort the connect sequence. A Start request or a retry that is still in
	 * flight must not start a session anymore, the failure is reported to
	 * NetworkManager right below. Bumping the generation makes all pending
	 * replies stale; a Start reply that still succeeds tears the session down
	 * itself. */
	priv->aborted = TRUE;
	priv->generation++;
	clear_retry_timeout (priv);
	g_warning ("Timeout waiting for the network configuration from trusttunneld");

	if (priv->proxy) {
		/* Tear the session down, NetworkManager is not going to ask for it
		 * once the failure is reported. */
		priv->stop_requested = TRUE;
		send_stop_request (priv->proxy);
	}

	nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin),
	                               NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
	return G_SOURCE_REMOVE;
}

static void
on_stop_reply (GObject *source, GAsyncResult *result, gpointer user_data)
{
	AsyncCall *call = user_data;
	GError *error = NULL;
	GVariant *reply;

	reply = g_dbus_proxy_call_finish (G_DBUS_PROXY (source), result, &error);
	if (!reply) {
		g_warning ("Failed to invoke Stop on trusttunneld: %s",
		           error ? error->message : "unknown");
		g_clear_error (&error);
	} else {
		guint32 err_code = 0;
		g_variant_get (reply, "(u)", &err_code);
		g_variant_unref (reply);
		if (err_code != NM_TRUSTTUNNEL_ERROR_SUCCESS)
			g_warning ("trusttunneld rejected the Stop request with error code %u", err_code);
	}

	/* The daemon stops the session asynchronously, the request is repeated
	 * when it reports the session as disconnected. */
	async_call_free (call);
}

static void
on_start_reply (GObject *source, GAsyncResult *result, gpointer user_data)
{
	AsyncCall *call = user_data;
	NMTrusttunnelPlugin *plugin = call->plugin;
	NMTrusttunnelPluginPrivate *priv = NM_TRUSTTUNNEL_PLUGIN_GET_PRIVATE (plugin);
	GError *error = NULL;
	GVariant *reply;
	guint32 err_code = 0;

	reply = g_dbus_proxy_call_finish (G_DBUS_PROXY (source), result, &error);
	if (!reply) {
		if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			g_warning ("Failed to invoke Start on trusttunneld: %s",
			           error ? error->message : "unknown");
		g_clear_error (&error);

		if (async_call_is_current (call)) {
			clear_connect_timeout (priv);
			priv->aborted = TRUE;
			nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin),
			                               NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
		}
		async_call_free (call);
		return;
	}

	g_variant_get (reply, "(u)", &err_code);
	g_variant_unref (reply);

	if (!async_call_is_current (call)) {
		/* The attempt was aborted while the Start request was in flight.
		 * The daemon may have created the session anyway, so release it. A
		 * newer attempt cannot own this session: the daemon serializes Start
		 * and would have answered ALREADY_RUNNING to it. */
		if (err_code == NM_TRUSTTUNNEL_ERROR_SUCCESS) {
			g_message ("The Start request was aborted, stopping the session");
			send_stop_request (G_DBUS_PROXY (source));
		}
		async_call_free (call);
		return;
	}

	if (err_code == NM_TRUSTTUNNEL_ERROR_ALREADY_RUNNING) {
		if (!priv->start_retried) {
			/* The daemon keeps a single session, a session left over by a
			 * crashed client is stopped and the request is repeated once the
			 * daemon reports the session as disconnected. */
			AsyncCall *stop_call = async_call_new (plugin, priv->generation);

			priv->start_retried = TRUE;
			priv->stopping_for_retry = TRUE;
			g_message ("trusttunneld reports a running session, stopping it and retrying");
			g_dbus_proxy_call (G_DBUS_PROXY (source),
			                   "Stop",
			                   NULL,
			                   G_DBUS_CALL_FLAGS_NONE,
			                   NM_TRUSTTUNNEL_DBUS_TIMEOUT_SEC * 1000,
			                   NULL,
			                   on_stop_reply,
			                   stop_call);
			async_call_free (call);
			return;
		}

		g_warning ("trusttunneld still reports a running session after it was stopped");
		priv->stopping_for_retry = FALSE;
		clear_connect_timeout (priv);
		priv->aborted = TRUE;
		nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin),
		                               NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
		async_call_free (call);
		return;
	}

	if (err_code != NM_TRUSTTUNNEL_ERROR_SUCCESS) {
		switch (err_code) {
		case NM_TRUSTTUNNEL_ERROR_INVALID_CONFIG:
			g_warning ("trusttunneld refused the Start request: the configuration is invalid");
			break;
		default:
			g_warning ("trusttunneld refused the Start request with error code %u", err_code);
			break;
		}
		priv->stopping_for_retry = FALSE;
		clear_connect_timeout (priv);
		priv->aborted = TRUE;
		nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin),
		                               NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
		async_call_free (call);
		return;
	}

	priv->stopping_for_retry = FALSE;
	g_clear_pointer (&priv->pending_toml, g_free);
	async_call_free (call);
}

static void
start_session (NMTrusttunnelPlugin *plugin)
{
	NMTrusttunnelPluginPrivate *priv = NM_TRUSTTUNNEL_PLUGIN_GET_PRIVATE (plugin);

	if (priv->aborted)
		return;

	if (!priv->proxy || !priv->pending_toml) {
		g_warning ("Cannot start the session: %s",
		           priv->proxy ? "the configuration is missing" : "no connection to trusttunneld");
		clear_connect_timeout (priv);
		priv->aborted = TRUE;
		nm_vpn_service_plugin_failure (NM_VPN_SERVICE_PLUGIN (plugin),
		                               NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED);
		return;
	}

	g_message ("Sending Start command to trusttunneld...");
	g_dbus_proxy_call (priv->proxy,
	                   "Start",
	                   g_variant_new ("(s)", priv->pending_toml),
	                   G_DBUS_CALL_FLAGS_NONE,
	                   NM_TRUSTTUNNEL_DBUS_TIMEOUT_SEC * 1000,
	                   priv->cancellable,
	                   on_start_reply,
	                   async_call_new (plugin, priv->generation));
}

static void
on_endpoint_resolved (GObject *source, GAsyncResult *result, gpointer user_data)
{
	AsyncCall *call = user_data;
	NMTrusttunnelPlugin *plugin = call->plugin;
	NMTrusttunnelPluginPrivate *priv = NM_TRUSTTUNNEL_PLUGIN_GET_PRIVATE (plugin);
	GError *error = NULL;
	GList *addresses;

	addresses = g_resolver_lookup_by_name_finish (G_RESOLVER (source), result, &error);

	if (!async_call_is_current (call)) {
		/* The attempt was aborted or superseded while the lookup was in
		 * flight. Do not report a cancellation as a connection failure. */
		if (addresses)
			g_resolver_free_addresses (addresses);
		g_clear_error (&error);
		async_call_free (call);
		return;
	}

	if (!addresses) {
		if (!g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
			g_warning ("Failed to resolve VPN server %s: %s",
			           priv->endpoint_address ? priv->endpoint_address : "(null)",
			           error ? error->message : "unknown");
		g_clear_error (&error);
	} else {
		GList *l;
		for (l = addresses; l; l = l->next) {
			GInetAddress *addr = G_INET_ADDRESS (l->data);
			if (g_inet_address_get_family (addr) == G_SOCKET_FAMILY_IPV4) {
				g_clear_pointer (&priv->server_address, g_free);
				priv->server_address = g_inet_address_to_string (addr);
				g_message ("Resolved VPN server %s -> %s",
				           priv->endpoint_address ? priv->endpoint_address : "(null)",
				           priv->server_address);
				break;
			}
		}
		g_resolver_free_addresses (addresses);
	}

	/* The source object is owned by the GTask of the asynchronous call, it
	 * must not be unreferenced here. */

	start_session (plugin);
	async_call_free (call);
}

/* Resolve the endpoint address to be able to report it as the external
 * gateway. The resolution must not block the main loop. */
static void
resolve_endpoint (NMTrusttunnelPlugin *plugin)
{
	NMTrusttunnelPluginPrivate *priv = NM_TRUSTTUNNEL_PLUGIN_GET_PRIVATE (plugin);
	struct in_addr v4_addr;
	struct in6_addr v6_addr;
	GResolver *resolver;

	if (!priv->endpoint_address || !*priv->endpoint_address) {
		start_session (plugin);
		return;
	}

	if (inet_pton (AF_INET, priv->endpoint_address, &v4_addr) == 1) {
		g_clear_pointer (&priv->server_address, g_free);
		priv->server_address = g_strdup (priv->endpoint_address);
		start_session (plugin);
		return;
	}

	if (inet_pton (AF_INET6, priv->endpoint_address, &v6_addr) == 1) {
		/* NM_VPN_PLUGIN_CONFIG_EXT_GATEWAY carries an IPv4 address only. */
		start_session (plugin);
		return;
	}

	resolver = g_resolver_get_default ();
	g_resolver_lookup_by_name_async (resolver,
	                                 priv->endpoint_address,
	                                 priv->cancellable,
	                                 on_endpoint_resolved,
	                                 async_call_new (plugin, priv->generation));
	g_object_unref (resolver);
}

static gboolean
real_connect (NMVpnServicePlugin *plugin,
              NMConnection *connection,
              GError **error)
{
	NMTrusttunnelPluginPrivate *priv = NM_TRUSTTUNNEL_PLUGIN_GET_PRIVATE (plugin);
	NMSettingVpn *s_vpn;
	NMTTrusttunnelConfig *config;

	s_vpn = nm_connection_get_setting_vpn (connection);
	if (!s_vpn) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "Connection missing VPN setting");
		return FALSE;
	}

	config = nm_trusttunnel_config_from_settings (s_vpn, error);
	if (!config)
		return FALSE;

	g_clear_pointer (&priv->pending_toml, g_free);
	priv->pending_toml = nm_trusttunnel_config_to_toml (config, error);
	priv->allow_ipv6 = config->allow_ipv6;
	g_strfreev (priv->dns_servers);
	priv->dns_servers = g_strdupv (config->dns_servers);
	g_clear_pointer (&priv->endpoint_address, g_free);
	if (config->address && *config->address)
		priv->endpoint_address = g_strdup (config->address);
	else if (config->server && *config->server)
		priv->endpoint_address = g_strdup (config->server);
	nm_trusttunnel_config_free (config);

	if (!priv->pending_toml)
		return FALSE;

	priv->connected = FALSE;
	priv->aborted = FALSE;
	priv->stop_requested = FALSE;
	priv->start_retried = FALSE;
	priv->stopping_for_retry = FALSE;
	clear_retry_timeout (priv);
	priv->has_ip4 = FALSE;
	priv->has_ip6 = FALSE;
	priv->sent_ip4 = FALSE;
	priv->sent_ip6 = FALSE;
	/* Invalidate every callback and reply from a previous attempt. */
	priv->generation++;

	/* A cancelled GCancellable cannot be reused, start with a fresh one. */
	g_clear_object (&priv->cancellable);
	priv->cancellable = g_cancellable_new ();

	/* The watchdog covers the whole connect phase: address resolution, the
	 * Start request and the delivery of the address configuration. It is
	 * released when the session is fully configured. */
	clear_connect_timeout (priv);
	priv->connect_timeout_id = g_timeout_add_seconds (NM_TRUSTTUNNEL_CONNECT_TIMEOUT_SEC,
	                                                  connect_timeout_cb,
	                                                  NM_TRUSTTUNNEL_PLUGIN (plugin));

	/* Connect to trusttunneld via the system bus. This must not block the
	 * main loop: the watchdog has to be able to fire while the bus name is
	 * being resolved or activated. */
	if (!priv->proxy) {
		g_dbus_proxy_new_for_bus (G_BUS_TYPE_SYSTEM,
		                          G_DBUS_PROXY_FLAGS_DO_NOT_LOAD_PROPERTIES,
		                          NULL,
		                          NM_TRUSTTUNNEL_DBUS_SERVICE,
		                          NM_TRUSTTUNNEL_DBUS_PATH,
		                          NM_TRUSTTUNNEL_DBUS_INTERFACE,
		                          priv->cancellable,
		                          on_proxy_ready,
		                          async_call_new (NM_TRUSTTUNNEL_PLUGIN (plugin),
		                                          priv->generation));
		return TRUE;
	}

	resolve_endpoint (NM_TRUSTTUNNEL_PLUGIN (plugin));

	return TRUE;
}

static gboolean
real_disconnect (NMVpnServicePlugin *plugin, GError **err)
{
	NMTrusttunnelPluginPrivate *priv = NM_TRUSTTUNNEL_PLUGIN_GET_PRIVATE (plugin);
	GError *error = NULL;
	GVariant *res;

	g_message ("real_disconnect: stopping TrustTunnel connection");

	clear_connect_timeout (priv);
	clear_retry_timeout (priv);

	/* Abort a connect sequence that is still in flight, its asynchronous
	 * callbacks must not start a session anymore. The generation makes their
	 * replies stale; they are deliberately not cancelled, so a Start request
	 * that reaches the daemon can still release its session. */
	priv->aborted = TRUE;
	priv->generation++;

	if (priv->proxy) {
		/* Stop listening to the daemon first, the session is going down
		 * anyway and the StateChanged signal would call us back. */
		if (priv->signal_handler_id) {
			g_signal_handler_disconnect (priv->proxy, priv->signal_handler_id);
			priv->signal_handler_id = 0;
		}
		if (priv->name_owner_handler_id) {
			g_signal_handler_disconnect (priv->proxy, priv->name_owner_handler_id);
			priv->name_owner_handler_id = 0;
		}

		/* Always send Stop. It is harmless when no session exists, and it is
		 * required when the watchdog already tried and failed to stop one. */
		res = g_dbus_proxy_call_sync (priv->proxy,
		                              "Stop",
		                              NULL,
		                              G_DBUS_CALL_FLAGS_NONE,
		                              NM_TRUSTTUNNEL_STOP_TIMEOUT_SEC * 1000,
		                              NULL,
		                              &error);
		if (res) {
			guint32 err_code = 0;
			g_variant_get (res, "(u)", &err_code);
			g_variant_unref (res);
			if (err_code != NM_TRUSTTUNNEL_ERROR_SUCCESS)
				g_warning ("trusttunneld rejected the Stop request with error code %u", err_code);
		} else {
			g_warning ("Failed to invoke Stop on trusttunneld: %s",
			           error ? error->message : "unknown");
			g_clear_error (&error);
		}

		g_clear_object (&priv->proxy);
	}

	priv->stop_requested = FALSE;

	g_clear_pointer (&priv->server_address, g_free);
	g_clear_pointer (&priv->endpoint_address, g_free);
	g_strfreev (priv->dns_servers);
	priv->dns_servers = NULL;
	g_clear_pointer (&priv->pending_toml, g_free);
	priv->connected = FALSE;
	priv->stopping_for_retry = FALSE;
	priv->has_ip4 = FALSE;
	priv->has_ip6 = FALSE;
	priv->sent_ip4 = FALSE;
	priv->sent_ip6 = FALSE;

	return TRUE;
}

static gboolean
real_need_secrets (NMVpnServicePlugin *plugin,
                   NMConnection *connection,
                   const char **setting_name,
                   GError **error)
{
	NMSettingVpn *s_vpn = nm_connection_get_setting_vpn (connection);
	const char *config_file;
	const char *pw;

	if (!s_vpn) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "Missing VPN settings");
		return FALSE;
	}

	config_file = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_CONFIG_FILE);
	if (config_file && *config_file)
		return FALSE;

	pw = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_PASSWORD);
	if (!pw || !*pw)
		pw = nm_setting_vpn_get_secret (s_vpn, NM_TRUSTTUNNEL_KEY_PASSWORD);
	if (!pw || !*pw) {
		*setting_name = NM_SETTING_VPN_SETTING_NAME;
		return TRUE;
	}

	return FALSE;
}

static gboolean
real_new_secrets (NMVpnServicePlugin *plugin,
                  NMConnection *connection,
                  GError **error)
{
	/* trusttunneld cannot update the authentication of an established
	 * HTTP/2 or QUIC session without tearing it down, so changing the
	 * credentials requires a reconnect. */
	g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
	             "Changing TrustTunnel credentials requires a reconnect: "
	             "trusttunneld cannot update the authentication of a live session");
	return FALSE;
}

static void
nm_trusttunnel_plugin_init (NMTrusttunnelPlugin *plugin)
{
	NMTrusttunnelPluginPrivate *priv = NM_TRUSTTUNNEL_PLUGIN_GET_PRIVATE (plugin);

	priv->cancellable = g_cancellable_new ();
}

static void
nm_trusttunnel_plugin_dispose (GObject *object)
{
	NMTrusttunnelPlugin *plugin = NM_TRUSTTUNNEL_PLUGIN (object);
	NMTrusttunnelPluginPrivate *priv = NM_TRUSTTUNNEL_PLUGIN_GET_PRIVATE (plugin);

	/* Stop the daemon session explicitly. nm_vpn_service_plugin_shutdown()
	 * only disconnects while the plugin state is STARTED or STARTING, so the
	 * session could outlive the plugin. real_disconnect() is idempotent, it
	 * only talks to the daemon while the proxy is still around. */
	if (priv->proxy)
		real_disconnect (NM_VPN_SERVICE_PLUGIN (plugin), NULL);

	clear_connect_timeout (priv);
	clear_retry_timeout (priv);

	if (priv->cancellable)
		g_cancellable_cancel (priv->cancellable);

	g_clear_object (&priv->cancellable);

	G_OBJECT_CLASS (nm_trusttunnel_plugin_parent_class)->dispose (object);
}

static void
nm_trusttunnel_plugin_finalize (GObject *object)
{
	NMTrusttunnelPlugin *plugin = NM_TRUSTTUNNEL_PLUGIN (object);
	NMTrusttunnelPluginPrivate *priv = NM_TRUSTTUNNEL_PLUGIN_GET_PRIVATE (plugin);

	clear_connect_timeout (priv);
	clear_retry_timeout (priv);

	if (priv->signal_handler_id && priv->proxy) {
		g_signal_handler_disconnect (priv->proxy, priv->signal_handler_id);
		priv->signal_handler_id = 0;
	}
	if (priv->name_owner_handler_id && priv->proxy) {
		g_signal_handler_disconnect (priv->proxy, priv->name_owner_handler_id);
		priv->name_owner_handler_id = 0;
	}

	g_clear_object (&priv->proxy);
	g_clear_pointer (&priv->server_address, g_free);
	g_clear_pointer (&priv->endpoint_address, g_free);
	g_strfreev (priv->dns_servers);
	priv->dns_servers = NULL;
	g_clear_pointer (&priv->pending_toml, g_free);

	G_OBJECT_CLASS (nm_trusttunnel_plugin_parent_class)->finalize (object);
}

static void
nm_trusttunnel_plugin_class_init (NMTrusttunnelPluginClass *plugin_class)
{
	GObjectClass *object_class = G_OBJECT_CLASS (plugin_class);
	NMVpnServicePluginClass *parent_class = NM_VPN_SERVICE_PLUGIN_CLASS (plugin_class);

	object_class->dispose = nm_trusttunnel_plugin_dispose;
	object_class->finalize = nm_trusttunnel_plugin_finalize;

	parent_class->connect = real_connect;
	parent_class->disconnect = real_disconnect;
	parent_class->need_secrets = real_need_secrets;
	parent_class->new_secrets = real_new_secrets;
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

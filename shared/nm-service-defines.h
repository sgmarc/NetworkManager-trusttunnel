/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-service-defines.h - TrustTunnel service definitions for NetworkManager */

#ifndef NM_TRUSTTUNNEL_SERVICE_DEFINES_H
#define NM_TRUSTTUNNEL_SERVICE_DEFINES_H

#define NM_DBUS_SERVICE_TRUSTTUNNEL    "org.freedesktop.NetworkManager.trusttunnel"
#define NM_DBUS_INTERFACE_TRUSTTUNNEL  "org.freedesktop.NetworkManager.trusttunnel"
#define NM_DBUS_PATH_TRUSTTUNNEL       "/org/freedesktop/NetworkManager/trusttunnel"

#define NM_TRUSTTUNNEL_DBUS_SERVICE    "com.adguard.TrustTunnel"
#define NM_TRUSTTUNNEL_DBUS_PATH       "/com/adguard/TrustTunnel"
#define NM_TRUSTTUNNEL_DBUS_INTERFACE  "com.adguard.TrustTunnel.Vpn1"

#define NM_TRUSTTUNNEL_KEY_CONFIG_FILE       "config-file"
#define NM_TRUSTTUNNEL_KEY_SERVER            "server"
#define NM_TRUSTTUNNEL_KEY_ADDRESS           "address"
#define NM_TRUSTTUNNEL_KEY_PORT              "port"
#define NM_TRUSTTUNNEL_KEY_USERNAME          "username"
#define NM_TRUSTTUNNEL_KEY_PASSWORD          "password"
/* Secret storage flags: "0" = saved in the connection file, "1" = owned
 * by a secret agent (GNOME keyring, via the auth dialog). */
#define NM_TRUSTTUNNEL_KEY_PASSWORD_FLAGS    "password-flags"
#define NM_TRUSTTUNNEL_KEY_PROTOCOL          "protocol"
#define NM_TRUSTTUNNEL_KEY_CUSTOM_SNI        "custom-sni"
#define NM_TRUSTTUNNEL_KEY_CLIENT_RANDOM     "client-random"
#define NM_TRUSTTUNNEL_KEY_CERT_PEM          "cert-pem"
#define NM_TRUSTTUNNEL_KEY_DNS_SERVERS       "dns-servers"
#define NM_TRUSTTUNNEL_KEY_ALLOW_IPV6        "allow-ipv6"
#define NM_TRUSTTUNNEL_KEY_CLIENT_BINARY     "client-binary"
#define NM_TRUSTTUNNEL_KEY_LOG_LEVEL         "log-level"

#define NM_TRUSTTUNNEL_DEFAULT_PORT          443
#define NM_TRUSTTUNNEL_DEFAULT_PROTOCOL      "http2"
#define NM_TRUSTTUNNEL_DEFAULT_LOG_LEVEL     "info"
#define NM_TRUSTTUNNEL_DEFAULT_CLIENT_BINARY "trusttunnel_client"

/* Maximum length of the client random field, in characters. Matches the
 * limit used by the TrustTunnel Flutter client. */
#define NM_TRUSTTUNNEL_MAX_FIELD_LENGTH      64

/* Upstream protocol values accepted by trusttunneld.
 * See TrustTunnelClient/trusttunnel/src/config.cpp (UPSTREAM_PROTO_MAP).
 * Note that "quic" is not a daemon value, it is a legacy alias for "http3". */
#define NM_TRUSTTUNNEL_PROTOCOL_HTTP2         "http2"
#define NM_TRUSTTUNNEL_PROTOCOL_HTTP3         "http3"
#define NM_TRUSTTUNNEL_PROTOCOL_AUTO          "auto"

/* Session states reported by the StateChanged(i) signal of trusttunneld.
 * See TrustTunnelClient/platform/linux/src/dbus_interface.h (VpnState). */
typedef enum {
	NM_TRUSTTUNNEL_STATE_DISCONNECTED    = 0,
	NM_TRUSTTUNNEL_STATE_CONNECTING      = 1,
	NM_TRUSTTUNNEL_STATE_CONNECTED       = 2,
	NM_TRUSTTUNNEL_STATE_WAITING_RECOVERY = 3,
	NM_TRUSTTUNNEL_STATE_RECOVERING       = 4,
	NM_TRUSTTUNNEL_STATE_WAITING_NETWORK  = 5,
} NMTTrusttunnelState;

/* Error codes returned by the Start(s)/Stop() methods of trusttunneld.
 * See TrustTunnelClient/platform/linux/src/dbus_interface.h (VpnError). */
typedef enum {
	NM_TRUSTTUNNEL_ERROR_SUCCESS         = 0,
	NM_TRUSTTUNNEL_ERROR_ALREADY_RUNNING = 1,
	NM_TRUSTTUNNEL_ERROR_INVALID_CONFIG  = 2,
} NMTTrusttunnelError;

/* Timeouts (seconds) used by the plugin. */
#define NM_TRUSTTUNNEL_DBUS_TIMEOUT_SEC   15
#define NM_TRUSTTUNNEL_STOP_TIMEOUT_SEC    3
#define NM_TRUSTTUNNEL_CONNECT_TIMEOUT_SEC 30

/* Delay before the Start request is repeated after the daemon reported the
 * session as disconnected. The daemon releases the session only after it has
 * sent the signal, so the request must not be repeated immediately. */
#define NM_TRUSTTUNNEL_RETRY_DELAY_MS     500

#endif /* NM_TRUSTTUNNEL_SERVICE_DEFINES_H */

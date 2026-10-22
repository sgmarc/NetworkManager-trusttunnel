/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-trusttunnel-config.h - TrustTunnel configuration model and TOML serializer */

#ifndef NM_TRUSTTUNNEL_CONFIG_H
#define NM_TRUSTTUNNEL_CONFIG_H

#include <glib.h>
#include <NetworkManager.h>

/**
 * NMTTrusttunnelConfig:
 *
 * Platform independent representation of a TrustTunnel session configuration.
 * It is the single source of truth shared by the service plugin, the GNOME
 * editor and the import/export code.
 */
typedef struct {
	char    *config_file;   /* unsupported by the service, kept to report a clear error */
	char    *server;        /* endpoint host name used for the TLS session */
	char    *address;       /* endpoint address (host or IP literal), without port */
	guint16  port;          /* endpoint port */
	char    *username;      /* endpoint user name */
	char    *password;      /* endpoint password */
	char    *protocol;      /* upstream protocol: http2, http3 or auto */
	char    *custom_sni;    /* custom TLS SNI, or NULL */
	char    *client_random; /* TLS client random prefix/mask hex string, or NULL */
	char    *cert_pem;      /* endpoint certificate in PEM format, or NULL */
	char   **dns_servers;   /* NULL terminated list of DNS upstreams, or NULL */
	gboolean allow_ipv6;    /* whether IPv6 may be used for the session */
	char    *log_level;     /* daemon log level */
} NMTTrusttunnelConfig;

NMTTrusttunnelConfig *nm_trusttunnel_config_from_settings (NMSettingVpn *s_vpn,
                                                         GError **error);
void                  nm_trusttunnel_config_free        (NMTTrusttunnelConfig *config);

char                 *nm_trusttunnel_config_to_toml      (const NMTTrusttunnelConfig *config,
                                                         GError **error);
/* Resolvers used when neither the daemon nor the profile provides any. */
const char *const    *nm_trusttunnel_config_default_dns_servers (void);

/* Split a "host", "host:port" or "[v6]:port" gateway into its host part
 * and, when present, its port. Returns FALSE for an unparsable gateway.
 * Either out parameter may be NULL. The host is owned by the caller. */
gboolean              nm_trusttunnel_config_parse_gateway (const char *gateway,
                                                          char **out_host,
                                                          guint16 *out_port);
/* Read an external TOML file. This may only be called from a user session
 * (editor or import); the root service must never use it. */
char                 *nm_trusttunnel_config_file_to_toml (const char *path,
                                                         GError **error);

#endif /* NM_TRUSTTUNNEL_CONFIG_H */

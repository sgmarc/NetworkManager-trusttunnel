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
#define NM_TRUSTTUNNEL_KEY_PROTOCOL          "protocol"
#define NM_TRUSTTUNNEL_KEY_CUSTOM_SNI        "custom-sni"
#define NM_TRUSTTUNNEL_KEY_CERT_PEM          "cert-pem"
#define NM_TRUSTTUNNEL_KEY_DNS_SERVERS       "dns-servers"
#define NM_TRUSTTUNNEL_KEY_ALLOW_IPV6        "allow-ipv6"
#define NM_TRUSTTUNNEL_KEY_CLIENT_BINARY     "client-binary"
#define NM_TRUSTTUNNEL_KEY_LOG_LEVEL         "log-level"

#define NM_TRUSTTUNNEL_DEFAULT_PORT          443
#define NM_TRUSTTUNNEL_DEFAULT_PROTOCOL      "http2"
#define NM_TRUSTTUNNEL_DEFAULT_LOG_LEVEL     "info"
#define NM_TRUSTTUNNEL_DEFAULT_CLIENT_BINARY "trusttunnel_client"

#endif /* NM_TRUSTTUNNEL_SERVICE_DEFINES_H */

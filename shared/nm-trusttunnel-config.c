/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/* nm-trusttunnel-config.c - TrustTunnel configuration model and TOML serializer */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <string.h>

#include <glib.h>
#include <NetworkManager.h>

#include "nm-trusttunnel-config.h"
#include "nm-service-defines.h"

/* Default upstream resolvers, same as the daemon default (AdGuard DNS unfiltered). */
static const char *const default_dns_servers[] = { "46.243.231.30", "46.243.231.31", NULL };

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
			if (*p < 0x20 || *p == 0x7f) {
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

/* Reject values that are not a plausible host name or IP literal. Escaping
 * already prevents TOML injection, but a newline or a quote in the endpoint
 * host always means the connection profile is broken, so report it early. */
static gboolean
is_valid_endpoint_host (const char *host)
{
	const unsigned char *p;

	if (!host || !*host)
		return FALSE;

	for (p = (const unsigned char *) host; *p; p++) {
		if (*p <= 0x20 || *p == 0x7f)
			return FALSE;
		switch (*p) {
		case '"':
		case '\\':
		case '#':
		case '/':
		case '=':
			return FALSE;
		default:
			break;
		}
	}

	return TRUE;
}

/* Convert CRLF and lone CR to LF so that the PEM certificate is stored in a
 * single canonical form before it is escaped into a TOML basic string. */
static char *
normalize_newlines (const char *str)
{
	GString *res = g_string_sized_new (strlen (str) + 1);
	const char *p;

	for (p = str; *p; p++) {
		if (*p == '\r') {
			if (p[1] == '\n')
				continue;
			g_string_append_c (res, '\n');
		} else {
			g_string_append_c (res, *p);
		}
	}

	return g_string_free (res, FALSE);
}

/* Return the length of @line up to an unquoted comment marker. */
static gsize
toml_value_length (const char *line)
{
	gsize len = strlen (line);
	gsize i;
	gboolean in_string = FALSE;

	for (i = 0; i < len; i++) {
		if (line[i] == '\\' && in_string && i + 1 < len) {
			i++;
			continue;
		}
		if (line[i] == '"') {
			in_string = !in_string;
			continue;
		}
		if (line[i] == '#' && !in_string)
			return i;
	}

	return len;
}

/* Minimal TOML scanner used to inspect the listener table of an external
 * configuration file. It only understands the subset of TOML that the
 * listener table is written in: table headers, plain key/value pairs and
 * comments. Multi line arrays and literal strings are not supported and are
 * not detected as such. A full parser is not needed here, the daemon
 * validates the whole document anyway. */

/* Check whether the line is a table header for @name. */
static gboolean
toml_line_is_table (const char *line, const char *name)
{
	const char *p = line;
	gsize name_len = strlen (name);

	while (g_ascii_isspace (*p))
		p++;
	if (*p != '[')
		return FALSE;
	p++;
	while (g_ascii_isspace (*p))
		p++;

	if (strncmp (p, name, name_len) != 0)
		return FALSE;
	p += name_len;
	while (g_ascii_isspace (*p))
		p++;

	return *p == ']';
}

/* Check whether the TOML document contains the table @name. */
static gboolean
toml_has_table (const char *content, const char *name)
{
	char **lines;
	gboolean found = FALSE;
	guint i;

	lines = g_strsplit (content, "\n", -1);
	for (i = 0; lines[i] && !found; i++)
		found = toml_line_is_table (lines[i], name);
	g_strfreev (lines);

	return found;
}

/* Look up @key inside the table @table. Returns the raw (unquoted) value or NULL. */
static char *
toml_get_table_key (const char *content, const char *table, const char *key)
{
	char **lines;
	char *value = NULL;
	gboolean in_table = FALSE;
	guint i;

	lines = g_strsplit (content, "\n", -1);
	for (i = 0; lines[i] && !value; i++) {
		const char *p = lines[i];
		gsize key_len = strlen (key);
		gsize value_len;

		while (g_ascii_isspace (*p))
			p++;
		if (*p == '#' || *p == '\0')
			continue;
		if (*p == '[') {
			in_table = toml_line_is_table (p, table);
			continue;
		}
		if (!in_table)
			continue;
		if (strncmp (p, key, key_len) != 0)
			continue;
		p += key_len;
		while (g_ascii_isspace (*p))
			p++;
		if (*p != '=')
			continue;
		p++;
		while (g_ascii_isspace (*p))
			p++;

		value_len = toml_value_length (p);
		value = g_strndup (p, value_len);
		g_strstrip (value);
	}
	g_strfreev (lines);

	return value;
}

/* Return the host part of "host", "host:port", "[v6]" or "[v6]:port". */
static char *
strip_port (const char *address)
{
	const char *colon;

	if (!address)
		return NULL;

	if (address[0] == '[') {
		const char *end = strchr (address, ']');
		if (end)
			return g_strndup (address + 1, end - address - 1);
		return g_strdup (address);
	}

	colon = strrchr (address, ':');
	/* Only strip a port if the address contains exactly one colon, otherwise it
	 * is a bare IPv6 literal. */
	if (colon && strchr (address, ':') == colon)
		return g_strndup (address, colon - address);

	return g_strdup (address);
}

static gboolean
parse_port (const char *value, guint16 *out_port)
{
	guint64 port;
	char *end = NULL;

	if (!value || !*value)
		return FALSE;

	port = g_ascii_strtoull (value, &end, 10);
	if (!end || *end != '\0' || port == 0 || port > G_MAXUINT16)
		return FALSE;

	*out_port = (guint16) port;
	return TRUE;
}

/* Parse a boolean value as it is accepted for the allow-ipv6 setting.
 * Returns FALSE if the value is not a valid boolean. */
static gboolean
parse_bool (const char *value, gboolean *out_bool)
{
	static const char *const true_values[] = { "true", "yes", "on", "1", NULL };
	static const char *const false_values[] = { "false", "no", "off", "0", NULL };
	guint i;

	if (!value || !*value)
		return FALSE;

	for (i = 0; true_values[i]; i++) {
		if (g_ascii_strcasecmp (value, true_values[i]) == 0) {
			*out_bool = TRUE;
			return TRUE;
		}
	}

	for (i = 0; false_values[i]; i++) {
		if (g_ascii_strcasecmp (value, false_values[i]) == 0) {
			*out_bool = FALSE;
			return TRUE;
		}
	}

	return FALSE;
}

/* Check whether a raw TOML array value is empty. A value that is not an
 * array at all is ignored by the daemon and therefore treated as empty. */
static gboolean
toml_array_is_empty (const char *value)
{
	const char *p = value;

	if (!p)
		return TRUE;

	while (g_ascii_isspace (*p))
		p++;
	if (*p != '[')
		return TRUE;
	p++;
	while (g_ascii_isspace (*p))
		p++;

	return *p == ']';
}

/* The log levels accepted by trusttunneld.
 * See TrustTunnelClient/trusttunnel/src/utils.cpp (parse_loglevel). */
static gboolean
is_valid_log_level (const char *level)
{
	static const char *const levels[] = { "error", "warn", "info", "debug", "trace", NULL };
	guint i;

	if (!level || !*level)
		return FALSE;

	for (i = 0; levels[i]; i++) {
		if (g_ascii_strcasecmp (level, levels[i]) == 0)
			return TRUE;
	}

	return FALSE;
}

/* trusttunneld matches the log level case-sensitively, so store it in the
 * canonical lowercase form instead of rejecting an otherwise valid value. */
static char *
normalize_log_level (const char *level)
{
	char *normalized;

	if (!level || !*level)
		return NULL;

	normalized = g_ascii_strdown (level, -1);
	if (!is_valid_log_level (normalized)) {
		g_free (normalized);
		return NULL;
	}

	return normalized;
}

/* Normalize the upstream protocol to a value the daemon understands.
 * Returns NULL if the protocol is not supported. */
static char *
normalize_protocol (const char *protocol)
{
	if (!protocol || !*protocol)
		return g_strdup (NM_TRUSTTUNNEL_DEFAULT_PROTOCOL);

	if (g_ascii_strcasecmp (protocol, NM_TRUSTTUNNEL_PROTOCOL_HTTP3) == 0
	    || g_ascii_strcasecmp (protocol, "quic") == 0)
		return g_strdup (NM_TRUSTTUNNEL_PROTOCOL_HTTP3);
	if (g_ascii_strcasecmp (protocol, NM_TRUSTTUNNEL_PROTOCOL_AUTO) == 0)
		return g_strdup (NM_TRUSTTUNNEL_PROTOCOL_AUTO);
	if (g_ascii_strcasecmp (protocol, NM_TRUSTTUNNEL_PROTOCOL_HTTP2) == 0)
		return g_strdup (NM_TRUSTTUNNEL_PROTOCOL_HTTP2);

	return NULL;
}

static char **
split_dns_servers (const char *dns_servers)
{
	char **list;
	GPtrArray *result;
	guint i;

	if (!dns_servers || !*dns_servers)
		return NULL;

	list = g_strsplit (dns_servers, ",", -1);
	result = g_ptr_array_new ();
	for (i = 0; list[i]; i++) {
		char *item = g_strstrip (list[i]);
		if (*item)
			g_ptr_array_add (result, g_strdup (item));
	}
	g_strfreev (list);

	if (result->len == 0) {
		g_ptr_array_free (result, TRUE);
		return NULL;
	}

	g_ptr_array_add (result, NULL);
	return (char **) g_ptr_array_free (result, FALSE);
}

NMTTrusttunnelConfig *
nm_trusttunnel_config_from_settings (NMSettingVpn *s_vpn, GError **error)
{
	NMTTrusttunnelConfig *config;
	const char *value;

	g_return_val_if_fail (NM_IS_SETTING_VPN (s_vpn), NULL);
	g_return_val_if_fail (!error || *error == NULL, NULL);

	config = g_new0 (NMTTrusttunnelConfig, 1);
	config->port = NM_TRUSTTUNNEL_DEFAULT_PORT;
	config->allow_ipv6 = TRUE;
	config->protocol = g_strdup (NM_TRUSTTUNNEL_DEFAULT_PROTOCOL);
	config->log_level = g_strdup (NM_TRUSTTUNNEL_DEFAULT_LOG_LEVEL);

	value = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_CONFIG_FILE);
	if (value && *value) {
		/* The service runs as root. Reading a path supplied by the connection
		 * profile would let any user make it read an arbitrary file, block on
		 * a FIFO or win a symlink race. Importing a TOML file is a client-side
		 * operation and belongs to the editor, not to this process. */
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "The \"%s\" setting is not supported: the VPN service must not read "
		             "files supplied by a connection profile. Import the configuration into "
		             "the connection instead",
		             NM_TRUSTTUNNEL_KEY_CONFIG_FILE);
		nm_trusttunnel_config_free (config);
		return NULL;
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_SERVER);
	if (value)
		config->server = g_strdup (value);

	value = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_ADDRESS);
	if (value && *value)
		config->address = strip_port (value);

	value = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_PORT);
	if (value && *value) {
		/* An unparsable port is reported as an error when the configuration
		 * is serialized, do not silently fall back to the default. */
		if (!parse_port (value, &config->port))
			config->port = 0;
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_USERNAME);
	if (value)
		config->username = g_strdup (value);

	value = nm_setting_vpn_get_secret (s_vpn, NM_TRUSTTUNNEL_KEY_PASSWORD);
	if (!value || !*value)
		value = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_PASSWORD);
	if (value)
		config->password = g_strdup (value);

	value = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_PROTOCOL);
	if (value && *value) {
		char *protocol = normalize_protocol (value);
		if (!protocol) {
			g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "Invalid value for setting \"%s\"", NM_TRUSTTUNNEL_KEY_PROTOCOL);
			nm_trusttunnel_config_free (config);
			return NULL;
		}
		g_free (config->protocol);
		config->protocol = protocol;
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_CUSTOM_SNI);
	if (value && *value)
		config->custom_sni = g_strdup (value);

	value = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_CERT_PEM);
	if (value && *value)
		config->cert_pem = g_strdup (value);

	value = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_DNS_SERVERS);
	config->dns_servers = split_dns_servers (value);

	value = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_ALLOW_IPV6);
	if (value && *value) {
		gboolean allow_ipv6;
		if (!parse_bool (value, &allow_ipv6)) {
			g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "Invalid value for setting \"%s\"", NM_TRUSTTUNNEL_KEY_ALLOW_IPV6);
			nm_trusttunnel_config_free (config);
			return NULL;
		}
		config->allow_ipv6 = allow_ipv6;
	}

	value = nm_setting_vpn_get_data_item (s_vpn, NM_TRUSTTUNNEL_KEY_LOG_LEVEL);
	if (value && *value) {
		char *level = normalize_log_level (value);

		if (!level) {
			g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "Invalid value for setting \"%s\"", NM_TRUSTTUNNEL_KEY_LOG_LEVEL);
			nm_trusttunnel_config_free (config);
			return NULL;
		}
		g_free (config->log_level);
		config->log_level = level;
	}

	return config;
}

void
nm_trusttunnel_config_free (NMTTrusttunnelConfig *config)
{
	if (!config)
		return;

	g_free (config->config_file);
	g_free (config->server);
	g_free (config->address);
	g_free (config->username);
	g_free (config->password);
	g_free (config->protocol);
	g_free (config->custom_sni);
	g_free (config->cert_pem);
	g_strfreev (config->dns_servers);
	g_free (config->log_level);
	g_free (config);
}

/* Append "host:port" as a TOML array element, bracketing bare IPv6 literals.
 * The host is escaped: a quote or a newline must never terminate the string
 * and inject additional TOML tables (for example another listener). */
static void
append_endpoint_address (GString *toml, const char *host, guint16 port)
{
	char *escaped_host = toml_escape (host);

	if (strchr (host, ':') != NULL && host[0] != '[') {
		g_string_append_printf (toml, "\"[%s]:%u\"", escaped_host, port);
	} else {
		g_string_append_printf (toml, "\"%s:%u\"", escaped_host, port);
	}

	g_free (escaped_host);
}

static char *
build_toml (const NMTTrusttunnelConfig *config, GError **error)
{
	const char *host;
	char *escaped_server;
	char *escaped_username;
	char *escaped_password;
	char *escaped_custom_sni = NULL;
	char *escaped_log_level;
	GString *toml;

	if (!config->server || !*config->server) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "Missing required setting \"%s\"", NM_TRUSTTUNNEL_KEY_SERVER);
		return NULL;
	}
	if (!config->username || !*config->username) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "Missing required setting \"%s\"", NM_TRUSTTUNNEL_KEY_USERNAME);
		return NULL;
	}
	if (!config->password || !*config->password) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "Missing required setting \"%s\"", NM_TRUSTTUNNEL_KEY_PASSWORD);
		return NULL;
	}
	if (!config->protocol || !*config->protocol) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "Invalid upstream protocol");
		return NULL;
	}
	if (config->port == 0) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "Invalid value for setting \"%s\"", NM_TRUSTTUNNEL_KEY_PORT);
		return NULL;
	}
	if (!is_valid_log_level (config->log_level)) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "Invalid value for setting \"%s\"", NM_TRUSTTUNNEL_KEY_LOG_LEVEL);
		return NULL;
	}

	if (!is_valid_endpoint_host (config->server)) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "Invalid value for setting \"%s\"", NM_TRUSTTUNNEL_KEY_SERVER);
		return NULL;
	}

	host = (config->address && *config->address) ? config->address : config->server;
	if (!is_valid_endpoint_host (host)) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "Invalid value for setting \"%s\"",
		             (config->address && *config->address) ? NM_TRUSTTUNNEL_KEY_ADDRESS
		                                                   : NM_TRUSTTUNNEL_KEY_SERVER);
		return NULL;
	}

	escaped_server = toml_escape (config->server);
	escaped_username = toml_escape (config->username);
	escaped_password = toml_escape (config->password);
	escaped_custom_sni = toml_escape (config->custom_sni);
	escaped_log_level = toml_escape (config->log_level);

	toml = g_string_new (NULL);
	g_string_append_printf (toml, "loglevel = \"%s\"\n", escaped_log_level);
	g_string_append (toml, "vpn_mode = \"general\"\n");
	/* NetworkManager owns the routing, a client side kill switch would
	 * conflict with the routes and the DNS servers it applies itself. */
	g_string_append (toml, "killswitch_enabled = false\n");
	g_string_append (toml, "post_quantum_group_enabled = true\n");
	g_string_append (toml, "exclusions = []\n\n");

	g_string_append (toml, "[endpoint]\n");
	g_string_append_printf (toml, "hostname = \"%s\"\n", escaped_server);
	g_string_append (toml, "addresses = [");
	append_endpoint_address (toml, host, config->port);
	g_string_append (toml, "]\n");
	g_string_append_printf (toml, "has_ipv6 = %s\n", config->allow_ipv6 ? "true" : "false");
	g_string_append_printf (toml, "username = \"%s\"\n", escaped_username);
	g_string_append_printf (toml, "password = \"%s\"\n", escaped_password);

	if (config->custom_sni && *config->custom_sni)
		g_string_append_printf (toml, "custom_sni = \"%s\"\n", escaped_custom_sni);

	if (config->cert_pem && *config->cert_pem) {
		/* A multiline literal string would be terminated by a """ sequence in
		 * the certificate itself. A regular basic string with escaped
		 * newlines has no such terminator and is still valid TOML. */
		char *normalized = normalize_newlines (config->cert_pem);
		char *escaped_cert = toml_escape (normalized);

		g_string_append_printf (toml, "certificate = \"%s\"\n", escaped_cert);
		g_free (escaped_cert);
		g_free (normalized);
	}

	g_string_append_printf (toml, "upstream_protocol = \"%s\"\n", config->protocol);

	if (config->dns_servers && config->dns_servers[0]) {
		guint i;
		g_string_append (toml, "dns_upstreams = [");
		for (i = 0; config->dns_servers[i]; i++) {
			char *escaped = toml_escape (config->dns_servers[i]);
			if (i > 0)
				g_string_append (toml, ", ");
			g_string_append_printf (toml, "\"%s\"", escaped);
			g_free (escaped);
		}
		g_string_append (toml, "]\n");
	} else {
		guint i;
		/* The daemon falls back to its own default resolvers when the list
		 * is empty, and those are exactly the addresses it reports in the
		 * NetworkReady signal. They are pinned here on purpose so that the
		 * plugin and the daemon agree on the resolvers of the session. */
		g_string_append (toml, "dns_upstreams = [");
		for (i = 0; default_dns_servers[i]; i++) {
			if (i > 0)
				g_string_append (toml, ", ");
			g_string_append_printf (toml, "\"%s\"", default_dns_servers[i]);
		}
		g_string_append (toml, "]\n");
	}

	g_string_append (toml, "\n[listener]\n");
	g_string_append (toml, "[listener.tun]\n");
	g_string_append (toml, "managed = false\n");
	g_string_append (toml, "included_routes = []\n");
	g_string_append (toml, "excluded_routes = []\n");

	g_free (escaped_server);
	g_free (escaped_username);
	g_free (escaped_password);
	g_free (escaped_custom_sni);
	g_free (escaped_log_level);

	return g_string_free (toml, FALSE);
}

char *
nm_trusttunnel_config_to_toml (const NMTTrusttunnelConfig *config, GError **error)
{
	g_return_val_if_fail (config != NULL, NULL);

	if (config->config_file && *config->config_file) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "The \"%s\" setting is not supported by the VPN service",
		             NM_TRUSTTUNNEL_KEY_CONFIG_FILE);
		return NULL;
	}

	return build_toml (config, error);
}

char *
nm_trusttunnel_config_file_to_toml (const char *path, GError **error)
{
	char *content = NULL;

	g_return_val_if_fail (path && *path, NULL);

	if (!g_file_get_contents (path, &content, NULL, error))
		return NULL;

	if (toml_has_table (content, "listener.socks")) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "Configuration file \"%s\" uses a SOCKS listener, but NetworkManager "
		             "requires a TUN listener", path);
		g_free (content);
		return NULL;
	}

	if (toml_has_table (content, "listener.tun")) {
		char *managed = toml_get_table_key (content, "listener.tun", "managed");
		char *included_routes = toml_get_table_key (content, "listener.tun", "included_routes");

		/* The daemon defaults "managed" to true, so the key must be present
		 * and must be the boolean false. A quoted value is not a boolean and
		 * would be read as true by the daemon. */
		if (!managed || g_strcmp0 (managed, "false") != 0) {
			g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "Configuration file \"%s\" must set listener.tun.managed = false, "
			             "because NetworkManager owns the interface configuration", path);
			g_free (managed);
			g_free (included_routes);
			g_free (content);
			return NULL;
		}

		if (!toml_array_is_empty (included_routes)) {
			g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
			             "Configuration file \"%s\" sets listener.tun.included_routes, but "
			             "NetworkManager requires an empty included_routes when the listener "
			             "is unmanaged", path);
			g_free (managed);
			g_free (included_routes);
			g_free (content);
			return NULL;
		}

		g_free (managed);
		g_free (included_routes);
		return content;
	}

	if (toml_has_table (content, "listener")) {
		g_set_error (error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_BAD_ARGUMENTS,
		             "Configuration file \"%s\" has no [listener.tun] table, which NetworkManager "
		             "requires to manage the interface", path);
		g_free (content);
		return NULL;
	}

	/* The file does not configure a listener at all: add the unmanaged TUN listener. */
	{
		GString *s = g_string_new (content);
		g_free (content);
		g_string_append (s,
		                 "\n[listener]\n"
		                 "[listener.tun]\n"
		                 "managed = false\n"
		                 "included_routes = []\n"
		                 "excluded_routes = []\n");
		content = g_string_free (s, FALSE);
	}

	return content;
}

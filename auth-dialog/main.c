/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Minimal auth dialog for the prototype.
 *
 * The password is kept as a plain vpn.data item, so there is nothing to
 * ask the user for yet: the connection is piped to us on stdin as
 *
 *     DATA_KEY=<key>\nDATA_VAL=<value>\n\n
 *     SECRET_KEY=<key>\nSECRET_VAL=<value>\n\n
 *     DONE\n\n
 *
 * and we hand the password back in the old-style "key\nvalue\n" line
 * protocol. Outputting nothing would make NetworkManager treat the
 * request as failed ("No agents were available"). When proper secret
 * storage (keyring / interactive prompting) is implemented, this is the
 * place where the dialog UI goes.
 */

#include <glib.h>
#include <glib/gi18n.h>
#include <stdio.h>
#include <string.h>

#include "nm-service-defines.h"

#define KEY_PASSWORD NM_TRUSTTUNNEL_KEY_PASSWORD
#define PREFIX(key, lit) ((key) && g_str_has_prefix (key, lit))

static char *
read_password_from_connection (void)
{
	char *line = NULL;
	size_t len = 0;
	gboolean want_secret = FALSE;
	gboolean want_data = FALSE;
	char *password = NULL;

	while (getline (&line, &len, stdin) != -1) {
		g_strchomp (line);

		if (g_str_equal (line, "DONE"))
			break;

		if (PREFIX (line, "SECRET_KEY="))
			want_secret = g_str_equal (line + strlen ("SECRET_KEY="), KEY_PASSWORD);
		else if (PREFIX (line, "DATA_KEY="))
			want_data = g_str_equal (line + strlen ("DATA_KEY="), KEY_PASSWORD);
		else if (PREFIX (line, "SECRET_VAL=")) {
			if (want_secret && !password) {
				password = g_strdup (line + strlen ("SECRET_VAL="));
				break;
			}
			want_secret = FALSE;
		} else if (PREFIX (line, "DATA_VAL=")) {
			if (want_data && !password)
				password = g_strdup (line + strlen ("DATA_VAL="));
			want_data = FALSE;
		}
	}

	free (line);
	return password;
}

int
main (int argc, char *argv[])
{
	char *password;

	password = read_password_from_connection ();

	if (password && *password) {
		g_print ("%s\n%s\n", KEY_PASSWORD, password);
		g_free (password);
	}

	return 0;
}

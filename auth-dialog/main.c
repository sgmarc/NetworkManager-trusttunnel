/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Interactive authentication dialog for TrustTunnel connections.
 *
 * The connection is piped to us on stdin as
 *
 *     DATA_KEY=<key>\nDATA_VAL=<value>\n\n
 *     SECRET_KEY=<key>\nSECRET_VAL=<value>\n\n
 *     DONE\n\n
 *
 * The answer is written to stdout in the old-style line protocol
 * accepted by the GNOME Shell agent: one "<key>\n<value>\n" pair per
 * secret, terminated by two empty lines. The agent then writes
 * "QUIT\n\n" back, which we must consume before exiting 0. Exiting
 * with a nonzero status reports USER_CANCELED — which is also what we
 * do when the user cancels the dialog or when "QUIT\n\n" arrives
 * before the answer (NM rescinded the request).
 */

#include <glib/gi18n.h>
#include <gtk/gtk.h>
#include <stdio.h>
#include <string.h>

#include "nm-service-defines.h"

#define KEY_PASSWORD NM_TRUSTTUNNEL_KEY_PASSWORD

typedef struct {
	GMainLoop *loop;
	GtkWidget *dialog;
	GtkWidget *entry;
	char *password;         /* from the pipe, or from the dialog */
	char *server;           /* for the prompt message */
	gboolean canceled;
	gboolean request_new;   /* "-r": always show the dialog */
	guint watch;            /* stdin watch (for QUIT while asking) */
} App;

/*****************************************************************************/

/* Parse one request line, keeping track of the current key and whether
 * it is a secret. Returns TRUE at DONE. */
static gboolean
handle_request_line (App *app, const char *line)
{
	static char *key;
	static gboolean is_secret;

	if (g_str_has_prefix (line, "DATA_KEY=")) {
		g_free (key);
		key = g_strdup (line + strlen ("DATA_KEY="));
		is_secret = FALSE;
	} else if (g_str_has_prefix (line, "SECRET_KEY=")) {
		g_free (key);
		key = g_strdup (line + strlen ("SECRET_KEY="));
		is_secret = TRUE;
	} else if (g_str_has_prefix (line, "SECRET_VAL=")
	           || g_str_has_prefix (line, "DATA_VAL=")) {
		char *val = g_strdup (g_str_has_prefix (line, "SECRET_VAL=")
		                      ? line + strlen ("SECRET_VAL=")
		                      : line + strlen ("DATA_VAL="));

		if (is_secret && g_strcmp0 (key, KEY_PASSWORD) == 0 && !app->password) {
			g_free (app->password);
			app->password = val;
		} else if (!is_secret
		           && g_strcmp0 (key, NM_TRUSTTUNNEL_KEY_SERVER) == 0) {
			g_free (app->server);
			app->server = val;
		} else {
			g_free (val);
		}
	} else {
		g_clear_pointer (&key, g_free);
		is_secret = FALSE;
		return g_str_equal (line, "DONE");
	}

	return FALSE;
}

/*****************************************************************************/

/* New-style external UI mode: report what should be asked and let the
 * shell show its own dialog (with the password-storage options). The
 * shell then dispatches the secrets back to NetworkManager itself. */
static void
output_keyfile_new_style (const App *app, gboolean should_ask)
{
	GKeyFile *kf = g_key_file_new ();
	char *data;

	g_key_file_set_integer (kf, "VPN Plugin UI", "Version", 2);
	g_key_file_set_string (kf, "VPN Plugin UI", "Title", _("TrustTunnel VPN"));
	{
		g_autofree char *description = NULL;

		if (app->server && app->server[0])
			description = g_strdup_printf (_("Password needed to connect to %s"),
			                               app->server);
		else
			description = g_strdup (_("Password needed to connect to the VPN server"));

		g_key_file_set_string (kf, "VPN Plugin UI", "Description", description);
	}
	g_key_file_set_string (kf, KEY_PASSWORD, "Label", _("Password:"));
	g_key_file_set_string (kf, KEY_PASSWORD, "Value",
	                       app->password ? app->password : "");
	g_key_file_set_boolean (kf, KEY_PASSWORD, "ShouldAsk", should_ask);
	g_key_file_set_boolean (kf, KEY_PASSWORD, "IsSecret", TRUE);

	data = g_key_file_to_data (kf, NULL, NULL);
	fputs (data, stdout);
	fflush (stdout);

	g_free (data);
	g_key_file_free (kf);
}

/*****************************************************************************/

static void
dialog_response (GtkDialog *dialog, int response, App *app)
{
	if (response != GTK_RESPONSE_OK) {
		/* Either button or window close: the user refused. */
		app->canceled = TRUE;
		g_main_loop_quit (app->loop);
		return;
	}

	g_free (app->password);
	app->password = g_strdup (gtk_entry_get_text (GTK_ENTRY (app->entry)));
	g_main_loop_quit (app->loop);
}

static void
ask_interactively (App *app)
{
	GtkWidget *grid;
	GtkWidget *label;
	GtkWidget *content;

	app->dialog = gtk_dialog_new_with_buttons (_("TrustTunnel VPN"),
	                                           NULL,
	                                           0,
	                                           _("Cancel"), GTK_RESPONSE_CANCEL,
	                                           _("OK"), GTK_RESPONSE_OK,
	                                           NULL);
	gtk_window_set_resizable (GTK_WINDOW (app->dialog), FALSE);

	content = gtk_dialog_get_content_area (GTK_DIALOG (app->dialog));
	grid = gtk_grid_new ();
	gtk_grid_set_row_spacing (GTK_GRID (grid), 10);
	gtk_grid_set_column_spacing (GTK_GRID (grid), 12);
	gtk_container_set_border_width (GTK_CONTAINER (grid), 12);
	gtk_box_pack_start (GTK_BOX (content), grid, TRUE, TRUE, 0);

	label = gtk_label_new (_("Password:"));
	gtk_widget_set_halign (label, GTK_ALIGN_END);
	gtk_grid_attach (GTK_GRID (grid), label, 0, 0, 1, 1);

	app->entry = gtk_entry_new ();
	gtk_entry_set_visibility (GTK_ENTRY (app->entry), FALSE);
	gtk_entry_set_activates_default (GTK_ENTRY (app->entry), TRUE);
	gtk_grid_attach (GTK_GRID (grid), app->entry, 1, 0, 1, 1);

	gtk_dialog_set_default_response (GTK_DIALOG (app->dialog), GTK_RESPONSE_OK);
	g_signal_connect (app->dialog, "response", G_CALLBACK (dialog_response), app);
	gtk_widget_show_all (app->dialog);
}

/* The agent only ever writes "QUIT\n\n" while we are asking (an
 * external cancel), so any byte read here means the request is gone
 * and we must leave without answering. */
static gboolean
stdin_watch_cb (GIOChannel *io, GIOCondition cond, gpointer user_data)
{
	App *app = user_data;
	char *line;
	gsize len;

	while (g_io_channel_read_line (io, &line, &len, NULL, NULL) == G_IO_STATUS_NORMAL) {
		g_free (line);
		break;
	}

	/* The agent only ever writes data here when the request is being
	 * canceled (QUIT) — leave without answering. */
	exit (1);
}

/*****************************************************************************/

int
main (int argc, char *argv[])
{
	App app = { 0, };
	GIOChannel *io;
	char *line;
	gsize len;
	gboolean done = FALSE;
	gboolean external_ui = FALSE;
	int i;

	gtk_init (&argc, &argv);

	for (i = 1; i < argc; i++) {
		if (g_str_equal (argv[i], "--external-ui-mode"))
			external_ui = TRUE;
		else if (g_str_equal (argv[i], "-r"))
			app.request_new = TRUE;
	}

	io = g_io_channel_unix_new (0);

	/* Phase 1: read the request until DONE. The agent blocks on
	 * writing it, so nobody expects us to interleave a GTK loop here. */
	while (!done) {
		GIOStatus status = g_io_channel_read_line (io, &line, &len, NULL, NULL);

		if (status != G_IO_STATUS_NORMAL)
			break;

		g_strchomp (line);
		done = handle_request_line (&app, line);
		g_free (line);
	}

	/* The request ends with "DONE\n\n" — after DONE one blank line may
	 * still be in flight; drain it (nonblocking) so the QUIT watch is
	 * not triggered by leftover data. */
	g_io_channel_set_flags (io, G_IO_FLAG_NONBLOCK, NULL);
	while (g_io_channel_read_line (io, &line, &len, NULL, NULL) == G_IO_STATUS_NORMAL) {
		gboolean any = g_strcmp0 (line, "\n") != 0;

		g_free (line);
		if (any)
			break;
	}
	g_io_channel_set_flags (io, 0, NULL);

	if (external_ui) {
		/* New-style: report and let the shell handle everything.
		 * "No secrets stored" → ask in the shell dialog; an existing
		 * password is reported as is, unless "-r" (ask again). */
		gboolean should_ask = !app.password || !app.password[0] || app.request_new;

		output_keyfile_new_style (&app, should_ask);

		/* Wait for the shell to close the pipe (dialog done or canceled). */
		while (g_io_channel_read_line (io, &line, &len, NULL, NULL) == G_IO_STATUS_NORMAL)
			g_free (line);
		return 0;
	}

	if (!app.password || !app.password[0]) {
		/* Phase 2: the password is unknown (an empty value means no
		 * secret is stored) — ask. Watch stdin so that a cancel
		 * (QUIT arriving before our answer) closes the dialog. */
		app.watch = g_io_add_watch (io, G_IO_IN | G_IO_HUP,
		                            stdin_watch_cb, &app);
		ask_interactively (&app);

		app.loop = g_main_loop_new (NULL, FALSE);
		g_main_loop_run (app.loop);

		g_source_remove (app.watch);
		g_clear_pointer (&app.dialog, gtk_widget_destroy);

		if (app.canceled || !app.password || !app.password[0])
			return 1;
	}

	/* Phase 3: answer, then wait for the agent's ack. */
	if (app.password) {
		printf ("%s\n%s\n", KEY_PASSWORD, app.password);
		g_free (app.password);
	}
	printf ("\n\n");
	fflush (stdout);

	while (TRUE) {
		GIOStatus status = g_io_channel_read_line (io, &line, &len, NULL, NULL);
		gboolean quit;

		if (status != G_IO_STATUS_NORMAL)
			break;

		quit = strstr (line, "QUIT") != NULL;
		g_free (line);
		if (quit)
			break;
	}

	return 0;
}

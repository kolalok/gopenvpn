/* gopenvpn.c
 * Copyright (C) 2006 Gary Grossman <gary@softwareasart.com>
 *
 * This program is free software; you can redistribute it and/or 
 * modify it under the terms of the GNU General Public License as 
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
 * USA
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <glob.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <paths.h>
#include <ctype.h>
#include <strings.h>
#include <pwd.h>
#include <syslog.h>

#include <glib.h>
#include <glib/gi18n.h>
#include <glib/gstdio.h>
#include <gtk/gtk.h>
#include <libsecret/secret.h>
#include <libayatana-appindicator/app-indicator.h>


#include "gettext.h"
#include "gopenvpn.h"

#ifndef _PATH_VARRUN
#define	_PATH_VARRUN	"/var/run/"
#endif

#ifndef _PATH_VARTMP
#define	_PATH_VARTMP	"/var/tmp/"
#endif

/* Filename of a state file given a connection's name */
#define STATEFILENAMEFMT _PATH_VARTMP "gopenvpn.%s.state"

/* Filename of a pid file given a connection's name */
#define PIDFILENAMEFMT _PATH_VARRUN "gopenvpn.%s.pid"

/* Section name based on the connection name */
#define CONNSECTIONFMT "conn_%s"

/*
 * VPNConfig Section
 */

/*
 * Enum constants for VPNConfig.state
 */

#define INACTIVE   0
#define CONNECTING 1
#define RECONNECTING 2
#define SENTSTATE  3
#define CONNECTED  4

typedef struct VPNApplet VPNApplet;

/*
 * VPNConfig type
 */

typedef struct VPNConfig
{
	VPNApplet         *applet;
	char              *name;
	char              *file;
	GtkWidget         *menuitem;
	gboolean           auto_connect;
	gboolean           use_keyring;
	char              *pidfilename;

	/* these are set per-connect instance and should be cleared between connections
	   except for "buffer" */
	GtkTextBuffer     *buffer;
	GIOChannel        *channel;
	int                state;
	int                retry;
	struct sockaddr_in sockaddr;
	pid_t		   pid;
	time_t		   connecting_start_time;
}
VPNConfig;

/*
 * VPNApplet type
 */

struct VPNApplet
{
	VPNConfig     *configs;
	int            configs_count;
	GtkWidget     *menu;
	GtkWidget     *count_item;
	GtkBuilder    *details_xml;
	gboolean       connecting;
	char          *auth_dialog_ui;
	char          *passphrase_dialog_ui;
	char          *details_dialog_ui;
	char          *closed_image;
	char          *connecting_image;	
	char          *open_image;
	int            last_details_page;
	gboolean       in_modal;
	gboolean       no_toggle;
	GKeyFile      *preferences;
	GKeyFile      *state;
	GHashTable    *configs_table;
	gboolean       batchmode;
	AppIndicator *app_indicator;

	/* these are used in batch mode */
	char          *homedir;
	uid_t          uid;
	gid_t          gid;
};

/*
 * Forward declarations
 */

gboolean vpn_applet_get_password(VPNApplet *applet,
								 const char *name,
								 char **username,
								 char **password);
void vpn_applet_update_count_and_icon(VPNApplet *applet);
void vpn_applet_update_preferences(VPNApplet *applet);
void vpn_applet_update_state(VPNApplet *applet);
void vpn_applet_update_details_dialog(VPNApplet *applet, int page_num);
void vpn_applet_display_error(VPNApplet *applet, const char *format, ...);
gboolean vpn_config_try_connect(gpointer user_data);
gboolean vpn_connect_monitor(gpointer user_data);
gboolean vpn_config_io_callback(GSource *source,
								GIOCondition condition,
								gpointer user_data);
void vpn_applet_destroy(VPNApplet *applet);

/*
 * Global variables
 */

VPNApplet *g_applet = NULL;	

/*
 * GNOME keyring support
 */

const SecretSchema * govpn_get_schema (void) G_GNUC_CONST;
#define GOVPN_SEC_SCHEMA govpn_get_schema ()

const SecretSchema *
govpn_get_schema (void)
{
	static const SecretSchema the_schema = {
	    "net.openvpn.gui.gopenvpn.Password", SECRET_SCHEMA_NONE,
	    {
	        {  "config_name", SECRET_SCHEMA_ATTRIBUTE_STRING },
	        {  "NULL", 0 },
	    }
	};
	return &the_schema;
}

gboolean get_keyring(const char *config_name,
					 char **username,
					 char **passphrase)
{
	GError *error = NULL;
	gchar *password;
	char **fields;

	g_return_val_if_fail(config_name != NULL, FALSE);
	g_return_val_if_fail(passphrase != NULL, FALSE);

	/* TODO This method may block indefinitely and should not be used in user interface threads. */
	password = secret_password_lookup_sync (GOVPN_SEC_SCHEMA, NULL, &error,
												   "config_name", config_name,
												   NULL);

	if (error != NULL) {
		syslog(LOG_WARNING, "Error retrieving password: %s\n", error->message);
		g_error_free (error);

		return FALSE;
	} else if (password == NULL) {
		/* no matching password found */
		return FALSE;
	} else {
		fields = g_strsplit(password, ":", 2);
		secret_password_free (password);

		if (g_strv_length(fields) != 2)
		{
			g_strfreev(fields);
			return FALSE;
		}

		if (username)
			*username = g_strdup(fields[0]);
		*passphrase = g_strdup(fields[1]);
		g_strfreev(fields);

		return TRUE;
	}
}

void set_keyring(const char *config_name,
				 const char *username,
				 const char *passphrase)
{
	GError *error = NULL;
	char *display_name;
	char *secret;

	display_name = g_strdup_printf(_("Passphrase for OpenVPN connection %s"), config_name);
	secret = g_strdup_printf("%s:%s", username ? username : "", passphrase);

	/* TODO This method may block indefinitely and should not be used in user interface threads. */
	secret_password_store_sync (GOVPN_SEC_SCHEMA, SECRET_COLLECTION_DEFAULT,
								display_name, secret, NULL, &error,
								"config_name", config_name,
								NULL);
	g_free(display_name);
	g_free(secret);

	if (error != NULL) {
		syslog(LOG_WARNING, "Error saving password: %s\n", error->message);
		g_error_free (error);
	}
}

/*
 * Utility functions
 */

void socket_printf(GIOChannel *channel,
				   const char *format,
				   ...)
{
	va_list ap;
	char *text;
	gsize bytes_written;

	va_start(ap, format);
	text = g_strdup_vprintf(format, ap);
	va_end(ap);

	g_io_channel_write_chars(channel, text, strlen(text), &bytes_written, NULL);
	g_io_channel_flush(channel, NULL);

	g_free(text);
}

GString *openvpn_mgmt_string_escape(gchar *str)
{
	char *s;
	GString *rval;
	gchar c;

	if (!str)
		return NULL;

	for (s = str, rval = g_string_new("") ; (c = *s) != '\0' ; ++s)
	{
		switch (c)
		{
			case '\\':
				g_string_append(rval, "\\\\");
				break;
			case '"':
				g_string_append_c(rval, '"');
				break;
			default:
				g_string_append_c(rval, c);
				break;
		}
	}
	return rval;
}

void set_menuitem_label(GtkWidget *menuitem,
						const char *format,
						...)
{
	va_list ap;
	char *text;

	g_return_if_fail(menuitem != NULL);
	g_return_if_fail(format != NULL);
	g_return_if_fail(GTK_IS_CONTAINER(menuitem));

	va_start(ap, format);
	text = g_strdup_vprintf(format, ap);
	va_end(ap);

	gtk_menu_item_set_label(GTK_MENU_ITEM(menuitem), text);

	g_free(text);
}

gboolean starts_with(const char *string,
					 const char *substring)
{
	return strncmp(string, substring, strlen(substring)) == 0;
}

char** parse_openvpn_output(const char *string,
							const char *prefix,
							gint num_fields)
{
	char **fields;

	if (!starts_with(string, prefix))
		return NULL;

	fields = g_strsplit(string+strlen(prefix),
						",",
						num_fields);

	if (g_strv_length(fields) != num_fields)
	{
		g_strfreev(fields);
		return NULL;
	}

	return fields;
}

void all_auto_up(VPNApplet *applet, gboolean early)
{
	int i, wantup = 0, isup = 0;
	VPNConfig *conf;
	for (i=0, conf = applet->configs ; i<applet->configs_count; i++, conf++)
	{
		if (conf->auto_connect)
		{
			++wantup;
			if (conf->state == CONNECTED)
				++isup;
		}
	}
	if (wantup == isup)
	{
		if (early)
			exit(0);
		gtk_main_quit();
	}
}

/*
 * Main program
 */

void vpn_config_stop(VPNConfig *self)
{
	VPNApplet *applet = self->applet;

	/* Do nothing if already disconnected */
	if (self->state == INACTIVE)
		return;

	if (self->channel)
	{
		socket_printf(self->channel, "signal SIGTERM\r\n");
		g_io_channel_shutdown(self->channel, TRUE, NULL);
		g_io_channel_unref(self->channel);
		self->channel = NULL;
	}

	g_source_remove_by_user_data(self);

	if (!applet->batchmode)
	{
		gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(self->menuitem),
									   FALSE);

		set_menuitem_label(self->menuitem, _("Connect %s"), self->name);
	}

	bzero(&self->sockaddr, sizeof self->sockaddr);
	self->pid = 0;
	vpn_applet_update_state(applet);
	self->state = INACTIVE;
	vpn_applet_update_count_and_icon(applet);
	syslog(LOG_NOTICE, "connection \"%s\" state = INACTIVE", self->name);
}


int vpn_connect_monitor(gpointer user_data)
{
	VPNConfig *self = (VPNConfig*)user_data;
	VPNApplet *applet = (VPNApplet*)self->applet;
	time_t waittime;

	if (self->state == CONNECTED)
		return 0;

	waittime = time(NULL) - self->connecting_start_time;
	if (waittime < 60)
	{
		syslog(LOG_DEBUG, "vpn_connect_monitor: connection \"%s\" waiting for %d seconds", self->name, (int)waittime);
		return 1;
	}
	syslog(LOG_DEBUG, "vpn_connect_monitor: giving up on connection \"%s\"", self->name);
	vpn_config_stop(self);
	self->auto_connect = FALSE;
	all_auto_up(applet, FALSE);
	return 0;
}

int vpn_config_try_connect(gpointer user_data)
{
	VPNConfig *self = (VPNConfig*)user_data;
	VPNApplet *applet = (VPNApplet*)self->applet;
	int s;
	FILE *pidfp = NULL; 
	char pidbuf[100];

	/* Connect to the gopenvpn-server */
	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0)
	{
		vpn_config_stop(self);
		vpn_applet_display_error(applet, _("Error creating socket to talk to OpenVPN management interface"));
		return FALSE;
	}		

	if (connect(s,
				(struct sockaddr*)&self->sockaddr,
				sizeof(self->sockaddr)))
	{
		if (++self->retry >= MAX_RETRY)
		{
			vpn_config_stop(self);
			vpn_applet_display_error(applet, _("Error connecting to OpenVPN management interface"));
			return -1;
		}
		else
			return 1;
	}

	/* We're connected! */

	/* Add an I/O watch for the pipe */
	self->channel = g_io_channel_unix_new(s);
	g_io_channel_set_flags(self->channel, G_IO_FLAG_NONBLOCK, NULL);

	g_io_add_watch(self->channel, G_IO_IN|G_IO_HUP|G_IO_ERR,
				   (GIOFunc)vpn_config_io_callback, self);

	/* Get the pid and write it into the state file */
	if (self->pidfilename
	 && (pidfp = g_fopen(self->pidfilename, "r")) != NULL
	 && fgets(pidbuf, sizeof pidbuf, pidfp))
	{
		if (isdigit(pidbuf[0]))
			self->pid = (int)strtol(pidbuf, NULL, 10);
		vpn_applet_update_state(applet);
	}
	if (pidfp)
		fclose(pidfp);

	return 0;
}

void vpn_config_clear_log(VPNConfig *self)
{
	GtkTextIter start_iter, end_iter;

	gtk_text_buffer_get_start_iter(GTK_TEXT_BUFFER(self->buffer),
								   &start_iter);
	gtk_text_buffer_get_end_iter(GTK_TEXT_BUFFER(self->buffer),
								 &end_iter);
	gtk_text_buffer_delete(GTK_TEXT_BUFFER(self->buffer),
						   &start_iter,
						   &end_iter);
}

void vpn_config_start(VPNConfig *self)
{
	VPNApplet *applet = self->applet;
	char *ovpn_args[] = {PKEXEC_BINARY_PATH, OPENVPN_BINARY_PATH, NULL, NULL, NULL, NULL, NULL, NULL,
			     NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL};

	int s;
	pid_t pid;
	socklen_t namelen;
	int status, port;

	/* Check the popup menu item */
	if (!applet->batchmode)
		gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(self->menuitem),
									   TRUE);

	/* Clear the logs */
	if (!applet->batchmode)
		vpn_config_clear_log(self);

	/* Do nothing if already connected */
	if (self->state != INACTIVE)
		return;

	self->use_keyring = !applet->batchmode;

	/* Choose a port for the OpenVPN management port */
	self->sockaddr.sin_family      = AF_INET;
	self->sockaddr.sin_addr.s_addr = INADDR_ANY;
	self->sockaddr.sin_port        = 0;

	s = socket(AF_INET, SOCK_STREAM, 0);
	namelen = sizeof(self->sockaddr);
	if (bind(s, (const struct sockaddr *)&self->sockaddr, sizeof(self->sockaddr)) ||
		getsockname(s, (struct sockaddr *)&self->sockaddr, &namelen))
	{
		if (!applet->batchmode)
		{
			vpn_applet_display_error(applet, _("Could not find an open TCP port for OpenVPN's management interface"));
			gtk_check_menu_item_set_active(GTK_CHECK_MENU_ITEM(self->menuitem),
										   FALSE);
		}
		return;
	}

	port = ntohs(self->sockaddr.sin_port);
	close(s);

	ovpn_args[2]  = "--cd";
	ovpn_args[3]  = g_strdup_printf("%s", CONFIG_PATH);
	ovpn_args[4]  = "--daemon";
	ovpn_args[5]  = "--script-security";
	ovpn_args[6]  = "2";
	ovpn_args[7]  = "--management-query-passwords";
	ovpn_args[8]  = "--management-hold";
	ovpn_args[9]  = "--management";
	ovpn_args[10] = "127.0.0.1";
	ovpn_args[11] = g_strdup_printf("%d", port);
	ovpn_args[12] = "--config";
	ovpn_args[13] = g_strdup_printf("%s", self->file);

	ovpn_args[14] = "--writepid";
	self->pidfilename = ovpn_args[15] = g_strdup_printf(PIDFILENAMEFMT, self->name);

	/* Start the openvpn subprocess */
	pid = fork();
	if (!pid)
	{
		/* Child process */
		execve(applet->batchmode ? OPENVPN_BINARY_PATH : PKEXEC_BINARY_PATH, applet->batchmode ? ovpn_args + 1 : ovpn_args, NULL);
		exit(-1);
	}

	waitpid(pid, &status, 0);

	g_free(ovpn_args[3]);
	g_free(ovpn_args[11]);
	g_free(ovpn_args[13]);

	if (status != 0 || pid == -1)
	{
		vpn_applet_display_error(applet, _("Error launching OpenVPN subprocess"));
		return;
	}

	/* Change the menu item */
	if (!applet->batchmode)
		set_menuitem_label(self->menuitem, _("Disconnect %s"), self->name);

	self->state = CONNECTING;
	self->connecting_start_time = time(NULL);
	vpn_applet_update_count_and_icon(applet);
	syslog(LOG_NOTICE, "connection \"%s\" state = CONNECTING", self->name);

	/* The OpenVPN management port may take a little while to come up.
	   Sleep a few seconds and give it a few tries. */
	self->retry = 0;
	g_timeout_add(1000, vpn_config_try_connect, self);

	/* In batch mode, monitor the connecting process */
	if (applet->batchmode)
		g_timeout_add(10000, vpn_connect_monitor, self);
}

/* XXX - make sure all the "self" stuff is actually freed here */
void vpn_config_free(VPNConfig *self)
{
	if (self->name)
	{
		g_free(self->name);
		self->name = NULL;
	}
	if (self->file)
	{
		g_free(self->file);
		self->file = NULL;
	}
	if (self->buffer)
	{
		g_object_unref(self->buffer);
		self->buffer = NULL;
	}
	if (self->channel)
	{
		g_io_channel_shutdown(self->channel, TRUE, NULL);
		g_io_channel_unref(self->channel);
		self->channel = NULL;
	}
}

void vpn_config_clicked(GtkMenuItem *menuitem,
						gpointer user_data)
{
	VPNConfig *self = (VPNConfig*)user_data;
	if (self->state != INACTIVE)
		vpn_config_stop(self);
	else
		vpn_config_start(self);
}

VPNConfig* vpn_config_get(VPNApplet *applet, int index)
{
	if (index >= 0 && index < applet->configs_count)
		return &applet->configs[index];
	else
		return NULL;
}

VPNConfig* vpn_config_find(VPNApplet *applet, const char *name)
{
	return g_hash_table_lookup(applet->configs_table, name);
}

void vpn_config_init(VPNConfig *self,
					 VPNApplet *applet,
					 const char *file)
{
	char *slash;
	char *period;

	bzero(self, sizeof *self);
	self->applet       = applet;
	self->file         = g_strdup(file);
	self->state        = INACTIVE;
	self->use_keyring  = !applet->batchmode;
	if (!applet->batchmode)
		self->buffer       = gtk_text_buffer_new(NULL);
	self->name         = g_strdup(file);

	slash = strrchr(file, '/');
	self->name = g_strdup(slash ? slash+1 : file);

	period = strrchr(self->name, '.');
	if (period)
		*period = 0;

	if (!applet->batchmode)
	{
		self->menuitem = gtk_check_menu_item_new_with_label("");

		set_menuitem_label(self->menuitem, _("Connect %s"), self->name);

		g_signal_connect(self->menuitem, "activate",
						 G_CALLBACK(vpn_config_clicked),
						 self);
	}
}

gboolean vpn_config_io_callback(GSource *source,
								GIOCondition condition,
								gpointer user_data)
{
	VPNConfig *self = (VPNConfig*)user_data;
	VPNApplet *applet = self->applet;
	char *line;
	char **fields;
	gsize len;
	GIOStatus gstat;

	/* We may have shut down the connection, but not yet fired
	 * the glib IOWatch callback */
	if (!self->channel)
		return FALSE;

	if (condition == G_IO_HUP || condition == G_IO_ERR)
	{
		VPNConfig *config = (VPNConfig*)user_data;
		vpn_config_stop(config);
		return FALSE;
	}

	for (;;)
	{
		fields = NULL;
		gstat = g_io_channel_read_line(self->channel,
								   &line,
								   &len,
								   NULL,
								   NULL);
		if (gstat == G_IO_STATUS_EOF)
		{
			vpn_config_stop(self);
			return FALSE;
		}

		if (!line || len == 0)
			break;

		g_strchomp(line);
		/* syslog(LOG_NOTICE, "got line=\"%s\"", line); */

		if (!strcmp(line, ">PASSWORD:Need 'Private Key' password"))
		{
			char *password;
			GString *GSpassword;
			gboolean got_keyring = FALSE;

			if (self->use_keyring)
			{
				got_keyring = get_keyring(self->name,
										  NULL,
										  &password);
				self->use_keyring = !got_keyring;
			}

			if (!got_keyring)
			{
				if (!vpn_applet_get_password(applet,
											 self->name,
											 NULL,
											 &password))
					continue;
			}

			if (applet->batchmode && (!strcmp(password, "") || password == NULL))
				gtk_main_quit();

			GSpassword = openvpn_mgmt_string_escape(password);
			g_free(password);

			socket_printf(self->channel,
						  "password \"Private Key\" \"%s\"\r\n",
						  GSpassword->str);

			g_string_free(GSpassword, TRUE);
		}

		else if (!strcmp(line, ">PASSWORD:Need 'Auth' username/password"))
		{
			char *username, *password;
			GString *GSusername, *GSpassword;
			gboolean got_keyring = FALSE;

			if (self->use_keyring)
			{
				got_keyring = get_keyring(self->name,
										  &username,
										  &password);
				self->use_keyring = !got_keyring;
			}

			if (!got_keyring)
			{
				if (!vpn_applet_get_password(applet,
											 self->name,
											 &username,
											 &password))
					continue;
			}

			GSusername = openvpn_mgmt_string_escape(username);
			GSpassword = openvpn_mgmt_string_escape(password);
			g_free(username);
			g_free(password);

			socket_printf(self->channel,
						  "username \"Auth\" \"%s\"\r\n",
						  GSusername->str);

			socket_printf(self->channel,
						  "password \"Auth\" \"%s\"\r\n",
						  GSpassword->str);

			g_string_free(GSusername, TRUE);
			g_string_free(GSpassword, TRUE);

		}

		else if (starts_with(line, ">INFO:"))
		{
			if (self->state == RECONNECTING)
			{
				/* Tell OpenVPN to log in real time */
				socket_printf(self->channel, "log on all\r\n", NULL);

				/* Turn on real-time state notifications */
				socket_printf(self->channel, "state on\r\n", NULL);

				/* Tell OpenVPN to retry on bad passwords */
				socket_printf(self->channel, "auth-retry interact\r\n", NULL);

				self->state = SENTSTATE;
				vpn_applet_update_count_and_icon(applet);
				syslog(LOG_NOTICE, "vpn_config_io_callback: connection \"%s\" state = SENTSTATE", self->name);
				socket_printf(self->channel, "state\r\n", NULL);

				/* Let OpenVPN start its business */
				socket_printf(self->channel, "hold release\r\n", NULL);
			}
			else
			{
				/* Tell OpenVPN to log in real time */
				socket_printf(self->channel, "log on all\r\n", NULL);

				/* Turn on real-time state notifications */
				socket_printf(self->channel, "state on\r\n", NULL);

				/* Tell OpenVPN to retry on bad passwords */
				socket_printf(self->channel, "auth-retry interact\r\n", NULL);

				/* Let OpenVPN start its business */
				socket_printf(self->channel, "hold release\r\n", NULL);
			}
		}

		else if ((fields = parse_openvpn_output(line,
												">STATE:",
												4)) != NULL)
		{
			char *state = fields[1];

			if (!strcmp(state, "RECONNECTING"))
			{
				/* Change our state back to connecting */
				syslog(LOG_NOTICE, "vpn_config_io_callback: connection \"%s\" state = \"RECONNECTING\"->CONNECTING", self->name);
				self->state = CONNECTING;
				self->connecting_start_time = time(NULL);

				vpn_applet_update_count_and_icon(applet);

				/* Let OpenVPN restart its business */
				socket_printf(self->channel, "hold release\r\n", NULL);
			}
			else if (!strcmp(state, "CONNECTED"))
			{
				syslog(LOG_NOTICE, "vpn_config_io_callback: connection \"%s\" state = \"CONNECTED\"->CONNECTED", self->name);
				self->state = CONNECTED;
				if (applet->batchmode)
					all_auto_up(applet, FALSE);
				else
				{
					vpn_applet_update_state(applet);
					vpn_applet_update_count_and_icon(applet);
				}
			}
			else if (!strcmp(state, "EXITING") && self->state != RECONNECTING)
			{
				if (applet->batchmode)
					gtk_main_quit();
				self->state = INACTIVE;
				syslog(LOG_NOTICE, "vpn_config_io_callback: connection \"%s\" state = \"EXITING\"->INACTIVE", self->name);
				break;
			}
		}

		else if (!applet->batchmode && (fields = parse_openvpn_output(line,
												">LOG:",
												3)) != NULL)
		{
			time_t timestamp;
			char *message, *time_string, *line;
			GtkTextIter iter;

			timestamp = atol(fields[0]);
			message = fields[2];

			time_string = g_strdup(ctime(&timestamp));
			g_strchomp(time_string);

			line = g_strdup_printf("%s: %s\r\n",
								   time_string,
								   message);

			gtk_text_buffer_get_end_iter(GTK_TEXT_BUFFER(self->buffer),
										 &iter);

			gtk_text_buffer_insert(GTK_TEXT_BUFFER(self->buffer),
								   &iter,
								   line,
								   strlen(line));
		}
		else if (self->state == SENTSTATE)
		{
			if ((fields = parse_openvpn_output(line, "", 5)) != NULL)
			{
				if (!strcmp(fields[1], "CONNECTED"))
				{
					syslog(LOG_NOTICE, "vpn_config_io_callback: connection \"%s\" state = CONNECTED", self->name);
					self->state = CONNECTED;
					if (applet->batchmode)
						all_auto_up(applet, FALSE);
					else
					{
						vpn_applet_update_state(applet);
						vpn_applet_update_count_and_icon(applet);
					}
				}
			g_strfreev(fields);
			}
		}
		g_free(line);
	}
	return TRUE;
}

gint vpn_applet_run_dialog(VPNApplet *applet,
						   GtkDialog *dialog)
{
	gint response;
	applet->in_modal = TRUE;
	response = gtk_dialog_run(dialog);
	applet->in_modal = FALSE;
	return response;
}

void vpn_applet_display_error(VPNApplet *applet, const char *format, ...)
{
	va_list ap;
	GtkWidget *dialog;
	char *text;

	if (applet->batchmode)
		return;

	va_start(ap, format);
	text = g_strdup_vprintf(format, ap);
	va_end(ap);

	dialog = gtk_message_dialog_new(NULL,
									GTK_DIALOG_MODAL|
									GTK_DIALOG_DESTROY_WITH_PARENT,
									GTK_MESSAGE_ERROR,
									GTK_BUTTONS_OK,
									text);

	g_free(text);

	vpn_applet_run_dialog(applet, GTK_DIALOG(dialog));

	gtk_widget_destroy(dialog);
}

/*
 * VPNApplet implementation
 */

VPNApplet *vpn_applet_new()
{
	VPNApplet *self = g_new(VPNApplet, 1);

	self->configs           = NULL;
	self->configs_count     = 0;
	self->menu              = NULL;
	self->count_item        = NULL;
	self->details_xml       = NULL;
	self->connecting        = FALSE;
	self->auth_dialog_ui    = NULL;
	self->passphrase_dialog_ui = NULL;
	self->details_dialog_ui = NULL;
	self->closed_image      = NULL;
	self->connecting_image  = NULL;	
	self->open_image        = NULL;
	self->last_details_page = 0;
	self->in_modal          = FALSE;
	self->no_toggle         = FALSE;
	self->preferences       = NULL;
	self->configs_table     = NULL;
	self->batchmode         = FALSE;
	self->app_indicator     = NULL;

	return self;
}

GtkWidget *vpn_applet_create_text(GtkTextBuffer *buffer)
{
	GtkWidget *text_view;
	GtkWidget* scrolled_window = gtk_scrolled_window_new(NULL,
														 NULL);

	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled_window),
								   GTK_POLICY_AUTOMATIC,
								   GTK_POLICY_AUTOMATIC);

	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(scrolled_window),
										GTK_SHADOW_IN);

	text_view = gtk_text_view_new();

	gtk_container_add(GTK_CONTAINER(scrolled_window),
					  text_view);

	gtk_text_view_set_buffer(GTK_TEXT_VIEW(text_view), buffer);
	gtk_text_view_set_editable(GTK_TEXT_VIEW(text_view), FALSE);
	gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(text_view), FALSE);
	gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(text_view), GTK_WRAP_NONE);

	return scrolled_window;
}

void vpn_applet_show_password_cb(GtkToggleButton *togglebutton,
								 gpointer user_data)
{
	GtkEntry *password_entry = (GtkEntry*)user_data;

	gtk_entry_set_visibility(password_entry,
							 !gtk_entry_get_visibility(password_entry));
}

gboolean vpn_applet_get_password(VPNApplet *applet,
								 const char *name,
								 char **username,
								 char **password)
{
	GtkWidget *dialog;
	GdkWindow *window;
	GtkWidget *username_entry;
	GtkWidget *show_password;
	gboolean use_username = (username != NULL);
	GtkWidget *label;
	GtkWidget *password_entry;
	int response;
	GtkBuilder *xml = NULL;
	GtkWidget *remember_password;
	const char *dialog_ui_file;
	const char *dialog_resource;

	dialog_ui_file = use_username ? applet->auth_dialog_ui : applet->passphrase_dialog_ui;
	dialog_resource = use_username ? "auth_dialog" : "passphrase_dialog";

	xml = gtk_builder_new_from_file(dialog_ui_file);

	dialog = GTK_WIDGET (gtk_builder_get_object (xml, dialog_resource));

	label = GTK_WIDGET (gtk_builder_get_object (xml, "configuration"));
	gtk_label_set_text(GTK_LABEL(label), name);

	password_entry = GTK_WIDGET (gtk_builder_get_object (xml, "password_entry"));

	show_password = GTK_WIDGET (gtk_builder_get_object (xml, "show_password"));
	g_signal_connect(G_OBJECT(show_password),
					 "toggled",
					 G_CALLBACK(vpn_applet_show_password_cb),
					 password_entry);

	remember_password = GTK_WIDGET (gtk_builder_get_object (xml, "remember_password"));

	if (use_username)
		username_entry = GTK_WIDGET (gtk_builder_get_object (xml, "username_entry"));
	else
		username_entry = NULL;

	gtk_window_set_position(GTK_WINDOW(dialog), GTK_WIN_POS_CENTER_ALWAYS);
	gtk_widget_realize(dialog);
	gtk_dialog_set_default_response(GTK_DIALOG(dialog),
									GTK_RESPONSE_OK);

	gtk_widget_show_all(dialog);

	response = vpn_applet_run_dialog(applet, GTK_DIALOG(dialog));

	if (username)
		*username = g_strdup(gtk_entry_get_text(GTK_ENTRY(username_entry)));

	*password = g_strdup(gtk_entry_get_text(GTK_ENTRY(password_entry)));

	if (!applet->batchmode && gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(remember_password)))
	{
		set_keyring(name,
					username ? *username : NULL,
					*password);
	}

	gtk_widget_destroy(dialog);

	return (response == GTK_RESPONSE_OK);
}

void vpn_applet_set_icon_state(VPNApplet *applet, int state)
{
	switch (state)
	{
	case INACTIVE:
		app_indicator_set_icon_full(applet->app_indicator, "gopenvpn-closed", "Disconnected");
		break;
	case CONNECTING:
	case RECONNECTING:
	case SENTSTATE:
		app_indicator_set_icon_full(applet->app_indicator, "gopenvpn-connecting", "Connecting");
		break;
	case CONNECTED:
		app_indicator_set_icon_full(applet->app_indicator, "gopenvpn-open", "Connected");
		break;
	}
}

void vpn_applet_update_count_and_icon(VPNApplet *applet)
{
	int i;
	int count = 0;
	gboolean new_connecting = FALSE;
	VPNConfig *config;

	if (applet->batchmode)
		return;

	for (i=0, config=applet->configs ; i<applet->configs_count; i++, config++)
	{
		if (config->state == CONNECTED)
			count++;
		else if (config->state == CONNECTING || config->state == RECONNECTING || config->state == SENTSTATE)
			new_connecting = TRUE;
	}

	if (!applet->batchmode)
		set_menuitem_label(applet->count_item, ngettext("OpenVPN: %d connection active", "OpenVPN: %d connections active", count), count);

	if (new_connecting)
	{
		vpn_applet_set_icon_state(applet, CONNECTING);
	}
	else
	{
		vpn_applet_set_icon_state(applet, (count != 0) ? CONNECTED : INACTIVE);
	}

	vpn_applet_update_details_dialog(applet, -1);

	applet->connecting = new_connecting;
}

void vpn_applet_update_details_dialog(VPNApplet *applet, int page_num)
{
	VPNConfig *config;

	if (applet->details_xml)
	{
		/* Update Details dialog if active */
		if (page_num == -1)
		{
			GtkWidget *notebook = GTK_WIDGET (gtk_builder_get_object(applet->details_xml, "logsNotebook"));
			page_num = gtk_notebook_get_current_page(GTK_NOTEBOOK(notebook));
		}
		config = vpn_config_get(applet, page_num);
		if (config)
		{
			gboolean connecting = (config->state != INACTIVE);
			GtkWidget *connectButton = GTK_WIDGET (gtk_builder_get_object(applet->details_xml, "connect"));
			GtkWidget *disconnectButton = GTK_WIDGET (gtk_builder_get_object(applet->details_xml, "disconnect"));
			GtkWidget *auto_connect_button = GTK_WIDGET (gtk_builder_get_object(applet->details_xml, "autoConnect"));

			gtk_widget_set_sensitive(connectButton, !connecting);
			gtk_widget_set_sensitive(disconnectButton, connecting);
			applet->no_toggle = TRUE;
			gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(auto_connect_button),
										 config->auto_connect);
			applet->no_toggle = FALSE;
		}
	}
}

void vpn_applet_switch_page_cb(GtkNotebook *notebook,
							   GtkWidget *page,
							   guint page_num,
							   gpointer user_data)
{
	VPNApplet *applet = (VPNApplet*)user_data;

	vpn_applet_update_details_dialog(applet, page_num);
}

void vpn_applet_clear_log_cb(GtkButton *button, gpointer user_data)
{
	VPNApplet *applet = (VPNApplet*)user_data;

	GtkWidget *notebook = GTK_WIDGET (gtk_builder_get_object(applet->details_xml, "logsNotebook"));

	int index = gtk_notebook_get_current_page(GTK_NOTEBOOK(notebook));

	VPNConfig *config = vpn_config_get(applet, index);

	if (config)
		vpn_config_clear_log(config);
}

void vpn_applet_connect_button_cb(GtkButton *button, gpointer user_data)
{
	VPNApplet *applet = (VPNApplet*)user_data;

	GtkWidget *notebook = GTK_WIDGET (gtk_builder_get_object(applet->details_xml, "logsNotebook"));

	int index = gtk_notebook_get_current_page(GTK_NOTEBOOK(notebook));

	VPNConfig *config = vpn_config_get(applet, index);

	if (config)
		vpn_config_start(config);
}

void vpn_applet_disconnect_button_cb(GtkButton *button, gpointer user_data)
{
	VPNApplet *applet = (VPNApplet*)user_data;

	GtkWidget *notebook = GTK_WIDGET (gtk_builder_get_object(applet->details_xml, "logsNotebook"));

	int index = gtk_notebook_get_current_page(GTK_NOTEBOOK(notebook));

	VPNConfig *config = vpn_config_get(applet, index);

	if (config)
		vpn_config_stop(config);
}

void vpn_applet_edit_config_cb(GtkButton *button, gpointer user_data)
{
	VPNApplet *applet = (VPNApplet*)user_data;

	GtkWidget *notebook = GTK_WIDGET (gtk_builder_get_object(applet->details_xml, "logsNotebook"));

	int index = gtk_notebook_get_current_page(GTK_NOTEBOOK(notebook));

	VPNConfig *config = vpn_config_get(applet, index);

	if (config)
	{
		char *argv[4];

		char *editor = g_key_file_get_string(applet->preferences,
											 "Preferences",
											 "Editor",
											 NULL);

		if (!editor)
			editor = g_strdup(GEDIT_BINARY_PATH);

		argv[0] = PKEXEC_BINARY_PATH;
		argv[1] = editor;
		argv[2] = config->file;
		argv[3] = NULL;

		g_spawn_async(NULL, argv, NULL, 0,
					  NULL, NULL, NULL, NULL);

		g_free(editor);
	}
}

void vpn_applet_auto_connect_button_cb(GtkButton *button, gpointer user_data)
{
	VPNApplet *applet = (VPNApplet*)user_data;
	GtkWidget *notebook = GTK_WIDGET (gtk_builder_get_object(applet->details_xml, "logsNotebook"));
	int index;
	VPNConfig *config;

	if (applet->no_toggle)
		return;

	index = gtk_notebook_get_current_page(GTK_NOTEBOOK(notebook));

	config = vpn_config_get(applet, index);

	if (config)
	{
		config->auto_connect = !config->auto_connect;
		vpn_applet_update_preferences(applet);
	}
}

void vpn_applet_details(GtkMenuItem *menuitem,
						gpointer user_data)
{
	VPNApplet *applet = (VPNApplet*)user_data;

	GtkWidget *dialog;
	GtkWidget *notebook;
	int i, page_num;
	VPNConfig *config;

	applet->details_xml = gtk_builder_new_from_file(applet->details_dialog_ui);

	dialog = GTK_WIDGET (gtk_builder_get_object(applet->details_xml, "details_dialog"));

	notebook = GTK_WIDGET (gtk_builder_get_object(applet->details_xml, "logsNotebook"));

	for (i=0, config=applet->configs; i<applet->configs_count; i++, config++)
	{
		GtkWidget *window;
		GtkWidget *label;

		window = vpn_applet_create_text(config->buffer);
		label = gtk_label_new(config->name);
		gtk_notebook_append_page(GTK_NOTEBOOK(notebook),
								 window,
								 label);
	}

	/* Remove the dummy first page */
	gtk_notebook_remove_page(GTK_NOTEBOOK(notebook), 0);	

	gtk_builder_add_callback_symbols(applet->details_xml,
								  "switch_page",	   G_CALLBACK(vpn_applet_switch_page_cb),
								  "autoConnect",	   G_CALLBACK(vpn_applet_auto_connect_button_cb),
								  "clearLog",		  G_CALLBACK(vpn_applet_clear_log_cb),
								  "editConfiguration", G_CALLBACK(vpn_applet_edit_config_cb),
								  "connect",		   G_CALLBACK(vpn_applet_connect_button_cb),
								  "disconnect",		G_CALLBACK(vpn_applet_disconnect_button_cb),
								  NULL);
	gtk_builder_connect_signals(applet->details_xml, applet);

	gtk_dialog_set_default_response(GTK_DIALOG(dialog),
									GTK_RESPONSE_CLOSE);

	gtk_widget_show_all(dialog);

	/* Focus the last page looked at */
	gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook),
								  applet->last_details_page);

	vpn_applet_update_details_dialog(applet, applet->last_details_page);

	vpn_applet_run_dialog(applet, GTK_DIALOG(dialog));

	/* Remember which page was last looked at */
	page_num = gtk_notebook_get_current_page(GTK_NOTEBOOK(notebook));
	if (page_num != applet->last_details_page)
	{
		applet->last_details_page = page_num;
		vpn_applet_update_preferences(applet);
	}

	gtk_widget_destroy(dialog);

	applet->details_xml = NULL;
}

void vpn_applet_quit(GtkMenuItem *menuitem,
					 gpointer user_data)
{
	gtk_main_quit();
}

void vpn_applet_init_popup_menu(VPNApplet *applet)
{
	int i;
	GtkWidget *details_item, *quit_item, *separator;
	VPNConfig *config;

	applet->menu = gtk_menu_new();

	applet->count_item = gtk_menu_item_new_with_label(_("OpenVPN: 0 connections active"));
	gtk_widget_set_sensitive(GTK_WIDGET(applet->count_item), FALSE);
	gtk_menu_shell_append(GTK_MENU_SHELL(applet->menu), applet->count_item);
	gtk_widget_show(applet->count_item);

	separator = gtk_separator_menu_item_new();
	gtk_menu_shell_append(GTK_MENU_SHELL(applet->menu), separator);
	gtk_widget_show(separator);

	for (i=0, config=applet->configs; i<applet->configs_count; i++, config++) {
		gtk_menu_shell_append(GTK_MENU_SHELL(applet->menu),
							  config->menuitem);
		gtk_widget_show(config->menuitem);
	}

	separator = gtk_separator_menu_item_new();
	gtk_menu_shell_append(GTK_MENU_SHELL(applet->menu), separator);
	gtk_widget_show(separator);

	details_item = gtk_menu_item_new_with_label(_("Details..."));

	g_signal_connect(details_item, "activate",
					 G_CALLBACK(vpn_applet_details), applet);
	gtk_widget_show(details_item);

	quit_item = gtk_menu_item_new_with_label(_("Quit"));

	g_signal_connect(quit_item, "activate",
					 G_CALLBACK(vpn_applet_quit), NULL);
	gtk_widget_show(quit_item);

	gtk_menu_shell_append(GTK_MENU_SHELL(applet->menu),
						  details_item);
	gtk_menu_shell_append(GTK_MENU_SHELL(applet->menu),
						  quit_item);

	app_indicator_set_menu(applet->app_indicator, GTK_MENU (applet->menu));
}

void vpn_applet_init_configs(VPNApplet *applet)
{
	glob_t gl;
	int i;
	VPNConfig *config;

	glob("/etc/openvpn/*.conf", 0, NULL, &gl);
	glob("/etc/openvpn/*.ovpn", GLOB_APPEND, NULL, &gl);	

	applet->configs_count = gl.gl_pathc;

	applet->configs = g_new(VPNConfig, applet->configs_count);

	for (i=0, config=applet->configs; i<applet->configs_count; i++, config++)
		vpn_config_init(config,
						applet,
						gl.gl_pathv[i]);

	globfree(&gl);

	if (!applet->batchmode && !applet->configs_count)
	{
		vpn_applet_display_error(applet, _("No OpenVPN configuration files were found in %s"), CONFIG_PATH);
	}

	if (!applet->batchmode && !g_file_test(OPENVPN_BINARY_PATH, G_FILE_TEST_IS_REGULAR))
	{
		vpn_applet_display_error(applet, _("Could not find openvpn binary at %s.  Make sure OpenVPN is installed."), OPENVPN_BINARY_PATH);
	}

	/* Build a hash table for quick access to configurations
	   by name */
	applet->configs_table = g_hash_table_new(g_str_hash,
											 g_str_equal);
	for (i=0, config=applet->configs; i<applet->configs_count; i++, config++)
	{
		g_hash_table_insert(applet->configs_table,
							config->name,
							config);
	}

}

void vpn_applet_reconnect_to_mgmt(VPNApplet *applet)
{
	struct stat st;
	int i;
	VPNConfig *conf;
	int port;
	char *procdir;

	if (!applet->configs)
		return;
	for (i=0, conf = applet->configs ; i<applet->configs_count; i++, conf++)
	{
		port = ntohs(conf->sockaddr.sin_port);
		procdir = NULL;

		if (conf->pid
		 && port
		 && (procdir = g_strdup_printf("/proc/%d", conf->pid)) != NULL
		 && stat(procdir, &st) == 0)
		{
			conf->sockaddr.sin_family      = AF_INET;
			conf->sockaddr.sin_addr.s_addr = INADDR_ANY;
			conf->sockaddr.sin_port        = htons(port);
			conf->retry                    = MAX_RETRY - 1;
			if (vpn_config_try_connect(conf) == 0)
			{
				if (!applet->batchmode)
				{
					set_menuitem_label(conf->menuitem, _("Disconnect %s"), conf->name);
					vpn_applet_update_count_and_icon(conf->applet);
				}
				syslog(LOG_NOTICE, "vpn_applet_reconnect_to_mgmt: connection \"%s\" state = RECONNECTING", conf->name);
				conf->state = RECONNECTING;
			}
		}
		if (procdir)
			g_free(procdir);
		if (conf->state == INACTIVE && conf->auto_connect)
			vpn_config_start(conf);
	}
}

void vpn_applet_init_status_icon(VPNApplet *applet)
{
	applet->app_indicator = app_indicator_new ("net.openvpn.gui.gopenvpn", "indicator-messages",
										  APP_INDICATOR_CATEGORY_APPLICATION_STATUS);

	app_indicator_set_status (applet->app_indicator, APP_INDICATOR_STATUS_ACTIVE);
	app_indicator_set_icon_theme_path(applet->app_indicator, PIXMAPS_DIR);
	app_indicator_set_icon_full(applet->app_indicator, "gopenvpn-closed", "Disconnected");
}

void vpn_applet_destroy(VPNApplet *applet)
{
	int i;
	VPNConfig *config;

	if (applet->configs)
	{
		for (i=0, config=applet->configs; i<applet->configs_count; i++, config++)
		{
			vpn_config_stop(config);
			vpn_config_free(config);
		}
		g_free(applet->configs);
	}

	if (applet->batchmode)
		return;

	if (applet->app_indicator)
		g_object_unref(applet->app_indicator);

	if (applet->menu)
		gtk_widget_destroy(applet->menu);

	if (applet->open_image)
		g_free(applet->open_image);
	if (applet->closed_image)
		g_free(applet->closed_image);
	if (applet->connecting_image)
		g_free(applet->connecting_image);

	if (applet->preferences)
		g_key_file_free(applet->preferences);

	g_free(applet);
}

void signal_handler(int signum)
{
	vpn_applet_destroy(g_applet);
	exit(-1);
}

void init_resource(VPNApplet *applet,
				   char **path,
				   const char *directory,
				   const char *filename)
{
	*path = g_build_filename(directory, filename, NULL);
	if (!*path || !g_file_test(*path, G_FILE_TEST_IS_REGULAR))
	{
		vpn_applet_display_error(applet, _("gopenvpn could not find some required resources: file %s was not found."),
								 filename);
		exit(-1);
	}
}

void vpn_applet_init_batchmode(VPNApplet *applet)
{
	char *s;
	struct passwd *p;

	/* Set the applet's uid and gid to the user & group that invoked sudo.
	 */
	if ((s  = getenv("SUDO_UID")) != NULL)
	{
		applet->uid = atoi(s);
		if ((p = getpwuid(applet->uid)) != NULL)
			applet->homedir = g_strdup(p->pw_dir);
	}
	else
		applet->uid = 0;
	if ((s  = getenv("SUDO_GID")) != NULL)
		applet->gid = atoi(s);
	else
		applet->gid = 0;
}

void vpn_applet_init_resources(VPNApplet *applet)
{
	init_resource(applet,
				  &applet->auth_dialog_ui,
				  GTKBUILDER_DIR,
				  "auth_dialog.ui");
	init_resource(applet,
				  &applet->passphrase_dialog_ui,
				  GTKBUILDER_DIR,
				  "passphrase_dialog.ui");
	init_resource(applet,
				  &applet->details_dialog_ui,
				  GTKBUILDER_DIR,
				  "details_dialog.ui");
	if (applet->batchmode)
		return;
	init_resource(applet,
				  &applet->open_image,
				  PIXMAPS_DIR,
				  OPEN_IMAGE);
	init_resource(applet,
				  &applet->closed_image,
				  PIXMAPS_DIR,
				  CLOSED_IMAGE);
	init_resource(applet,
				  &applet->connecting_image,
				  PIXMAPS_DIR,
				  CONNECTING_IMAGE);
}

char *get_preferences_path(VPNApplet *applet)
{
	return g_build_filename(applet->batchmode ? applet->homedir : getenv("HOME"), ".gopenvpn", NULL);
}

char *get_state_path(VPNApplet *applet)
{
	return g_build_filename(applet->batchmode ? applet->homedir : getenv("HOME"), ".gopenvpn.state", NULL);
}

void vpn_applet_init_preferences(VPNApplet *applet)
{
	char *preferences_path = get_preferences_path(applet);
	char *str, *section;
	int i;
	VPNConfig *conf;

	applet->preferences = g_key_file_new();

	g_key_file_load_from_file(applet->preferences,
							  preferences_path,
							  0,
							  NULL);

	for (i=0, conf=applet->configs ; i<applet->configs_count; i++, conf++)
	{
		if ((section = g_strdup_printf(CONNSECTIONFMT, conf->name)) != NULL
		 && g_key_file_get_boolean(applet->preferences, section, "AutoConnect", NULL))
			conf->auto_connect = TRUE;
		if (section)
			g_free(section);
	}

	str = g_key_file_get_string(applet->preferences,
								"Preferences",
								"CurrentConfiguration",
								NULL);

	if (str)
	{
		VPNConfig *config = vpn_config_find(applet, str);
		if (config)
			applet->last_details_page = config - applet->configs;
		g_free(str);
	}

	g_free(preferences_path);
}

void vpn_applet_init_state(VPNApplet *applet)
{
	char *state_path = get_state_path(applet);
	char *section;
	int i;
	VPNConfig *conf;

	applet->state = g_key_file_new();

	g_key_file_load_from_file(applet->preferences,
							  state_path,
							  0,
							  NULL);

	for (i=0, conf=applet->configs ; i<applet->configs_count; i++, conf++)
	{
		if ((section = g_strdup_printf(CONNSECTIONFMT, conf->name)) != NULL)
		{
			conf->sockaddr.sin_port = htons(g_key_file_get_integer(applet->preferences, section, "Port", NULL));
			conf->pid = g_key_file_get_integer(applet->preferences, section, "Pid", NULL);
		}
		if (section)
			g_free(section);
	}
	g_free(state_path);
}

void vpn_applet_update_preferences(VPNApplet *applet)
{
	VPNConfig *config;
	char *data, *section;
	char *preferences_path = get_preferences_path(applet);
	int i;

	config = vpn_config_get(applet, applet->last_details_page);

	g_key_file_set_string(applet->preferences,
						  "Preferences",
						  "CurrentConfiguration",
						  config ? config->name : "");

	for (i=0, config=applet->configs ; i<applet->configs_count; i++, config++)
	{
		if ((section = g_strdup_printf(CONNSECTIONFMT, config->name)) != NULL)
		{
			g_key_file_set_boolean(applet->preferences, section, "AutoConnect", config->auto_connect);
		}
		if (section)
			g_free(section);
	}

	data = g_key_file_to_data(applet->preferences,
							  NULL,
							  NULL);

	if (data)
	{
		FILE *fp = g_fopen(preferences_path, "w");
		fputs(data, fp);
		fclose(fp);

		g_free(data);
	}
	if (applet->batchmode) {
		if (chown(preferences_path, applet->uid, applet->gid) == -1) {
			perror("chown");
		}
	}

	g_free(preferences_path);
}

void vpn_applet_update_state(VPNApplet *applet)
{
	int i;
	char *data, *section;
	char *state_path = get_state_path(applet);
	VPNConfig *conf;

	for (i=0, conf=applet->configs ; i<applet->configs_count; i++, conf++)
	{
		if ((section = g_strdup_printf(CONNSECTIONFMT, conf->name)) != NULL)
		{
			g_key_file_set_integer(applet->state, section, "Port", ntohs(conf->sockaddr.sin_port));
			g_key_file_set_integer(applet->state, section, "Pid", conf->pid);
		}
		if (section)
			g_free(section);
	}

	data = g_key_file_to_data(applet->state,
							  NULL,
							  NULL);

	if (data)
	{
		FILE *fp = g_fopen(state_path, "w");
		fputs(data, fp);
		fclose(fp);

		g_free(data);
	}
	if (applet->batchmode) {
		if (chown(state_path, applet->uid, applet->gid) == -1) {
			perror("chown");
		}
	}

	g_free(state_path);
}

void vpn_applet_init_signals(VPNApplet *applet)
{
	signal(SIGTERM, signal_handler);
	signal(SIGINT, signal_handler);
	signal(SIGHUP, signal_handler);	
}

void vpn_applet_init(VPNApplet *applet)
{
	if (getenv("SUDO_COMMAND"))
	{
		syslog(LOG_INFO, "vpn_applet_init: batch mode enabled");
		applet->batchmode = TRUE;
	}

	vpn_applet_init_signals(applet);
	vpn_applet_init_resources(applet);
	if (!applet->batchmode)
		vpn_applet_init_status_icon(applet);
	vpn_applet_init_configs(applet);
	if (applet->batchmode)
		vpn_applet_init_batchmode(applet);
	vpn_applet_init_preferences(applet);
	if (applet->batchmode)
		all_auto_up(applet, TRUE);
	vpn_applet_init_state(applet);
	if (!applet->batchmode)
		vpn_applet_init_popup_menu(applet);
	vpn_applet_reconnect_to_mgmt(applet);
}

int main(int argc, char *argv[])
{
	openlog("gopenvpn", LOG_PID, LOG_DAEMON);
	syslog(LOG_INFO, "starting");
	setlocale(LC_ALL, "");
	bindtextdomain(PACKAGE, LOCALEDIR);
	bind_textdomain_codeset(PACKAGE, "UTF-8");
	textdomain(PACKAGE);

	gtk_init_check(&argc, &argv);
	g_applet = vpn_applet_new();
	vpn_applet_init(g_applet);
	gtk_main();
	if (!g_applet->batchmode)
		vpn_applet_destroy(g_applet);

	return 0;
}

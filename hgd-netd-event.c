#include <stdlib.h>

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include "config.h"
#ifdef HAVE_PYTHON
#undef _POSIX_C_SOURCE /* crappy hack for debian python */
#include <Python.h> /* defines _GNU_SOURCE comes before stdio.h */
#include "py.h"
#else
#define _GNU_SOURCE
#endif

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_LIBCONFIG
#include "cfg.h"
#endif
#include "user.h"
#include "db.h"
#include "hgd.h"
#include "mplayer.h"
#include "net.h"
#include <openssl/ssl.h>
#ifdef HAVE_TAGLIB
#include <tag_c.h>
#endif

#define PORT_NO (6633)



struct netd_settings {
	int		 crypto_pref;
	int		 req_votes;
	sqlite3		*db;
};

struct netd_settings settings = {HGD_CRYPTO_PREF_IF_POSS, 2, NULL};

const char			*hgd_component = HGD_COMPONENT_HGD_NETD;

void
hgd_exit_nicely()
{
	DPRINTF(HGD_D_ERROR, "TODO:");
}

static void DPRINTF_cb(int severity, const char *msg)
{
	int s;
	switch (severity) {
		case _EVENT_LOG_DEBUG: s = HGD_D_DEBUG; break;
		case _EVENT_LOG_MSG:   s = HGD_D_INFO;   break;
		case _EVENT_LOG_WARN:  s = HGD_D_WARN;  break;
		case _EVENT_LOG_ERR:   s = HGD_D_ERROR; break;
		default:               s = -1;     break; /* never reached */
	}
	DPRINTF(s, "%s", msg);
}

/*
 * user|perms|has_vote?
 *
 * authentication has already been checked here
 */
	int
hgd_cmd_id(con_t *con, char **args)
{
	int			 vote = -1;
	char			*resp = NULL;

	if (hgd_user_has_voted(settings.db, con->user->name, &vote) != HGD_OK) {
		DPRINTF(HGD_D_WARN, "problem determining if voted: %s",
				con->user->name);
		return (HGD_FAIL);
	}

	xasprintf(&resp, "ok|%s|%u|%d", con->user->name, con->user->perms, vote);

	evbuffer_add_printf(con->out,  "%s", resp);

	free(resp);

	return (HGD_OK);
}

/*
 * respond to client what is currently playing.
 *
 * response:
 * ok|0				nothing playing
 * ok|1|id|filename|user	track is playing
 * err|...			failure
 */
int
hgd_cmd_now_playing(con_t *con, char **args)
{
	struct hgd_playlist_item	 playing;
	char				*reply;
	int				 num_votes;
	int				 voted;

	(void) args; /* silence compiler */

	memset(&playing, 0, sizeof(playing));
	if (hgd_get_playing_item(settings.db, &playing) == HGD_FAIL) {
		evbuffer_add_printf(con->out, "err|" HGD_RESP_E_INT);
		hgd_free_playlist_item(&playing);
		return (HGD_FAIL);
	}

	if (playing.filename == NULL) {
		evbuffer_add_printf(con->out, "ok|0");
	} else {
		if ((hgd_get_num_votes(settings.db, &num_votes)) != HGD_OK) {
			DPRINTF(HGD_D_ERROR, "can't get votes");
			evbuffer_add_printf(con->out, "err|" HGD_RESP_E_INT);
			return (HGD_FAIL);
		}

		if (con->user != NULL) {
			if (hgd_user_has_voted( settings.db,
			    con->user->name, &voted) != HGD_OK) {
				DPRINTF(HGD_D_WARN, "cant decide if voted: %s",
				    con->user->name);
				evbuffer_add_printf(con->out, "err|" HGD_RESP_E_INT);
				return (HGD_FAIL);
			}
		} else
			voted = -1;

		xasprintf(&reply, "ok|1|%d|%s|%s|%s|%s|"
		    "%s|%s|%d|%d|%d|%d|%d|%d|%d", /* added in 0.5 */
		    playing.id, playing.filename + strlen(HGD_UNIQ_FILE_PFX),
		    playing.tags.artist, playing.tags.title, playing.user,
		    playing.tags.album, playing.tags.genre,
		    playing.tags.duration, playing.tags.bitrate,
		    playing.tags.samplerate, playing.tags.channels,
		    playing.tags.year, (settings.req_votes - num_votes),
		    voted);
		evbuffer_add_printf(con->out, "%s", reply);

		free(reply);
	}

	hgd_free_playlist_item(&playing);

	return (HGD_OK);
}

int
hgd_cmd_proto(con_t *con, char **unused)
{
	char			*reply;

	(void) unused;

	xasprintf(&reply, "ok|%d|%d", HGD_PROTO_VERSION_MAJOR,
	    HGD_PROTO_VERSION_MINOR);
	evbuffer_add_printf(con->out, "%s", reply);
	free(reply);

	return (HGD_OK);
}

/*
 * report back items in the playlist
 */
int
hgd_cmd_playlist(con_t *con, char **args)
{
	char			*resp;
	struct hgd_playlist	 list;
	int			 i, num_votes;
	int			 voted = 0;

	(void) args;

	if (hgd_get_playlist(settings.db, &list) == HGD_FAIL) {
		evbuffer_add_printf(con->out, "err|" HGD_RESP_E_INT);
		return (HGD_FAIL);
	}

	/* and respond to client */
	xasprintf(&resp, "ok|%d", list.n_items);
	evbuffer_add_printf(con->out, "%s", resp);
	free(resp);

	if ((hgd_get_num_votes(settings.db, &num_votes)) != HGD_OK) {
		DPRINTF(HGD_D_ERROR, "can't get votes");
		evbuffer_add_printf(con->out, "err|" HGD_RESP_E_INT);
		return (HGD_FAIL);
	}

	if (con->user != NULL) {
		if (hgd_user_has_voted(settings.db, con->user->name, &voted) != HGD_OK) {
			DPRINTF(HGD_D_WARN, "problem determining if voted: %s",
			    con->user->name);
			evbuffer_add_printf(con->out, "err|" HGD_RESP_E_INT);
			return (HGD_FAIL);
		}
	}
	else {
		voted = -1;
	}

	for (i = 0; i < list.n_items; i++) {
		xasprintf(&resp, "%d|%s|%s|%s|%s|%s|%s|%d|%d|%d|%d|%d|%d|%d",
		    list.items[i]->id,
		    list.items[i]->filename + strlen(HGD_UNIQ_FILE_PFX),
		    list.items[i]->tags.artist,
		    list.items[i]->tags.title,
		    list.items[i]->user,
		    list.items[i]->tags.album,
		    list.items[i]->tags.genre,
		    list.items[i]->tags.duration,
		    list.items[i]->tags.bitrate,
		    list.items[i]->tags.samplerate,
		    list.items[i]->tags.channels,
		    list.items[i]->tags.year,
		    (i == 0 ? (settings.req_votes - num_votes) : settings.req_votes),
		    (i == 0 ? voted : 0)
		);
		evbuffer_add_printf(con->out,"%s", resp);
		DPRINTF(HGD_D_DEBUG, "%s\n", resp);
		free(resp);
	}

	hgd_free_playlist(&list);

	return (HGD_OK);
}


/* lookup table for command handlers */
struct hgd_cmd_despatch_event	cmd_despatches[] = {
	/* cmd,		n_args,	secure,	auth,	auth_lvl,	handler_function */
	/* bye is special */
	{"bye",		0,	0,	0,	HGD_AUTH_NONE,	NULL},
	{"id",		0,	0,	1,	HGD_AUTH_NONE,	NULL},
	{"ls",		0,	1,	0,	HGD_AUTH_NONE,	hgd_cmd_playlist},
	{"pl",		0,	1,	0,	HGD_AUTH_NONE,	hgd_cmd_playlist},
	{"np",		0,	1,	0,	HGD_AUTH_NONE,	hgd_cmd_now_playing},
	{"proto",	0,	0,	0,	HGD_AUTH_NONE,	hgd_cmd_proto},

	{NULL,		0,	0,	0,	HGD_AUTH_NONE,	hgd_cmd_id}	/* terminate */
};

/* enusure atleast 1 more than the commamd with the most args */
	uint8_t
hgd_parse_line_event(con_t *con, char *line)
{
	char			*tokens[HGD_MAX_PROTO_TOKS];
	char			*next = line;
	uint8_t			n_toks = 0;
	struct hgd_cmd_despatch_event *desp, *correct_desp;
	uint8_t			bye = 0;

	DPRINTF(HGD_D_DEBUG, "Parsing line: %s", line);
	if (line == NULL) return HGD_FAIL;

	/* tokenise */
	do {
		tokens[n_toks] = xstrdup(strsep(&next, "|"));
		DPRINTF(HGD_D_DEBUG, "tok %d: \"%s\"", n_toks, tokens[n_toks]);
	} while ((n_toks++ < HGD_MAX_PROTO_TOKS) && (next != NULL));

	DPRINTF(HGD_D_DEBUG, "Got %d tokens", n_toks);
	if ((n_toks == 0) || (strlen(tokens[0]) == 0)) {
		evbuffer_add_printf(con->out,
				"err|" HGD_RESP_E_INVCMD);
		con->num_bad_commands++;
		goto clean;
	}

	/* now we look up which function to call */
	correct_desp = NULL;
	for (desp = cmd_despatches; desp->cmd != NULL; desp ++) {

		if (strcmp(desp->cmd, tokens[0]) != 0)
			continue;

		if (n_toks - 1 != desp->n_args)
			continue;

		/* command is valid \o/ */
		correct_desp = desp;
		break;
	}

	/* command not found */
	if (correct_desp == NULL) {
		DPRINTF(HGD_D_DEBUG, "Despatching '%s' handler", tokens[0]);

		DPRINTF(HGD_D_INFO, "Invalid command");
		evbuffer_add_printf(con->out,  "err|" HGD_RESP_E_INVCMD);
		con->num_bad_commands++;

		goto clean;
	}

	/* bye has special meaning */
	if (strcmp(correct_desp->cmd, "bye") == 0) {
		bye = 1;
		goto clean;
	}

	/* if the server is *only* accepting SSL connections, a number
	 * of commands will be out of bounds until encryption is
	 * estabished.
	 */
	if ((settings.crypto_pref == HGD_CRYPTO_PREF_ALWAYS) &&
			(correct_desp->secure) &&
			(!con->is_ssl)) {
		DPRINTF(HGD_D_INFO, "Client '%s' is trying to bypass SSL",
				con->cli_str);
		evbuffer_add_printf(con->out, "err|" HGD_RESP_E_SSLREQ);
		con->num_bad_commands++;
		goto clean;
	}

	/* user should be authenticated for some comands */
	if (correct_desp->auth_needed && con->user == NULL) {
		DPRINTF(HGD_D_INFO, "User not authenticated to use '%s'",
				correct_desp->cmd);
		evbuffer_add_printf(con->out,  "err|" HGD_RESP_E_DENY);
		con->num_bad_commands++;
		goto clean;
	}

	/* if admin command, check user is an admin */
	if (correct_desp->authlevel != HGD_AUTH_NONE) {
		DPRINTF(HGD_D_DEBUG, "Checking authlevel..."
				"expecting %d, got %d",
				correct_desp->authlevel, con->user->perms);
		if (!(con->user->perms & correct_desp->authlevel)) {
			DPRINTF(HGD_D_INFO,
					"'%s': unauthorised use of admin command",
					con->cli_str);
			evbuffer_add_printf(con->out, "err|" HGD_RESP_E_DENY);

			con->num_bad_commands++;
			goto clean;
		}
	}

	/* otherwise despatch */
	if (correct_desp->handler(con, &tokens[1]) != HGD_OK) {
		/*
		 * This happens often, ie when a client tries to
		 * vote off twice, and that is fine, so we put the message
		 * in INFO rather than WARN.
		 */
		DPRINTF(HGD_D_INFO, "despatch of '%s' for '%s' returned -1",
				tokens[0], "");
		con->num_bad_commands++;
	} else
		con->num_bad_commands = 0;

clean:
	/* free tokens */
	for (; n_toks > 0; )
		free(tokens[--n_toks]);

	return (bye);
}

int create_ss() {
	int sd;
	struct sockaddr_in addr;
	int sockopt = 1;


	// Create server socket
	if( (sd = socket(PF_INET, SOCK_STREAM, 0)) < 0 )
	{
		perror("socket error");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT_NO);
	addr.sin_addr.s_addr = INADDR_ANY;

	// Bind socket to address
	if (bind(sd, (struct sockaddr*) &addr, sizeof(addr)) != 0)
	{
		perror("bind error");
	}

	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR,
				&sockopt, sizeof(sockopt)) < 0) {
		perror("SO_RESUSEADDR error");

		//DPRINTF(HGD_D_WARN, "Can't set SO_REUSEADDR");
	}

	// Start listing on the socket
	if (listen(sd, 2) < 0)
	{
		perror("listen error");
		return -1;
	}
	return sd;

}

void read_callback(struct bufferevent *bev, void *ctx)
{
	con_t *con = (con_t*) ctx;
	char * line;

	bufferevent_read_buffer(bev, con->in);
	line = evbuffer_readln(con->in, NULL, EVBUFFER_EOL_CRLF);

	DPRINTF(HGD_D_DEBUG, "got line [%s]", line);

	hgd_parse_line_event(con, line);
	free(line);

	bufferevent_write_buffer(bev, con->out);

}

void write_callback(struct bufferevent *bev, void *ctx)
{
	DPRINTF(HGD_D_DEBUG, "write callback");
	con_t *con = (con_t*) ctx;
	bufferevent_write_buffer(bev, con->out);
}


void cb(struct bufferevent *bev, short events, void *ptr)
{
	puts("TODO:\n");
}

void accept_cb_func(evutil_socket_t fd, short what, void *arg)
{
	struct event_base *eb = (struct event_base*) arg;
	struct bufferevent *bev;

	con_t *con = calloc(1, sizeof(con_t));

	printf("Got an event on socket %d:%s%s%s []\n",
			(int) fd,
			/*(what&EV_TIMEOUT) ? " timeout" : "",*/
			(what&EV_READ)    ? " read" : "",
			(what&EV_WRITE)   ? " write" : "",
			(what&EV_SIGNAL)  ? " signal" : ""
	      );

	struct sockaddr_in client_addr;
	socklen_t client_len = sizeof(client_addr);
	int client_sd;

	// Accept client request
	client_sd = accept(fd, (struct sockaddr *)&client_addr, &client_len);

	if (client_sd < 0)
	{
		perror("accept error");
		return;
	}

	con->out = evbuffer_new();
	con->in = evbuffer_new();

	bev = bufferevent_socket_new(eb, client_sd, 0);
	bufferevent_setcb(bev,read_callback, write_callback, cb, con);

	evbuffer_add_printf(con->out, "ok|" HGD_RESP_O_GREET "\r\n");


	bufferevent_enable(bev, EV_READ|EV_WRITE);
	/*	new_con_e = event_new(eb, client_sd, EV_TIMEOUT|EV_READ|EV_PERSIST, cb,
		eb);
		event_add(new_con_e, NULL);*/


	printf("Successfully connected with client.\n");

}

int main()
{
	struct event_base *eb;
	int running = 1;
	struct event *ev1;
	char *db_path;

	hgd_debug = 4;

	xasprintf(&db_path, "%s/%s", state_path, HGD_DB_NAME);
	settings.db = hgd_open_db(db_path, 0);
	if (settings.db == NULL)
		hgd_exit_nicely();

	event_enable_debug_mode();
	event_set_log_callback(DPRINTF_cb);
	eb = event_base_new();

	ev1 = event_new(eb, create_ss(), EV_TIMEOUT|EV_READ|EV_PERSIST, accept_cb_func,
			eb);

	event_add(ev1, NULL);

	while (running) {
		event_base_dispatch(eb);
		puts("Tick");
	}
}

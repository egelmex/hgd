/*
 * Copyright (c) 2011, Edd Barrett <vext01@gmail.com>
 * Copyright (c) 2011, Martin Ellis <ellism88@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* vim: set fdm=syntax */
#include <stdlib.h>

#include <event2/event.h>
#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <sysexits.h>

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

#define OUT(x...)					\
	do {						\
		evbuffer_add_printf(con->out, x);	\
		evbuffer_add_printf(con->out, "\r\n");	\
	} while (0)

typedef struct {
	char			*filestore_path;
	char			*state_path;

} path_t;

typedef struct {
	int			 num_configs;
	char			 *config_paths[4];
} libconfig_t;

struct ssl_settings {
	int			 ssl_capable;
	SSL_METHOD		*method;
	enum crypto_pref_e	 crypto_pref;
	SSL_CTX			*ctx;
};

struct netd_settings {
	int			 req_votes;
	int			 port;
	int			 flood_limit;
	long long		 max_upload_size;
	sqlite3			*db;
	struct event_base	*eb;
	char			*vote_sound;
	int			 daemonise;
	uint8_t			 lookup_client_dns;
	path_t			 paths;
	libconfig_t		 libconfig;
	struct ssl_settings	ssl;
};

struct netd_settings settings = {
	.port = 6633,
	.req_votes = 2,
	.flood_limit = 100,
	.max_upload_size = HGD_DFL_MAX_UPLOAD,
	.db = NULL,
	.eb = NULL,
	.vote_sound = NULL,
	.daemonise = 0,
	.lookup_client_dns = 0,
	.paths = {NULL, NULL},
	.libconfig = {0, {NULL, NULL, NULL, NULL}},
	.ssl = {0, NULL, if_poss, NULL}
};


const char			*hgd_component = HGD_COMPONENT_HGD_NETD;

int
hgd_get_tag_metadata(char *filename, struct hgd_media_tag *meta)
{
#ifdef HAVE_TAGLIB
	TagLib_File			*file;
	TagLib_Tag			*tag;
	const TagLib_AudioProperties	*ap;
#endif

	DPRINTF(HGD_D_DEBUG, "Attempting to read tags for '%s'", filename);

	meta->artist = xstrdup("");
	meta->title = xstrdup("");
	meta->album = xstrdup("");
	meta->genre = xstrdup("");
	meta->year = 0;
	meta->duration = 0;
	meta->samplerate = 0;
	meta->channels = 0;
	meta->bitrate = 0;

#ifdef HAVE_TAGLIB
	file = taglib_file_new(filename);
	if (file == NULL) {
		DPRINTF(HGD_D_DEBUG, "taglib could not open '%s'", filename);
		return (HGD_FAIL);
	}

	if (!taglib_file_is_valid(file)) {
		DPRINTF(HGD_D_WARN, "invalid tag in '%s'", filename);
		return (HGD_FAIL);
	}

	tag = taglib_file_tag(file);
	if (tag == NULL) {
		DPRINTF(HGD_D_WARN, "failed to get tag of '%s'", filename);
		return (HGD_FAIL);
	}

	free(meta->artist);
	free(meta->title);
	free(meta->album);
	free(meta->genre);

	meta->artist = xstrdup(taglib_tag_artist(tag));
	meta->title = xstrdup(taglib_tag_title(tag));
	meta->album = xstrdup(taglib_tag_album(tag));
	meta->genre = xstrdup(taglib_tag_genre(tag));

	meta->year = taglib_tag_year(tag);

	/* now audio properties: i dont consider this failing fatal */
	ap = taglib_file_audioproperties(file);
	if (ap != NULL) {
		meta->duration = taglib_audioproperties_length(ap);
		meta->samplerate = taglib_audioproperties_samplerate(ap);
		meta->channels = taglib_audioproperties_channels(ap);
		meta->bitrate = taglib_audioproperties_bitrate(ap);
	} else {
		DPRINTF(HGD_D_WARN,
		    "failed to get audio properties: %s", filename);
	}

	DPRINTF(HGD_D_INFO,
	    "Got tag from '%s': '%s' by '%s' from the album '%s' from the year"
	    "'%u' of genre '%s' [%d secs, %d chans, %d Hz, %d bps]\n",
	    filename, meta->title, meta->artist, meta->album, meta->year,
	    meta->genre, meta->duration, meta->channels, meta->samplerate,
	    meta->bitrate);
	taglib_file_free(file);
	taglib_tag_free_strings();
#else
	DPRINTF(HGD_D_DEBUG, "No taglib support, skipping tag retrieval");
#endif

	return (HGD_OK);
}


void
hgd_exit_nicely()
{
	DPRINTF(HGD_D_ERROR, "TODO:");
}

void cb(struct bufferevent *bev, short events, void *ptr)
{
	puts("TODO:\n");
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

	OUT("%s\r\n", resp);

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
		OUT( "err|" HGD_RESP_E_INT "\r\n");
		hgd_free_playlist_item(&playing);
		return (HGD_FAIL);
	}

	if (playing.filename == NULL) {
		OUT( "ok|0");
	} else {
		if ((hgd_get_num_votes(settings.db, &num_votes)) != HGD_OK) {
			DPRINTF(HGD_D_ERROR, "can't get votes");
			OUT( "err|" HGD_RESP_E_INT);
			return (HGD_FAIL);
		}

		if (con->user != NULL) {
			if (hgd_user_has_voted( settings.db,
			    con->user->name, &voted) != HGD_OK) {
				DPRINTF(HGD_D_WARN, "cant decide if voted: %s",
				    con->user->name);
				OUT( "err|" HGD_RESP_E_INT);
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
		OUT( "%s", reply);

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
	OUT( "%s", reply);
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
		OUT( "err|" HGD_RESP_E_INT);
		return (HGD_FAIL);
	}

	/* and respond to client */
	xasprintf(&resp, "ok|%d", list.n_items);
	OUT( "%s", resp);
	free(resp);

	if ((hgd_get_num_votes(settings.db, &num_votes)) != HGD_OK) {
		DPRINTF(HGD_D_ERROR, "can't get votes");
		OUT( "err|" HGD_RESP_E_INT);
		return (HGD_FAIL);
	}

	if (con->user != NULL) {
		if (hgd_user_has_voted(settings.db, con->user->name, &voted) != HGD_OK) {
			DPRINTF(HGD_D_WARN, "problem determining if voted: %s",
			    con->user->name);
			OUT( "err|" HGD_RESP_E_INT);
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
		OUT("%s", resp);
		DPRINTF(HGD_D_DEBUG, "%s\n", resp);
		free(resp);
	}

	hgd_free_playlist(&list);

	return (HGD_OK);
}

int
hgd_cmd_user_list(con_t *con, char **args)
{
	struct hgd_user_list	*list;
	int			 i, ret = HGD_FAIL;
	char			*msg, *msg1 = NULL;

	/* TODO: look at NULL */
	if (hgd_user_list(settings.db, NULL, &list) != HGD_OK) {
		OUT( "err|" HGD_RESP_E_INT);
		goto clean;
	}

	xasprintf(&msg, "ok|%d", list->n_users);
	OUT( "%s", msg);
	free(msg);

	for (i = 0; i < list->n_users; i++) {
		xasprintf(&msg1, "%s|%d",
		    list->users[i]->name, list->users[i]->perms);
		OUT( "%s", msg1);
		free(msg1);
	}

	ret = HGD_OK;
clean:
	if (list != NULL) {
		hgd_free_user_list(list);
		free(list);
	}

	return (ret);
}

int
hgd_cmd_pause(con_t *con, char **unused)
{
	int ret;

	(void) unused;

	ret = hgd_pause_track(settings.paths.state_path);

	if (ret == HGD_OK)
		OUT( "ok");
	else if (ret == HGD_FAIL_NOPLAY)
		OUT( "err|" HGD_RESP_E_NOPLAY);
	else
		OUT( "err|" HGD_RESP_E_DENY);

	return (ret);
}

int
hgd_cmd_skip(con_t *con, char **unused)
{
	int			ret;

	(void) unused;

	ret = hgd_skip_track(settings.paths.state_path);

	switch (ret) {
	case HGD_FAIL_NOPLAY:
		OUT( "err|" HGD_RESP_E_NOPLAY);
		break;
	case HGD_OK:
		OUT( "ok");
		break;
	default:
		OUT( "err|" HGD_RESP_E_INT);
		break;
	};

	return (ret);
}

int
hgd_cmd_user_mkadmin(con_t *con, char **args)
{
	int		ret = HGD_FAIL;

	switch(hgd_user_mod_perms(settings.db, NULL, args[0], HGD_AUTH_ADMIN, 1)) {
	case HGD_OK:
		OUT( "ok");
		ret = HGD_OK;
		break;
	case HGD_FAIL_USRNOEXIST:
		    OUT( "err|" HGD_RESP_E_USRNOEXIST);
		break;
	case HGD_FAIL_PERMNOCHG:
		OUT( "err|" HGD_RESP_E_PERMNOCHG);
		break;
	default:
		OUT( "err|" HGD_RESP_E_INT);
	};

	return (ret);
}

int
hgd_cmd_user_noadmin(con_t *con, char **args)
{
	int		ret = HGD_FAIL;

	/*TODO: look at NULL pararm */
	switch(hgd_user_mod_perms(settings.db, NULL, args[0], HGD_AUTH_ADMIN, 0)) {
	case HGD_OK:
		OUT( "ok");
		ret = HGD_OK;
		break;
	case HGD_FAIL_USRNOEXIST:
		    OUT( "err|" HGD_RESP_E_USRNOEXIST);
		break;
	case HGD_FAIL_PERMNOCHG:
		OUT( "err|" HGD_RESP_E_PERMNOCHG);
		break;
	default:
		OUT( "err|" HGD_RESP_E_INT);
	};

	return (ret);
}

/*
 * queue a track
 *
 * args: filename|size
 * reponses
 * ok...			ok and waiting for payload
 * ok				ok and payload accepted
 * err|...
 *
 * after 'ok...'
 * client then sends 'size' bytes of the media to queue
 */
int
hgd_cmd_queue(con_t *con, char **args)
{
	char			*filename_p = args[0];
	size_t			bytes = atoi(args[1]);
	int			ret = HGD_OK;
	binary_t		*binary_mode = NULL;
	char			*filename;

	binary_mode = calloc (1, sizeof(binary_t));

	if ((settings.flood_limit >= 0) &&
	    (hgd_num_tracks_user(settings.db, con->user->name) >= settings.flood_limit)) {

		DPRINTF(HGD_D_WARN,
		    "User '%s' trigger flood protection", con->user->name);
		OUT( "err|" HGD_RESP_E_FLOOD);

		return (HGD_FAIL);
	}

	/* strip path, we don't care about that */
	filename = basename(filename_p);

	if ((bytes == 0) || ((long long int) bytes > settings.max_upload_size)) {
		DPRINTF(HGD_D_WARN, "Incorrect file size");
		OUT( "err|" HGD_RESP_E_FLSIZE);
		ret = HGD_FAIL;
		goto clean;
	}

	/* prepare to recieve the media file and stash away */
	xasprintf(&binary_mode->filename, "%s/" HGD_UNIQ_FILE_PFX "%s",
	    settings.paths.filestore_path, filename);
	DPRINTF(HGD_D_DEBUG, "Template for filestore is '%s'",
	    binary_mode->filename);

	binary_mode->fd = mkstemps(binary_mode->filename, strlen(filename) + 1); /* +1 for hyphen */
	if (binary_mode->fd < 0) {
		DPRINTF(HGD_D_ERROR, "mkstemp: %s: %s",
		    settings.paths.filestore_path, SERROR);
		OUT( "err|" HGD_RESP_E_INT);
		ret = HGD_FAIL;
		goto clean;
	}

	OUT( "ok|...");

	DPRINTF(HGD_D_INFO, "Recving %d byte payload '%s' from %s into %s",
	    (int) bytes, filename, con->user->name, binary_mode->filename);

	binary_mode->bytes_left = bytes;
	con->binary_mode = binary_mode;


clean:
	return (ret);
}

int
binary_finished_cb(con_t *con)
{
	int ret = HGD_OK;
	struct hgd_media_tag	tags;
	binary_t *binary = con->binary_mode;
	//payload = NULL;

	/*
	 * get tag metadata
	 * no error that there is no #ifdef HAVE_TAGLIB
	 */
	hgd_get_tag_metadata(binary->filename, &tags);

	/* insert track into db */
	if (hgd_insert_track(settings.db, basename(binary->filename),
		    &tags, con->user->name) != HGD_OK) {
		OUT( "err|" HGD_RESP_E_INT);
		goto clean;
	}

	hgd_free_media_tags(&tags);

	OUT( "ok");
	DPRINTF(HGD_D_INFO, "Transfer of '%s' complete", binary->filename);
clean:
	return (ret);
}

/**
 * Identify yourself to the server
 *
 * args: username, pass
 */
int
hgd_cmd_user(con_t *con, char **args)
{
	struct hgd_user		*info;

	DPRINTF(HGD_D_INFO, "User on host '%s' authenticating as '%s'",
	    con->cli_str, args[0]);

	/* get salt */
	info = hgd_authenticate_user(settings.db, args[0], args[1]);
	if (info == NULL) {
		OUT( "err|" HGD_RESP_E_DENY);
		return (HGD_FAIL);
	}

	DPRINTF(HGD_D_INFO, "User '%s' successfully authenticated", args[0]);

	/* only if successful do we assign the info struct */
	con->user = info;
	OUT( "ok");

	return (HGD_OK);
}

int
hgd_cmd_vote_off(con_t *con, char **args)
{
	char				*ipc_path = NULL;
	char				*scmd, id_str[HGD_ID_STR_SZ], *read;
	FILE				*ipc_file;
	int				 open_ret, num_votes;
	int				 ret = HGD_FAIL;

	DPRINTF(HGD_D_INFO, "%s wants to skip track", con->user->name);

	/*
	 * Is the file they are voting off playing?
	 * We check this using the ipc file playd writes for us. This
	 * contains (if existent), the tid of the currently playing file.
	 *
	 * We use this file with locks to avoid race conditions.
	 */
	xasprintf(&ipc_path, "%s/%s", settings.paths.state_path, HGD_PLAYING_FILE);
	open_ret = hgd_file_open_and_lock(ipc_path, F_RDLCK, &ipc_file);
	switch (open_ret) {
		case HGD_OK:
			break; /* good */
		case HGD_FAIL_ENOENT:
			DPRINTF(HGD_D_WARN, "nothing playing to vote off");
			OUT( "err|" HGD_RESP_E_NOPLAY);
			goto clean;
			break;
		default:
			DPRINTF(HGD_D_ERROR, "failed to open ipc file");
			OUT( "err|" HGD_RESP_E_INT);
			goto clean;
			break;
	};

	/* Read the track id from the ipc file */
	read = fgets(id_str, HGD_ID_STR_SZ, ipc_file);
	hgd_file_unlock_and_close(ipc_file);
	if (read == NULL) {
		if (!feof(ipc_file)) {
			DPRINTF(HGD_D_WARN, "Can't find track id in ipc file");
			OUT( "err|" HGD_RESP_E_INT);
			goto clean;
		}
	}

	/* this check only happens for the "safe" varient for vo */
	if ((args != NULL) && (atoi(id_str) != atoi(args[0]))) {
		DPRINTF(HGD_D_INFO, "Track to voteoff isn't playing");
		OUT( "err|" HGD_RESP_E_WRTRK);
		goto clean;
	}

	/* insert vote */
	switch (hgd_insert_vote(settings.db, con->user->name)) {
	case HGD_OK:
		break; /* good */
	case HGD_FAIL_DUPVOTE:
		/* duplicate vote */
		DPRINTF(HGD_D_INFO, "User '%s' already voted",
		    con->user->name);
		OUT( "err|" HGD_RESP_E_DUPVOTE);
		return (HGD_OK);
		break;
	default:
		OUT( "err|" HGD_RESP_E_INT);
		return (HGD_FAIL);
	};

	/* play a sound on voting */
	if (settings.vote_sound != NULL) {
		DPRINTF(HGD_D_DEBUG, "Play voteoff sound: '%s'", settings.vote_sound);
		xasprintf(&scmd, "mplayer -really-quiet %s", settings.vote_sound);

		if (system(scmd) != 0) {
			/* unreachable as mplayer doesn't return non-zero :\ */
			DPRINTF(HGD_D_WARN,
			    "Vote-off noise failed to play: %s", settings.vote_sound);
		}

		free(scmd);
	}

	/* are we at the vote limit yet? */
	if ((hgd_get_num_votes(settings.db, &num_votes)) != HGD_OK) {
		OUT( "err|" HGD_RESP_E_INT);
		return (HGD_FAIL);
	}

	if (num_votes < settings.req_votes) {
		OUT( "ok");
		return (HGD_OK);
	}

	DPRINTF(HGD_D_INFO, "Vote limit exceeded - skip track");
	if (hgd_skip_track(settings.paths.state_path) != HGD_OK) {
		DPRINTF(HGD_D_ERROR, "Failed to skip track");
		OUT( "err|" HGD_RESP_E_INT);
		goto clean;
	}

	OUT( "ok");
	ret = HGD_OK;
clean:
	if (ipc_path)
		free(ipc_path);

	return (ret);
}

int
hgd_cmd_vote_off_noarg(con_t *con, char **unused)
{
	(void) unused;
	return (hgd_cmd_vote_off(con, NULL));
}

int
hgd_cmd_user_add(con_t *con, char **params)
{
	int			ret = HGD_FAIL;

	(void) con;

	/* TODO: hgd_user_add second param NULL */
	switch (hgd_user_add(settings.db, NULL, params[0], params[1])) {
	case HGD_OK:
		OUT( "ok");
		ret = HGD_OK;
		break;
	case HGD_FAIL_USREXIST:
		OUT( "err|" HGD_RESP_E_USREXIST);
		break;
	default:
		OUT( "err|" HGD_RESP_E_INT);
	}

	return (ret);
}

int
hgd_cmd_user_del(con_t *con, char **params)
{
	int			ret = HGD_FAIL;

	(void) con;

	switch (hgd_user_del(settings.db, params[0])) {
	case HGD_OK:
		OUT( "ok");
		ret = HGD_OK;
		break;
	case HGD_FAIL_USRNOEXIST:
		OUT( "err|" HGD_RESP_E_USRNOEXIST);
		break;
	default:
		OUT( "err|" HGD_RESP_E_INT);
	}

	return (ret);
}

int
hgd_cmd_encrypt_questionmark(con_t *con, char **unused)
{
	(void) unused;

	if ((settings.ssl.crypto_pref != never) && (settings.ssl.ssl_capable))
		OUT ("ok|tlsv1");
	else
		OUT ("ok|nocrypto");

	return (HGD_OK);
}

int
hgd_cmd_encrypt(con_t *con, char **unused)
{
	int			 ssl_err = 0, ret = -1;
	SSL			*ssl;
	(void) unused;

	if (con->is_ssl) {
		DPRINTF(HGD_D_WARN, "User tried to enable encyption twice");
		OUT ("err|" HGD_RESP_E_SSLAGN);
		return (HGD_FAIL);
	}

	if ((!settings.ssl.ssl_capable) || (settings.ssl.crypto_pref == never)) {
		DPRINTF(HGD_D_WARN, "User tried encrypt, when not possible");
		OUT("err|" HGD_RESP_E_SSLNOAVAIL);
		return (HGD_FAIL);
	}

	DPRINTF(HGD_D_DEBUG, "New SSL for session");
	ssl = SSL_new(settings.ssl.ctx);
	if (ssl == NULL) {
		PRINT_SSL_ERR(HGD_D_ERROR, "SSL_new");
		goto clean;
	}
	con->is_ssl = 1;
	bufferevent_openssl_filter_new(settings.eb, con->bev, ssl,
	    BUFFEREVENT_SSL_ACCEPTING, BEV_OPT_CLOSE_ON_FREE);

	ret = HGD_OK; /* all is well */
clean:

	if (ret == HGD_FAIL) {
		DPRINTF(HGD_D_INFO, "SSL connection failed");
		hgd_exit_nicely(); /* be paranoid and kick client */
	} else {
		DPRINTF(HGD_D_INFO, "SSL connection established");
		OUT("ok");
	}

	return (ret);
}

/* lookup table for command handlers */
struct hgd_cmd_despatch_event	cmd_despatches[] = {
	/* cmd,		n_args,	secure,	auth,	auth_lvl,	handler_function */
	/* bye is special */
	{"bye",		0,	0,	0,	HGD_AUTH_NONE,	NULL},
	{"id",		0,	0,	1,	HGD_AUTH_NONE,	NULL},
	{"encrypt",	0,	0,	0,	HGD_AUTH_NONE,	hgd_cmd_encrypt},
	{"encrypt?",	0,	0,	0,	HGD_AUTH_NONE,	hgd_cmd_encrypt_questionmark},
	{"ls",		0,	1,	0,	HGD_AUTH_NONE,	hgd_cmd_playlist},
	{"pl",		0,	1,	0,	HGD_AUTH_NONE,	hgd_cmd_playlist},
	{"np",		0,	1,	0,	HGD_AUTH_NONE,	hgd_cmd_now_playing},
	{"proto",	0,	0,	0,	HGD_AUTH_NONE,	hgd_cmd_proto},
	{"q",		2,	1,	1,	HGD_AUTH_NONE,	hgd_cmd_queue},
	{"user",	2,	1,	0,	HGD_AUTH_NONE,	hgd_cmd_user},
	{"vo",		0,	1,	1,	HGD_AUTH_NONE,	hgd_cmd_vote_off_noarg},
	{"vo",		1,	1,	1,	HGD_AUTH_NONE,	hgd_cmd_vote_off},
	{"user-add",	2,	1,	1,	HGD_AUTH_ADMIN, hgd_cmd_user_add},
	{"user-del",	1,	1,	1,	HGD_AUTH_ADMIN, hgd_cmd_user_del},
	{"user-list",	0,	1,	1,	HGD_AUTH_ADMIN, hgd_cmd_user_list},
	{"user-mkadmin",1,	1,	1,	HGD_AUTH_ADMIN,	hgd_cmd_user_mkadmin},
	{"user-noadmin",1,	1,	1,	HGD_AUTH_ADMIN,	hgd_cmd_user_noadmin},
	{"pause",	0,	1,	1,	HGD_AUTH_ADMIN,	hgd_cmd_pause},
	{"skip",	0,	1,	1,	HGD_AUTH_ADMIN, hgd_cmd_skip},
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
		OUT(
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
		OUT(  "err|" HGD_RESP_E_INVCMD);
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
	if ((settings.ssl.crypto_pref == always) &&
			(correct_desp->secure) &&
			(!con->is_ssl)) {
		DPRINTF(HGD_D_INFO, "Client '%s' is trying to bypass SSL",
				con->cli_str);
		OUT( "err|" HGD_RESP_E_SSLREQ);
		con->num_bad_commands++;
		goto clean;
	}

	/* user should be authenticated for some comands */
	if (correct_desp->auth_needed && con->user == NULL) {
		DPRINTF(HGD_D_INFO, "User not authenticated to use '%s'",
				correct_desp->cmd);
		OUT(  "err|" HGD_RESP_E_DENY);
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
			OUT( "err|" HGD_RESP_E_DENY);

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

/**
 * Creates a ServerSocket for the server.
 * @return The FileDescriptor of the Server Socket.
 */
int create_ss(int port) {
	int sd;
	struct sockaddr_in addr;
	int sockopt = 1;

	DPRINTF(HGD_D_DEBUG, "Listening on port %d", port);

	// Create server socket
	if( (sd = socket(PF_INET, SOCK_STREAM, 0)) < 0 )
	{
		perror("socket error");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
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

/**
 * Called whenever a user has sent some data to be processed.
 * Has two modes line and binary.
 */
void read_callback(struct bufferevent *bev, void *ctx)
{
	con_t *con = (con_t*) ctx;
	char * line;

	bufferevent_read_buffer(bev, con->in);
	if (con->binary_mode == NULL) {
		line = evbuffer_readln(con->in, NULL, EVBUFFER_EOL_CRLF);
		DPRINTF(HGD_D_DEBUG, "got line [%s]", line);
		con->closing = hgd_parse_line_event(con, line);
		free(line);
	} else {
		char data[1024];
		int bytes_copied = 0;
		int write_ret;

		do {
			bytes_copied =
			    evbuffer_remove(con->in, data,
			    con->binary_mode->bytes_left < 1024 ?
			    con->binary_mode->bytes_left : 1024);
			DPRINTF(HGD_D_DEBUG, "Recieved %d bytes %d to go:",
				bytes_copied, con->binary_mode->bytes_left);

			con->binary_mode->bytes_left -= bytes_copied;
			write_ret = write(con->binary_mode->fd, data, bytes_copied);

			if (write_ret < bytes_copied) {
				/*
				 * We are not sure if this is possible.
				 * It has not *yet* happened.
				 */
				DPRINTF(HGD_D_ERROR,
				    "Short write: %d vs %d",
				    (int) write_ret, (int) bytes_copied);
				/*TODO: goto clean; */
			} else if (write_ret < 0) {
				DPRINTF(HGD_D_ERROR, "Failed to write %d bytes: %s",
				    (int) bytes_copied, SERROR);
				OUT( "err|" HGD_RESP_E_INT);
				unlink(con->binary_mode->filename); /* don't much care if this fails */
				/* TODO: goto clean; */
			}
		} while ( con->binary_mode->bytes_left > 0 && evbuffer_get_length(con->in) > 0 );

		if (con->binary_mode->bytes_left == 0) {
			binary_finished_cb(con);
			if (con->binary_mode != NULL) {
				close(con->binary_mode->fd);
				free(con->binary_mode);
				con->binary_mode = NULL;
			}
		}
	}

	if (con->closing) {
		OUT( "ok|Catch you later d00d!");
		bufferevent_disable(bev, EV_READ);
	}
	bufferevent_write_buffer(bev, con->out);

}

/**
 * This callback is called when the output is exauseted.
 * If there is any more data to write in the out buffer it is written.
 */
void write_callback(struct bufferevent *bev, void *ctx)
{
	DPRINTF(HGD_D_DEBUG, "write callback");
	con_t *con = (con_t*) ctx;
	bufferevent_write_buffer(bev, con->out);
	if (con->closing && evbuffer_get_length(bufferevent_get_output(bev)) == 0) {
		DPRINTF(HGD_D_DEBUG, "all done, closing");
		bufferevent_free(bev);
	}
}



/**
 * This callback is called when new users connect.  It sets up buffered
 * reader for the user to comunicate on.
 * @param fd filedescriptor of server socket
 * @param what TODO:
 * @param args pointer to event_base
 */
void
accept_cb_func(evutil_socket_t fd, short what, void *arg)
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

	bev = bufferevent_socket_new(eb, client_sd, BEV_OPT_CLOSE_ON_FREE);
	bufferevent_setcb(bev,read_callback, write_callback, cb, con);

	OUT( "ok|" HGD_RESP_O_GREET);


	bufferevent_enable(bev, EV_READ|EV_WRITE);
	/*	new_con_e = event_new(eb, client_sd, EV_TIMEOUT|EV_READ|EV_PERSIST, cb,
		eb);
		event_add(new_con_e, NULL);*/


	printf("Successfully connected with client.\n");

}


static char**
setup_libconfig()
{
	settings.libconfig.config_paths[0] = NULL;

	xasprintf(&settings.libconfig.config_paths[1], "%s",  HGD_GLOBAL_CFG_DIR HGD_SERV_CFG );
	settings.libconfig.num_configs++;

	settings.libconfig.config_paths[2] = hgd_get_XDG_userprefs_location(netd);
	settings.libconfig.num_configs++;

}

static int
hgd_read_config(char **config_locations)
{
#ifdef HAVE_LIBCONFIG
	/*
	 * config_lookup_int64 is used because lib_config changed
	 * config_lookup_int from returning a long int, to a int, and debian
	 * still uses the old version.
	 * See hgd-playd.c for how to remove the stat when deb get into gear
	 */
	config_t		 cfg, *cf;

	cf = &cfg;

	if (hgd_load_config(cf, config_locations) == HGD_FAIL) {
		return (HGD_OK);
	}

	hgd_cfg_daemonise(cf, "netd", &settings.daemonise);
	hgd_cfg_netd_rdns(cf, &settings.lookup_client_dns);
	hgd_cfg_statepath(cf, &settings.paths.state_path);
	hgd_cfg_crypto(cf, "netd", &settings.ssl.crypto_pref);
	hgd_cfg_netd_flood_limit(cf, &settings.flood_limit);
	/*hgd_cf_netd_ssl_privkey(cf, &ssl_key_path); TODO:*/
	hgd_cfg_netd_votesound(cf, &settings.req_votes);
	hgd_cfg_netd_port(cf, &settings.port);
	hgd_cfg_netd_max_filesize(cf, &settings.max_upload_size);
	/*hgd_cfg_netd_sslcert(cf, &ssl_cert_path); TODO:*/
	hgd_cfg_debug(cf, "netd", &hgd_debug); /*TODO: put this is settings? */
	hgd_cfg_netd_voteoff_sound(cf, &settings.vote_sound);

	/* we can destory config here because we copy all heap alloc'd stuff */
	config_destroy(cf);
#endif

	return (HGD_OK);
}
static void
hgd_usage(void)
{
	printf("usage: hgd-netd <options>\n");
	printf("    -B			Do not daemonise, run in foreground\n");
#ifdef HAVE_LIBCONFIG
	printf("    -c <path>		Path to a config file to use\n");
#endif
	printf("    -D			Disable reverse DNS lookups for clients\n");
	printf("    -d <path>		Set hgd state directory\n");
	printf("    -E			Disable SSL encryption support\n");
	printf("    -e			Require SSL encryption from clients\n");
	printf("    -f			Don't fork - service single client (debug)\n");
	printf("    -F			Flood limit (-1 for no limit)\n");
	printf("    -h			Show this message and exit\n");
	printf("    -k <path>		Set path to SSL private key file\n");
	printf("    -n <num>		Set number of votes required to vote-off\n");
	printf("    -p <port>		Set network port number\n");
	printf("    -s <mbs>		Set maximum upload size (in MB)\n");
	printf("    -S <path>		Set path to SSL certificate file\n");
	printf("    -v			Show version and exit\n");
	printf("    -x <level>		Set debug level (0-3)\n");
	printf("    -y <path>		Set path to noise to play when voting off\n");
}

static int
parse_options_1(int argc, char **argv)
{
	int	ch;

	DPRINTF(HGD_D_DEBUG, "Parsing options:1");
	while ((ch = getopt(argc, argv, "Bc:Dd:EefF:hk:n:p:s:S:vx:y:")) != -1) {
		switch (ch) {
		case 'h':
			/* Do this early so we don't waist time setting up stuff we don't need */
			hgd_usage();
			return (HGD_FAIL);
		case 'c':
			if (settings.libconfig.num_configs < 3) {
				settings.libconfig.num_configs++;
				DPRINTF(HGD_D_DEBUG, "added config %d %s",
				    settings.libconfig.num_configs, optarg);
				settings.libconfig.config_paths[settings.libconfig.num_configs] =
				    optarg;
			} else {
				DPRINTF(HGD_D_WARN,
				    "Too many config files specified");
				hgd_exit_nicely();
			}
			break;
		case 'x':
			hgd_debug = atoi(optarg);
			if (hgd_debug > 3)
				hgd_debug = 3;
			DPRINTF(HGD_D_DEBUG, "set debug to %d", hgd_debug);
			break;
		default:
			break; /* next getopt will catch errors */
		}
	}
	RESET_GETOPT();
	return (HGD_OK);
}

static int
parse_options_2(int argc, char **argv)
{
	int		ch;

	DPRINTF(HGD_D_DEBUG, "Parsing options:2");
	while ((ch = getopt(argc, argv, "Bc:Dd:EefF:hk:n:p:s:S:vx:y:")) != -1) {
		switch (ch) {
		case 'B':
			settings.daemonise = 0;
			DPRINTF(HGD_D_DEBUG, "Not \"backgrounding\" daemon.");
			break;
		case 'c':
			break; /* already handled */
		case 'D':
			DPRINTF(HGD_D_DEBUG, "No client DNS lookups");
			settings.lookup_client_dns = 0;
			break;
		case 'd':
			free(settings.paths.state_path);
			settings.paths.state_path = xstrdup(optarg);
			DPRINTF(HGD_D_DEBUG, "Set hgd dir to '%s'", settings.paths.state_path);
			break;
		case 'e':
			settings.ssl.crypto_pref = always;
			DPRINTF(HGD_D_DEBUG, "Server will insist on crypto");
			break;
		case 'E':
			settings.ssl.crypto_pref = never;
			DPRINTF(HGD_D_WARN, "Encryption disabled manually");
			break;
		case 'F':
			settings.flood_limit = atoi(optarg);
			DPRINTF(HGD_D_DEBUG, "Set flood limit to %d",
			    settings.flood_limit);
			break;
		case 'k':
			/* TODO:
			free(ssl_key_path);
			ssl_key_path = optarg;
			DPRINTF(HGD_D_DEBUG,
			    "set ssl private key path to '%s'", ssl_key_path);
			*/
			break;
		case 'n':
			settings.req_votes = atoi(optarg);
			DPRINTF(HGD_D_DEBUG,
			    "Set required-votes to %d", settings.req_votes);
			break;
		case 'p':
			settings.port = atoi(optarg);
			DPRINTF(HGD_D_DEBUG, "Set port to %d", settings.port);
			break;
		case 's':
			settings.max_upload_size = strtoll(optarg, NULL, 0) * HGD_MB;
			DPRINTF(HGD_D_DEBUG, "Set max upload size to %lld",
			    (long long int) settings.max_upload_size);
			break;
		case 'S':
			/* TODO:
			free(ssl_cert_path);
			ssl_cert_path = optarg;
			DPRINTF(HGD_D_DEBUG,
			    "set ssl cert path to '%s'", ssl_cert_path);
			*/
			break;
		case 'v':
			hgd_print_version();
			return (HGD_FAIL);
			break;
		case 'x':
			DPRINTF(HGD_D_DEBUG, "set debug to %d", atoi(optarg));
			hgd_debug = atoi(optarg);
			if (hgd_debug > 3)
				hgd_debug = 3;
			break; /* already set but over-rideable */
		case 'y':
			free(settings.vote_sound);
			settings.vote_sound = optarg;
			DPRINTF(HGD_D_DEBUG,
			    "set voteoff sound %s", settings.vote_sound);
			break;
		};
	}
	return (HGD_OK);
}

int
setup_SSL()
{
	char *ssl_cert_path = NULL, *ssl_key_path =  NULL;

	ssl_key_path = xstrdup(HGD_DFL_KEY_FILE);
	ssl_cert_path = xstrdup(HGD_DFL_CERT_FILE);
	/* TODO: set paths */
	/* unless the user actively disables SSL, we try to be capable */
	if (settings.ssl.crypto_pref != never) {
		if (hgd_setup_ssl_ctx(&(settings.ssl.method),
		    &(settings.ssl.ctx), 1,
		    ssl_cert_path, ssl_key_path) == 0) {
			DPRINTF(HGD_D_INFO, "Server is SSL capable");
			settings.ssl.ssl_capable = 1;
		} else {
			DPRINTF(HGD_D_WARN, "Server is SSL incapable");
		}
	} else {
		DPRINTF(HGD_D_INFO, "Server was forced SSL incapable");
	}
	return (HGD_OK);
}

/**
 * Entry point
 */
int
main(int argc, char **argv)
{
	int running = 1;
	struct event *ev1;
	char *db_path;

	/* TODO: signal handlers */

	HGD_INIT_SYSLOG_DAEMON();

	hgd_debug = 4;

	settings.paths.state_path = xstrdup(HGD_DFL_DIR);
	xasprintf(&db_path, "%s/%s", settings.paths.state_path, HGD_DB_NAME);
	xasprintf(&(settings.paths.filestore_path), "%s/%s",
	    settings.paths.state_path, HGD_FILESTORE_NAME);

	setup_libconfig();

	if (parse_options_1(argc, argv) != HGD_OK)
		goto exit;
	hgd_read_config(settings.libconfig.config_paths + settings.libconfig.num_configs);
	if (parse_options_2(argc, argv) != HGD_OK)
		goto exit;



	settings.db = hgd_open_db(db_path, 0);
	if (settings.db == NULL)
		hgd_exit_nicely();

	event_enable_debug_mode();
	event_set_log_callback(DPRINTF_cb);
	settings.eb = event_base_new();

	setup_SSL();
	ev1 = event_new(settings.eb, create_ss(settings.port),
	    EV_TIMEOUT|EV_READ|EV_PERSIST, accept_cb_func,
	    settings.eb);

	event_add(ev1, NULL);

	while (running) {
		event_base_dispatch(settings.eb);
		puts("Tick");
	}
	return (0);

exit:
	_exit(EX_OK);
}

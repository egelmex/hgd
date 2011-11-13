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

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <vlc/vlc.h>

#include "hgd.h"

libvlc_instance_t * inst;
libvlc_media_player_t *mp;
libvlc_media_t *m;
libvlc_event_manager_t *events;

int
hgd_playback_init(void)
{
	/* Load the VLC engine */
	inst = libvlc_new (0, NULL);
	return (HGD_OK);
}

int
hgd_playback_clean()
{
	/* not currently used */
	return (HGD_OK);
}


void
stop_callback(const struct libvlc_event_t *event, void *data) {
	pthread_mutex_t *mutex  =  (pthread_mutex_t*) data;

	DPRINTF(HGD_D_DEBUG, "VLC STOP CALLBACK");
	pthread_mutex_unlock(mutex);
}

int
hgd_play_track(struct hgd_playlist_item *t, uint8_t purge_fs, uint8_t purge_db)
{
	pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
	int ret;

	ret = pthread_mutex_init(&mutex, NULL);


	DPRINTF(HGD_D_DEBUG, "VLC playing: %s", t->filename);

	m = libvlc_media_new_path (inst, t->filename);

	mp = libvlc_media_player_new_from_media(m);

	events = libvlc_media_player_event_manager(mp);
	libvlc_event_attach(events,libvlc_MediaPlayerStopped,
	   stop_callback, &mutex);

	libvlc_media_release(m);

	libvlc_media_player_play(mp);

	/* initialize a mutex to its default value */

	DPRINTF(HGD_D_DEBUG, "taking first lock");
	pthread_mutex_lock(&mutex);

	/*DPRINTF(HGD_D_DEBUG, "locking again");*/
	pthread_mutex_lock(&mutex);

	DPRINTF(HGD_D_DEBUG, "unlocking again");

	pthread_mutex_unlock(&mutex);

	pthread_mutex_destroy(&mutex);

	libvlc_media_player_stop (mp);
	libvlc_media_player_release (mp);

	if (hgd_mark_finished(t->id, purge_db) == HGD_FAIL)
		DPRINTF(HGD_D_WARN,
		    "Could not purge/mark finished -- trying to continue");

	DPRINTF(HGD_D_DEBUG, "VLC done playing: %s", t->filename);
}


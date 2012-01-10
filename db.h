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

#ifndef __DB_H
#define __DB_H

/* sqlite database error string (from global db ptr) */
#define DERROR			sqlite3_errmsg(db)

#include <sqlite3.h>

#include "hgd.h"

#define	HGD_DB_SCHEMA_VERS	"1"

sqlite3				*hgd_open_db(char *, uint8_t);
int				 hgd_get_playing_item_cb(void *arg,
				     int argc, char **data, char **names);
int				 hgd_get_playing_item(sqlite3 *db,
				     struct hgd_playlist_item *playing);
int				 hgd_get_num_votes_cb(void *arg,
				     int argc, char **data, char **names);
int				 hgd_get_num_votes(sqlite3 *db, int *nv);
int				 hgd_insert_track(sqlite3 *db, char *filename,
				     struct hgd_media_tag *, char *user);
int				 hgd_insert_vote(sqlite3 *db, char *user);
int				 hgd_get_playlist(sqlite3 *db, struct hgd_playlist *list);
int				 hgd_get_next_track(sqlite3 *db,
				     struct hgd_playlist_item *track);
int				 hgd_mark_playing(sqlite3 *db, int id);
int				 hgd_mark_finished(sqlite3 *db, int id, uint8_t purge);
int				 hgd_clear_votes(sqlite3 *db);
int				 hgd_clear_playlist(sqlite3 *db);
int				 hgd_init_playstate(sqlite3 *db);
int				 hgd_user_add_db(sqlite3 *db, char *usr, char *slt, char *hash);
struct hgd_user			*hgd_authenticate_user(sqlite3 *db, char *user, char *pass);
int				 hgd_user_del_db(sqlite3 *db, char *user);
struct hgd_user_list		*hgd_get_all_users(sqlite3 *db);
int				 hgd_num_tracks_user(sqlite3 *db, char *username);
int				 hgd_make_new_db(char *db_path);
int				 hgd_user_mod_perms_db(sqlite3 *db, struct hgd_user *user);
int				 hgd_user_has_voted(sqlite3 *db, char *user, int *v);
int				 hgd_get_user(sqlite3 *db,char *user, struct hgd_user *result);

#endif

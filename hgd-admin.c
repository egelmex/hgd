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

#define _GNU_SOURCE	/* linux */

#include <sys/types.h>
#include <sys/stat.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sqlite3.h>
#include <openssl/rand.h>

#include "config.h"
#include "hgd.h"
#ifdef HAVE_LIBCONFIG
#include "cfg.h"
#endif
#include "db.h"
#include "user.h"
#include "mplayer.h"

const char			*hgd_component = HGD_COMPONENT_HGD_ADMIN;

uint8_t				 purge_finished_db = 1;
uint8_t				 purge_finished_fs = 1;
uint8_t				 clear_playlist_on_start = 0;

/*
 * clean up, exit. if exit_ok = 0, an error (signal/error)
 */
void
hgd_exit_nicely()
{
	if (!exit_ok)
		DPRINTF(HGD_D_ERROR, "hgd-playd was interrupted or crashed\n");

	if (mplayer_fifo_path)
		free(mplayer_fifo_path);
	if (db)
		sqlite3_close(db);
	if (state_path)
		free(state_path);
	if (db_path)
		free (db_path);
	if (filestore_path)
		free(filestore_path);

	hgd_cleanup_ssl(NULL);

	HGD_CLOSE_SYSLOG();

	exit (!exit_ok);
}
/* NOTE! -c is reserved for 'config file path' */
void
hgd_usage()
{
        printf("Usage: hgdc [opts] command [args]\n\n");
        printf("Commands include:\n");
        printf("    db-init				Initialise database.\n");
        printf("    pause				Pause MPlayer.\n");
        printf("    skip				Next track.\n");
        printf("    status				Show daemon status'.\n");
        printf("    user-add <username> [password]	Add a user.\n");
        printf("    user-del <username>			Delete a user.\n");
        printf("    user-list				List users.\n");
	printf("    user-mkadmin <username>		Make a user an admin.\n");
	printf("    user-noadmin <username>		Revoke admin rights from user.\n");
	/*
        printf("    user-disable username\tDisable a user account");
        printf("    user-chpw username\t\t\tChange a users password\n");
        printf("    user-enable username\t\t\Re-enable a user\n\n");
	*/
        printf("\n  Options include:\n");
	printf("    -c <path>		Location of config files\n");
        printf("    -d <path>		Location of state directory\n");
        printf("    -h			Show this message and exit\n");
        printf("    -x <level>		Set debug level (0-3)\n");
        printf("    -v			Show version and exit\n");
}


int
hgd_acmd_init_db(char **args)
{
	(void) args;

	return (hgd_make_new_db(db_path));
}

/* make a user an administrator */
int
hgd_acmd_mkadmin(char **args)
{
	int		ret = HGD_FAIL;

	switch (hgd_user_mod_perms(args[0], HGD_AUTH_ADMIN, 1)) {
	case HGD_OK: /* FALLTHRU */
	case HGD_FAIL_PERMNOCHG:
		ret = HGD_OK;
		break;
	default: /* can also ret HGD_FAIL_USRNOEXIST */
		break;
	};

	return (ret);
}

/* revoke admin rights from a user */
int
hgd_acmd_noadmin(char **args)
{
	int		ret = HGD_FAIL;

	switch (hgd_user_mod_perms(args[0], HGD_AUTH_ADMIN, 0)) {
	case HGD_OK: /* FALLTHRU */
	case HGD_FAIL_PERMNOCHG:
		ret = HGD_OK;
		break;
	default: /* can also ret HGD_FAIL_USRNOEXIST */
		break;
	};

	return (ret);
}

int
hgd_acmd_user_list_print(char **args)
{
	struct hgd_user_list	*list;
	int			 i, ret = HGD_FAIL;
	char			*permstr = NULL;

	if (db == NULL)
		db = hgd_open_db(db_path, 0);

	if (db == NULL)
		goto clean;

	if (hgd_user_list(&list) != HGD_OK)
		goto clean;

	for (i = 0; i < list->n_users; i++) {
		hgd_gen_perms_str(list->users[i]->perms, &permstr);
		printf("%-20s %s\n",
		    list->users[i]->name, permstr);
		free(permstr);
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
hgd_acmd_skip(char **args)
{
	(void) args;
	return(hgd_skip_track());
}

int
hgd_acmd_pause(char **args)
{
	(void) args;
	return (hgd_pause_track());
}

int
hgd_acmd_user_add(char **args)
{
	return (hgd_user_add(args[0], args[1]));
}

int
hgd_acmd_user_add_prompt(char **args)
{
	char			 pass[HGD_MAX_PASS_SZ];

	if (db == NULL)
		db = hgd_open_db(db_path, 0);

	if (db == NULL)
		return (HGD_FAIL);

	if (hgd_readpassphrase_confirmed(pass, NULL) != HGD_OK)
		return (HGD_FAIL);

	return (hgd_user_add(args[0], pass));
}

int
hgd_acmd_user_del(char **args)
{
	if (db == NULL)
		db = hgd_open_db(db_path, 0);

	if (db == NULL)
		return (HGD_FAIL);

	if (hgd_user_del(args[0]) != HGD_OK)
		return (HGD_FAIL);

	return (HGD_OK);
}

int
hgd_acmd_status(char **args)
{
	(void) args;

	char		*descrs[2] = {
			"Network listener daemon (hgd-netd)",
			"MPlayer overseer daemon (hgd-playd)" };
	char 		*comps[2] = {
			HGD_COMPONENT_HGD_NETD,
			HGD_COMPONENT_HGD_PLAYD };
	char		*states[3] = { "Absent", "Running", "Unknown" };
	char		*cur_state;
	int	 	 i, run;

	printf("\n  HGD subsystems status:\n\n");

	for (i = 0; i < 2; i++) {
		if (hgd_check_component_status(comps[i], &run) == HGD_OK)
			cur_state = states[run];
		else
			cur_state = states[2];

		printf("    %-40s: %s\n", descrs[i], cur_state);

	}
	printf("\n");

	return (HGD_OK);
}

struct hgd_admin_cmd admin_cmds[] = {
	{ "db-init", 0, hgd_acmd_init_db },
	{ "pause", 0, hgd_acmd_pause },
	{ "skip", 0, hgd_acmd_skip },
	{ "status", 0, hgd_acmd_status },
	{ "user-add", 2, hgd_acmd_user_add },
	{ "user-add", 1, hgd_acmd_user_add_prompt },
	{ "user-del", 1, hgd_acmd_user_del },
	{ "user-list", 0, hgd_acmd_user_list_print },
	{ "user-mkadmin", 1, hgd_acmd_mkadmin},
	{ "user-noadmin", 1, hgd_acmd_noadmin},
#if 0
	{ "user-disable", 1, hgd_acmd_user_disable },
	{ "user-chpw", 1, hgd_acmd_user_chpw },
	{ "user-enable", 1, hgd_acmd_user_enable },
#endif
	{ 0, 0, NULL }
};

int
hgd_parse_command(int argc, char **argv)
{
	struct hgd_admin_cmd	*acmd, *correct_acmd = NULL;

	if (argc == 0) {
		hgd_usage();
		DPRINTF(HGD_D_ERROR, "bad usage");
		return (HGD_FAIL);
	}

	DPRINTF(HGD_D_DEBUG, "Looking for command handler for '%s'", argv[0]);

	for (acmd = admin_cmds; acmd->cmd != 0; acmd++) {
		if ((acmd->num_args == argc -1) &&
		    (strcmp(acmd->cmd, argv[0]) == 0))
			correct_acmd = acmd;
	}

	if (correct_acmd == NULL) {
		DPRINTF(HGD_D_WARN, "Incorrect usage: '%s' with %d args",
		    argv[0], argc - 1);
		return (HGD_FAIL);
	}

	if (correct_acmd->handler(++argv) != HGD_OK)
		return (HGD_FAIL);

	return (HGD_OK);
}

int
hgd_read_config(char **config_locations)
{
#ifdef HAVE_LIBCONFIG
	/*
	 * config_lookup_int64 is used because lib_config changed
	 * config_lookup_int from returning a long int, to a int, and debian
	 * still uses the old version.
	 */
	config_t		 cfg, *cf;
	int			 dont_fork = dont_fork;

	cf = &cfg;

	if (hgd_load_config(cf, config_locations) == HGD_FAIL) {
		return (HGD_OK);
	}

	hgd_cfg_statepath(cf, &state_path);
	hgd_cfg_debug(cf, "admin", &hgd_debug);

	config_destroy(cf);
#endif
	return (HGD_OK);
}


int
main(int argc, char **argv)
{
	char			*config_path[4] = {NULL, NULL, NULL, NULL};
	int			 num_config = 2, ch;

	/* syslog as early as possible */
	HGD_INIT_SYSLOG();

#ifdef HAVE_LIBCONFIG
	config_path[0] = NULL;
	xasprintf(&config_path[1], "%s", HGD_GLOBAL_CFG_DIR HGD_SERV_CFG);
	config_path[2] = hgd_get_XDG_userprefs_location(hgdc);
#endif

	hgd_register_sig_handlers();
	state_path = xstrdup(HGD_DFL_DIR);

	DPRINTF(HGD_D_DEBUG, "Parsing options:1");
	while ((ch = getopt(argc, argv, "c:d:hvx:" "c:x:")) != -1) {
		switch (ch) {
		case 'c':
			if (num_config < 3) {
				num_config++;
				DPRINTF(HGD_D_DEBUG, "added config %d %s",
				    num_config, optarg);
				config_path[num_config] = optarg;
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
			DPRINTF(HGD_D_DEBUG,
			    "set debug level to %d", hgd_debug);
			break;
		default:
			break; /* next getopt will catch errors */
		};
	}

	hgd_read_config(config_path + num_config);

	while(num_config > 0) {
		if (config_path[num_config] != NULL) {
			free (config_path[num_config]);
			config_path[num_config] = NULL;
		}
		num_config--;
	}

	RESET_GETOPT();

	DPRINTF(HGD_D_DEBUG, "Parsing options:2");
	while ((ch = getopt(argc, argv, "c:d:hvx:" "c:x:")) != -1) {
		switch (ch) {
		case 'c':
			break; /* already handled */
		case 'd':
			free(state_path);
			state_path = xstrdup(optarg);
			DPRINTF(HGD_D_DEBUG, "set hgd dir to '%s'", state_path);
			break;
		case 'v':
			hgd_print_version();
			exit_ok = 1;
			hgd_exit_nicely();
			break;
		case 'x':
			DPRINTF(HGD_D_DEBUG, "set debug to %d", atoi(optarg));
			hgd_debug = atoi(optarg);
			if (hgd_debug > 3)
				hgd_debug = 3;
			break; /* already set but over-rideable */
		case 'h':
		default:
			hgd_usage();
			exit_ok = 1;
			hgd_exit_nicely();
			break;
		};
	}

	argc -= optind;
	argv += optind;

	xasprintf(&db_path, "%s/%s", state_path, HGD_DB_NAME);
	xasprintf(&filestore_path, "%s/%s", state_path, HGD_FILESTORE_NAME);

	umask(~S_IRWXU);
	hgd_mk_state_dir();

	if (hgd_parse_command(argc, argv) == -1)
		hgd_exit_nicely();

	exit_ok = 1;
	hgd_exit_nicely();
	_exit (EXIT_SUCCESS); /* NOREACH */
}

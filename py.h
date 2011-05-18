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

#ifndef __PY_H
#define __PY_H

#include "hgd.h"

#define PRINT_PY_ERROR()	do { \
					PyErr_Print(); \
					DPRINTF(HGD_D_ERROR, "Python error"); \
				} while (0);

/* python extensions */
#define HGD_MAX_PY_MODS		16
#define HGD_DFL_PY_DIR		HGD_DFL_SVR_CONF_DIR "/scripts"
struct hgd_py_mods {
	PyObject		*mod;
	uint8_t			 n_mods;
};
extern struct hgd_py_mods	 hgd_pys;

int				 hgd_init_py();
void				 hgd_free_py();

#endif

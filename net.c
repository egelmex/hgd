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


#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#define _GNU_SOURCE	/* linux */
#include <errno.h>
#include <poll.h>
#include <stdio.h>

#include <openssl/ssl.h>

#include "config.h"
#include "hgd.h"
#include "net.h"


void
hgd_cleanup_ssl(SSL_CTX **ctx) {
	(void) ERR_free_strings();
	(void) EVP_cleanup();

	if ((ctx != NULL) && (*ctx != NULL))
		 SSL_CTX_free(*ctx);
}

int
hgd_setup_ssl_ctx(SSL_METHOD **method, SSL_CTX **ctx,
    int server, char *cert_path, char *key_path) {

#if 0
	/* XXX For semi-implemented certificate verification - FAO mex */
	char		*home;
	char		*keystore_path = NULL;
#endif

	SSL_library_init();
	OpenSSL_add_all_algorithms();

	SSL_load_error_strings();

	if (server) {
		DPRINTF(HGD_D_DEBUG, "Setting up TLSv1_server_method");
		*method = (SSL_METHOD *) TLSv1_server_method();
		if (*method == NULL) {
			PRINT_SSL_ERR(HGD_D_ERROR, "TLSv1_server_method");
			return (HGD_FAIL);
		}
	} else {
		DPRINTF(HGD_D_DEBUG, "Setting up TLSv1_client_method");
		*method = (SSL_METHOD *) TLSv1_client_method();
		if (*method == NULL) {
			PRINT_SSL_ERR(HGD_D_ERROR, "TLSv1_client_method");
			return (HGD_FAIL);
		}

#if 0
		/* XXX For semi-implemented certificate verification - FAO mex */

		home = getenv("HOME");
		if (!home) {
			/* crapout? */
			DPRINTF(HGD_D_ERROR, "Could not get home env value");
			exit (HGD_FAIL);
		}


		xasprintf(&keystore_path, "%s%s", home, "/.hgdc/certs");
		/* xxx: create  cert_path if it doesn't exist*/
#endif
	}

	DPRINTF(HGD_D_DEBUG, "Setting up SSL_CTX_new");
	*ctx = SSL_CTX_new(*method);
	if (*ctx == NULL) {
		PRINT_SSL_ERR(HGD_D_ERROR, "SSL_CTX_new");
		return (HGD_FAIL);
	}

	if (!server) {
#if 0
		/* XXX For semi-implemented certificate verification - FAO mex */

		if(! SSL_CTX_load_verify_locations(*ctx, NULL, keystore_path))
		{
			DPRINTF(HGD_D_ERROR,
			    "Could not load verify location: %s",
			    keystore_path);
			/* XXX: Handle failed load here */
			exit (HGD_FAIL);
		}
#endif
		goto done;
	}

	/* set the local certificate from CertFile */
	DPRINTF(HGD_D_DEBUG, "Loading SSL certificate");
	if (!SSL_CTX_use_certificate_file(
	    *ctx, cert_path, SSL_FILETYPE_PEM)) {
		DPRINTF(HGD_D_WARN, "Can't load SSL cert: %s", cert_path);
		PRINT_SSL_ERR(HGD_D_WARN, "SSL_CTX_use_certificate_file");
		return (HGD_FAIL);
	} else {
		DPRINTF(HGD_D_DEBUG, "Loaded SSL certificate \"%s\"", cert_path);
	}

	/* set the private key from KeyFile */
	DPRINTF(HGD_D_DEBUG, "Loading SSL private key");
	if (!SSL_CTX_use_PrivateKey_file(
	    *ctx, key_path, SSL_FILETYPE_PEM)) {
		DPRINTF(HGD_D_WARN, "Can't load SSL key: %s", key_path);
		PRINT_SSL_ERR(HGD_D_WARN, "SSL_CTX_use_PrivateKey_file");
		return (HGD_FAIL);
	} else {
		DPRINTF(HGD_D_DEBUG, "Loaded SSL private key \"%s\"", key_path);
	}

	/* verify private key */
	DPRINTF(HGD_D_DEBUG, "Verify SSL private certificate");
	if (!SSL_CTX_check_private_key(*ctx)) {
		DPRINTF(HGD_D_WARN, "Can't verify SSL key: %s", key_path);
		PRINT_SSL_ERR(HGD_D_WARN, "SSL_CTX_check_private_key");
		return (HGD_FAIL);
	}



done:
	return (HGD_OK);
}

void
hgd_sock_send_bin_nossl(int fd, char *msg, ssize_t sz)
{
	ssize_t		tot_sent = 0, sent;
	char		*next = msg;

	while (tot_sent != sz) {
		sent = send(fd, next, sz - tot_sent, 0);

		if (sent < 0) {
			DPRINTF(HGD_D_WARN, "Send failed");
			continue;
		} else
			DPRINTF(HGD_D_DEBUG, "Sent %d bytes", (int) sent);

		msg += sent;
		tot_sent += sent;
	}
}

void
hgd_sock_send_bin_ssl(SSL *ssl, char *msg, ssize_t sz)
{
	ssize_t		sent = 0;

	/* SSL_write is all or nothing */
	while (!sent) {
		sent = SSL_write(ssl, msg, sz);

		if (sent <= 0) {
			DPRINTF(HGD_D_WARN, "Send failed");
			sent = 0;
			continue;
		} else
			DPRINTF(HGD_D_DEBUG, "Sent %d bytes", (int) sent);
	}
}

/* send binary over the socket */
void
hgd_sock_send_bin(int fd, SSL *ssl, char *msg, ssize_t sz)
{
	if (ssl == NULL) {
		hgd_sock_send_bin_nossl(fd, msg, sz);
	} else {
		hgd_sock_send_bin_ssl(ssl, msg, sz);
	}
}

/* send a SSL encrypted message onto the network */
void
hgd_sock_send_ssl(SSL *ssl, char *msg)
{
	char			*buffer = NULL;

	DPRINTF(HGD_D_DEBUG, "SSL send '%s'", msg);

	buffer = xcalloc(HGD_MAX_LINE, sizeof(char));
	strncpy(buffer, msg, HGD_MAX_LINE);

	SSL_write(ssl, buffer, HGD_MAX_LINE);
	free(buffer);
}

/* send a message onto the network */
void
hgd_sock_send(int fd, char *msg)
{
	ssize_t			sent_tot = 0, sent, len;

	len = strlen(msg);

	while (sent_tot != len) {
		sent = send(fd, msg, len - sent_tot, 0);
		if (sent < 0) {
			DPRINTF(HGD_D_WARN, "send: %s", SERROR);
			sent = 0;
		}
		sent_tot += sent;
	}

	DPRINTF(HGD_D_DEBUG, "Sent %d bytes", (int) len);
}

void
hgd_sock_send_line_ssl(SSL *ssl, char *msg)
{
	char			*term;

	DPRINTF(HGD_D_DEBUG, "Trying to send SSL message: '%s'", msg);

	xasprintf(&term, "%s\r\n", msg);
	hgd_sock_send_ssl(ssl, term);

	free(term);
}

void
hgd_sock_send_line_nossl(int fd, char *msg)
{
	char			*term;

	xasprintf(&term, "%s\r\n", msg);
	hgd_sock_send(fd, term);
	free(term);

	DPRINTF(HGD_D_DEBUG, "Sent line: %s", msg);

}

/* send a \r\n terminated line */
void
hgd_sock_send_line(int fd, SSL *ssl, char *msg)
{
	if (ssl == NULL)
		return (hgd_sock_send_line_nossl(fd, msg));
	else
		return (hgd_sock_send_line_ssl(ssl, msg));
}

/* recieve a specific size, free when done */
char *
hgd_sock_recv_bin_nossl(int fd, ssize_t len)
{
	ssize_t			recvd_tot = 0, recvd;
	char			*msg, *full_msg = NULL;
	struct pollfd		pfd;
	int			data_ready = 0, tries_left = 3;

	/* spin until something is ready */
	pfd.fd = fd;
	pfd.events = POLLIN;

	while (!dying && !data_ready) {
		data_ready = poll(&pfd, 1, INFTIM);
		if (data_ready == -1) {
			if (errno != EINTR) {
				DPRINTF(HGD_D_WARN, "poll error: %s", SERROR);
				dying = 1;
			}
			data_ready = 0;
		}
	}

	if (dying)
		hgd_exit_nicely();

	full_msg = xmalloc(len);
	msg = full_msg;

	while (recvd_tot != len && tries_left > 0) {
		recvd = recv(fd, msg, len - recvd_tot, 0);

		switch (recvd) {
		case 0:
			/* should not happen */
			DPRINTF(HGD_D_WARN, "No bytes recvd");
			tries_left--;
			continue;
		case -1:
			if (errno == EINTR)
				continue;
			DPRINTF(HGD_D_WARN, "recv: %s", SERROR);
			tries_left--;
		default:
			/* good */
			break;
		};

		msg += recvd;
		recvd_tot += recvd;
	}

	if (tries_left == 0) {
		DPRINTF(HGD_D_ERROR, "Gave up trying to recieve: %s", SERROR);
		return (NULL);
	}

	return (full_msg);
}

/* recieve a specific size, free when done */
char *
hgd_sock_recv_bin_ssl(SSL *ssl, ssize_t len)
{
	ssize_t			recvd_tot = 0, recvd;
	char			*msg, *full_msg = NULL;

	full_msg = xmalloc(len);
	msg = full_msg;

	while (recvd_tot != len) {
		recvd = SSL_read(ssl, msg, len - recvd_tot);

		if (recvd <= 0) {
			PRINT_SSL_ERR(HGD_D_ERROR, __func__);
			return (NULL);
		}

		msg += recvd;
		recvd_tot += recvd;
	}

	return (full_msg);
}

/* recieve a specific size, free when done */
char *
hgd_sock_recv_bin(int fd, SSL *ssl, ssize_t len)
{
	if (ssl == NULL)
		return (hgd_sock_recv_bin_nossl(fd, len));
	else
		return (hgd_sock_recv_bin_ssl(ssl, len));
}

char *
hgd_sock_recv_line_nossl(int fd)
{
	ssize_t			 recvd_tot = 0, recvd;
	char			 recv_char, *full_msg = NULL;
	struct pollfd		 pfd;
	char			*c;
	int			 data_ready = 0;

	/* spin until something is ready */
	pfd.fd = fd;
	pfd.events = POLLIN;

	while (!dying && !data_ready) {
		data_ready = poll(&pfd, 1, INFTIM);
		if (data_ready == -1) {
			if (errno != EINTR) {
				DPRINTF(HGD_D_WARN, "Poll error: %s", SERROR);
				dying = 1;
			}
			data_ready = 0;
		}
	}

	if (dying)
		hgd_exit_nicely();

	full_msg = xmalloc(HGD_MAX_LINE);

	do {
		/* recieve one byte */
		recvd = recv(fd, &recv_char, 1, 0);

		switch (recvd) {
		case 0:
			/* should not happen */
			DPRINTF(HGD_D_WARN, "No bytes recvd");
			free(full_msg);
			return (NULL);
		case -1:
			if (errno == EINTR)
				continue;
			DPRINTF(HGD_D_WARN, "recv: %s", SERROR);
			free(full_msg);
			return (NULL);
		default:
			/* good */
			break;
		};

		if (recvd_tot >= HGD_MAX_LINE)
			DPRINTF(HGD_D_ERROR, "Socket line was long");

		full_msg[recvd_tot] = recv_char;

		recvd_tot += recvd;
	} while ((recvd_tot >= 1) &&
	    (recvd_tot <= HGD_MAX_LINE) && (recv_char != '\n'));

	/* get rid of \r\n */
	c = strstr(full_msg, "\r\n");
	if (c == NULL) {
		DPRINTF(HGD_D_WARN, "could not locate \\r\\n terminator");
	} else {
		*c = 0;
	}

	full_msg[recvd_tot - 1] = 0;
	full_msg[recvd_tot] = 0;

	return (full_msg);
}

char *
hgd_sock_recv_line_ssl(SSL *ssl)
{
	char			*buffer = NULL;
	int			 ssl_ret = 0;
	char			*line = NULL, *c;


	buffer = xcalloc(HGD_MAX_LINE, sizeof(char));

	ssl_ret = SSL_read(ssl, buffer, HGD_MAX_LINE);
	if (ssl_ret <= 0) {
		PRINT_SSL_ERR(HGD_D_ERROR, "SSL_read");
		free(buffer);
		return (NULL);
	}

	/* get rid of \r\n */
	c = strstr(buffer, "\r\n");
	if (c == NULL) {
		DPRINTF(HGD_D_WARN, "could not locate \\r\\n terminator");
	} else {
		*c = 0;
	}

	DPRINTF(HGD_D_DEBUG, "SSL recvd:'%s'", buffer);

	line = xstrdup(buffer);
	free(buffer);

	return (line);
}

/*
 * recieve a line, free when done.
 * returns NULL on error.
 */
char *
hgd_sock_recv_line(int fd, SSL *ssl)
{
	if (ssl == NULL) {
		return (hgd_sock_recv_line_nossl(fd));
	} else {
		return (hgd_sock_recv_line_ssl(ssl));
	}
}

uint8_t
hgd_is_ip_addr(char *str)
{
	struct sockaddr_in	sa;
	int			res;

	res = inet_pton(AF_INET, str, &(sa.sin_addr));
	return (res != 0);
}

/*
 * Copyright (c) 2025 Ryan Moeller
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */ 

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/thr.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <paths.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#ifdef WITH_OPENSSL
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "openssl_hostname_validation.h"
#endif

#include <libgeom.h>

#include "core/geom.h"
#include "misc/subr.h"

#include "g_nbd.h"
#include "nbd-protocol.h"

#define NBD_DEFAULT_PORT	"10809"

uint32_t lib_version = G_LIB_VERSION;
uint32_t version = G_NBD_VERSION;

static void nbd_connect(struct gctl_req *req, unsigned flags);
static void nbd_list(struct gctl_req *req, unsigned flags);
static void nbd_reconnect(struct gctl_req *req, unsigned flags);
static void nbd_scale(struct gctl_req *req, unsigned flags);

#ifdef WITH_OPENSSL
#define TLS_OPTS \
		{ 'A', "cacert", G_VAL_OPTIONAL, G_TYPE_STRING }, \
		{ 'C', "cert", G_VAL_OPTIONAL, G_TYPE_STRING }, \
		{ 'K', "key", G_VAL_OPTIONAL, G_TYPE_STRING }
#define TLS_USAGE \
	    "[[-A cacert] -C cert -K key] "
#endif
struct g_command class_commands[] = {
	{ "connect", G_FLAG_LOADKLD, nbd_connect,
	    {
		{ 'S', "simple", NULL, G_TYPE_BOOL },
		{ 'c', "connections", "1", G_TYPE_NUMBER },
		{ 'n', "name", "", G_TYPE_STRING },
		{ 'p', "port", NBD_DEFAULT_PORT, G_TYPE_STRING },
#ifdef WITH_OPENSSL
		TLS_OPTS,
#endif
		G_OPT_SENTINEL
	    },
	    "[-S] [-c num] [-n name] [-p port] "
#ifdef WITH_OPENSSL
	    TLS_USAGE
#endif
	    "host"
	},
	{ "exports", 0, nbd_list,
	    {
		{ 'p', "port", NBD_DEFAULT_PORT, G_TYPE_STRING },
#ifdef WITH_OPENSSL
		TLS_OPTS,
#endif
		G_OPT_SENTINEL
	    },
	    "[-p port] "
#ifdef WITH_OPENSSL
	    TLS_USAGE
#endif
	    "host"
	},
	{ "reconnect", 0, nbd_reconnect,
	    {
		{ 'r', "seconds", "0", G_TYPE_NUMBER },
#ifdef WITH_OPENSSL
		TLS_OPTS,
#endif
		G_OPT_SENTINEL
	    },
	    "[-r seconds] "
#ifdef WITH_OPENSSL
	    TLS_USAGE
#endif
	    "prov"
	},
	{ "scale", 0, nbd_scale,
	    {
		{ 'c', "connections", NULL, G_TYPE_NUMBER },
#ifdef WITH_OPENSSL
		TLS_OPTS,
#endif
		G_OPT_SENTINEL
	    },
	    "-c num "
#ifdef WITH_OPENSSL
	    TLS_USAGE
#endif
	    "prov"
	},
	{ "disconnect", 0, NULL,
	    G_NULL_OPTS,
	    "prov"
	},
	G_CMD_SENTINEL
};

struct nbd_client {
	struct gctl_req *req;
	const char *host;
	const char *port;
	const char *name;
	const char *description;
	uint64_t size;
	union {
		uint32_t flags;
		struct {
			uint16_t handshake_flags;
			uint16_t transmission_flags;
		};
	};
	uint32_t minimum_blocksize;
	uint32_t preferred_blocksize;
	uint32_t maximum_payload;
	int socket;
	long tid;
#ifdef WITH_OPENSSL
	SSL_CTX *ssl_ctx;
#endif
};

/* Callback is responsible for freeing name/description. */
typedef int (*nbd_client_list_cb)(void *ctx, char *name, char *description);

#ifdef WITH_OPENSSL
/* See http://archives.seul.org/libevent/users/Jan-2013/msg00039.html */
static int
cert_verify_callback(X509_STORE_CTX *x509_ctx, void *arg)
{
	struct nbd_client *client = arg;
	X509 *server_cert;

	if (X509_verify_cert(x509_ctx) != 1)
		return (0);
	server_cert = X509_STORE_CTX_get_current_cert(x509_ctx);
	if (validate_hostname(client->host, server_cert) != MatchFound) {
		gctl_error(client->req, "Failed to verify server hostname.");
		return (0);
	}
	return (1);
}

static int
nbd_client_tls_init(struct nbd_client *client)
{
	struct gctl_req *req = client->req;
	const char *cacert = NULL, *cert = NULL, *key = NULL;
	SSL_CTX *ctx;

	if (gctl_has_param(req, "cacert"))
		cacert = gctl_get_ascii(req, "cacert");
	if (gctl_has_param(req, "cert"))
		cert = gctl_get_ascii(req, "cert");
	if (gctl_has_param(req, "key"))
		key = gctl_get_ascii(req, "key");
	if (cert == NULL && key == NULL) {
		if (cacert == NULL)
			return (0);
		gctl_error(req, "Need cert and key with cacert.");
		return (-1);
	}
	if (cert == NULL || key == NULL) {
		gctl_error(req, "Both cert and key must be given.");
		return (-1);
	}
	client->ssl_ctx = ctx = SSL_CTX_new(TLS_client_method());
	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		gctl_error(req, "Failed to create TLS client context.");
		return (-1);
	}
	if (cacert != NULL && SSL_CTX_load_verify_file(ctx, cacert) != 1) {
		ERR_print_errors_fp(stderr);
		gctl_error(req, "Failed to load CA certificate file.");
		return (-1);
	}
	if (SSL_CTX_use_certificate_chain_file(ctx, cert) != 1) {
		ERR_print_errors_fp(stderr);
		gctl_error(req, "Failed to load certificate chain file.");
		return (-1);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) != 1) {
		ERR_print_errors_fp(stderr);
		gctl_error(req, "Failed to load private key file.");
		return (-1);
	}
	if (SSL_CTX_check_private_key(ctx) != 1) {
		ERR_print_errors_fp(stderr);
		gctl_error(req, "Failed to check private key.");
		return (-1);
	}
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
	SSL_CTX_set_cert_verify_callback(ctx, cert_verify_callback, client);
	SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);
	SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
	return (0);
}
#endif

static int
nbd_client_connect(struct nbd_client *client, bool noretry)
{
	struct addrinfo hints, *first_ai, *ai;
	struct gctl_req *req = client->req;
	const char *what;
	int s, on, error;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	error = getaddrinfo(client->host, client->port, &hints, &first_ai);
	if (error != 0) {
		if (noretry)
			gctl_error(req, "Failed to locate server (%s:%s): %s",
			    client->host, client->port, gai_strerror(error));
		return (-1);
	}
	on = 1;
	for (ai = first_ai; ai != NULL; ai = ai->ai_next) {
#if __FreeBSD_version >= 1500000
		if (ai->ai_family == AF_UNIX) {
			what = "UNIX-domain sockets cannot be used as of 15.0";
			error = ENOTSUP;
			continue;
		}
#endif
		s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
		if (s == -1) {
			what = "socket";
			error = errno;
			continue;
		}
		if (ai->ai_family != AF_UNIX) {
			if (setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &on,
			    sizeof(on)) == -1) {
				what = "TCP_NODELAY";
				goto close;
			}
			if (setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &on,
			    sizeof(on)) == -1) {
				what = "SO_KEEPALIVE";
				goto close;
			}
		}
		if (connect(s, ai->ai_addr, ai->ai_addrlen) == -1) {
			what = "connect";
			goto close;
		}
		break;
close:
		error = errno;
		close(s);
		s = -1;
	}
	if (s == -1) {
		freeaddrinfo(first_ai);
		if (noretry)
			gctl_error(req, "Failed to create socket: %s: %s",
			    what, strerror(error));
		return (-1);
	}
	client->socket = s;
	freeaddrinfo(first_ai);
	return (0);
}

static int
nbd_client_send(struct nbd_client *client, const void *buf, size_t buflen)
{
	struct gctl_req *req = client->req;
	ssize_t len;
	int s = client->socket;

	assert(buf != NULL);
	assert(buflen != 0);
	while ((len = send(s, buf, buflen, MSG_NOSIGNAL)) != buflen) {
		if (len > 0) {
			buf += len;
			buflen -= len;
			continue;
		} else if (len == 0) {
			gctl_error(req, "Connection closed.");
			return (-1);
		}
		if (errno == EINTR)
			continue;
		gctl_error(req, "Connection failed: %s", strerror(errno));
		return (-1);
	}
	return (0);
}

static int
nbd_client_recv(struct nbd_client *client, void *buf, size_t buflen)
{
	struct gctl_req *req = client->req;
	ssize_t len;
	int s = client->socket;

	assert(buf != NULL);
	assert(buflen != 0);
	while ((len = recv(s, buf, buflen, MSG_WAITALL)) != buflen) {
		if (len > 0) {
			buf += len;
			buflen -= len;
			continue;
		} else if (len == 0) {
			gctl_error(req, "Connection closed.");
			return (-1);
		}
		if (errno == EINTR)
			continue;
		gctl_error(req, "Connection failed: %s", strerror(errno));
		return (-1);
	}
	return (0);
}

static inline void
nbd_oldstyle_negotiation_ntoh(struct nbd_oldstyle_negotiation *handshake)
{
	handshake->size = be64toh(handshake->size);
	handshake->flags = be32toh(handshake->flags);
}

static inline bool
nbd_oldstyle_negotiation_is_valid(struct nbd_oldstyle_negotiation *handshake)
{
	if ((handshake->flags & NBD_FLAG_HAS_FLAGS) == 0)
		return (false);
	return (true);
}

static int
nbd_client_oldstyle_negotiation(struct nbd_client *client)
{
	struct nbd_oldstyle_negotiation handshake;

	if (nbd_client_recv(client, &handshake, sizeof(handshake)) != 0)
		return (-1);
	nbd_oldstyle_negotiation_ntoh(&handshake);
	if (!nbd_oldstyle_negotiation_is_valid(&handshake)) {
		gctl_error(client->req, "Invalid handshake.");
		return (-1);
	}
	client->size = handshake.size;
#define IGNORED_BITS 0xffff0000
	if ((handshake.flags & IGNORED_BITS) != 0)
		fprintf(stderr, "Ignoring flags in upper nibble: 0x%08x\n",
		    handshake.flags & IGNORED_BITS);
#undef IGNORED_BITS
	client->handshake_flags = handshake.flags;
	return (0);
}

static inline void
nbd_newstyle_negotiation_ntoh(struct nbd_newstyle_negotiation *handshake)
{
	handshake->handshake_flags = be16toh(handshake->handshake_flags);
}

static inline bool
nbd_newstyle_negotiation_is_valid(struct nbd_newstyle_negotiation *handshake)
{
	if ((handshake->handshake_flags & NBD_FLAG_FIXED_NEWSTYLE) == 0)
		return (false);
	return (true);
}

static int
nbd_client_newstyle_negotiation(struct nbd_client *client)
{
	struct nbd_newstyle_negotiation handshake;
	struct nbd_client_flags response;
	uint32_t client_flags;

	if (nbd_client_recv(client, &handshake, sizeof(handshake)) != 0)
		return (-1);
	nbd_newstyle_negotiation_ntoh(&handshake);
	if (!nbd_newstyle_negotiation_is_valid(&handshake)) {
		gctl_error(client->req, "Invalid handshake.");
		return (-1);
	}
	client->handshake_flags = handshake.handshake_flags;
	client_flags = NBD_CLIENT_FLAG_FIXED_NEWSTYLE;
	if ((handshake.handshake_flags & NBD_FLAG_NO_ZEROES) != 0)
		client_flags |= NBD_CLIENT_FLAG_NO_ZEROES;
	memset(&response, 0, sizeof(response));
	response.client_flags = htobe32(client_flags);
	return (nbd_client_send(client, &response, sizeof(response)));
}

static int
nbd_client_send_option(struct nbd_client *client, uint32_t opt,
    const void *data, size_t datalen)
{
	struct nbd_option option;

	memset(&option, 0, sizeof(option));
	option.magic = htobe64(NBD_OPTION_MAGIC);
	option.option = htobe32(opt);
	option.length = htobe32(datalen);
	if (nbd_client_send(client, &option, sizeof(option)) != 0)
		return (-1);
	if (data == NULL || datalen == 0)
		return (0);
	return (nbd_client_send(client, data, datalen));
}

static inline void
nbd_export_info_ntoh(struct nbd_export_info *info)
{
	info->size = be64toh(info->size);
	info->transmission_flags = be16toh(info->transmission_flags);
}

static int
nbd_client_recv_export_info(struct nbd_client *client,
    struct nbd_export_info *info)
{
	static const size_t SHORT_INFO_LEN =
	    sizeof(*info) - sizeof(info->reserved);

	if (nbd_client_recv(client, info, SHORT_INFO_LEN) != 0)
		return (-1);
	nbd_export_info_ntoh(info);
	if ((info->transmission_flags & NBD_FLAG_NO_ZEROES) != 0)
		return (0);
	return (nbd_client_recv(client, info->reserved,
	    sizeof(info->reserved)));
}

static inline void
nbd_option_reply_ntoh(struct nbd_option_reply *reply)
{
	reply->magic = be64toh(reply->magic);
	reply->option = be32toh(reply->option);
	reply->type = be32toh(reply->type);
	reply->length = be32toh(reply->length);
}

static inline bool
nbd_option_reply_is_valid(struct nbd_option_reply *reply, uint32_t opt)
{
	if (reply->magic != NBD_OPTION_REPLY_MAGIC)
		return (false);
	if (reply->option != opt)
		return (false);
	return (true);
}

#ifndef NBD_OPTION_REPLY_LENGTH_LIMIT
#define NBD_OPTION_REPLY_LENGTH_LIMIT (4 * PAGE_SIZE) /* arbitrary safeguard */
#endif

static int
nbd_client_recv_option_reply(struct nbd_client *client,
    struct nbd_option_reply *reply, uint32_t opt)
{
	assert(opt != NBD_OPTION_EXPORT_NAME);
	if (nbd_client_recv(client, reply, sizeof(*reply)) != 0)
		return (-1);
	nbd_option_reply_ntoh(reply);
	if (!nbd_option_reply_is_valid(reply, opt)) {
		gctl_error(client->req, "Invalid option reply.");
		return (-1);
	}
	if (reply->length > NBD_OPTION_REPLY_LENGTH_LIMIT) {
		gctl_error(client->req, "Option reply too long, didn't read.");
		return (-1);
	}
	return (0);
}

#ifdef WITH_OPENSSL
static int
nbd_client_starttls(struct nbd_client *client)
{
	struct nbd_option_reply reply;
	struct gctl_req *req = client->req;
	SSL *ssl;

	if (nbd_client_send_option(client, NBD_OPTION_STARTTLS, NULL, 0) != 0)
		return (-1);
	if (nbd_client_recv_option_reply(client, &reply, NBD_OPTION_STARTTLS)
	    != 0)
		return (-1);
	if (reply.type != NBD_REPLY_ACK) {
		gctl_error(req, "Failed to negotiate TLS.");
		return (-1);
	}
	ssl = SSL_new(client->ssl_ctx);
	if (ssl == NULL) {
		/* TODO: verbose flag */
		ERR_print_errors_fp(stderr);
		gctl_error(req, "Failed to create TLS connection.");
		return (-1);
	}
	if (SSL_set_tlsext_host_name(ssl, client->host) != 1) {
		ERR_print_errors_fp(stderr);
		SSL_free(ssl);
		gctl_error(req, "Failed to set TLS servername extension.");
		return (-1);
	}
	if (SSL_set_fd(ssl, client->socket) != 1) {
		ERR_print_errors_fp(stderr);
		SSL_free(ssl);
		gctl_error(req, "Failed to set TLS socket file descriptor.");
		return (-1);
	}
	if (SSL_connect(ssl) != 1) {
		ERR_print_errors_fp(stderr);
		SSL_free(ssl);
		gctl_error(req, "TLS handshake failed.");
		return (-1);
	}
	if (BIO_get_ktls_send(SSL_get_wbio(ssl)) != 1) {
		SSL_free(ssl);
		gctl_error(req, "Failed to use ktls for send.");
		return (-1);
	}
	if (BIO_get_ktls_recv(SSL_get_rbio(ssl)) != 1) {
		SSL_free(ssl);
		gctl_error(req, "Failed to use ktls for receive.");
		return (-1);
	}
	SSL_free(ssl);
	return (0);
}
#endif

static int
nbd_client_negotiate_fallback(struct nbd_client *client)
{
	struct nbd_export_info info;

	if (nbd_client_send_option(client, NBD_OPTION_EXPORT_NAME,
	    client->name, strlen(client->name)) != 0)
		return (-1);
	if (nbd_client_recv_export_info(client, &info) != 0)
		return (-1);
	client->size = info.size;
	client->transmission_flags = info.transmission_flags;
	return (0);
}

static inline void
nbd_info_export_ntoh(struct nbd_info_export *export)
{
	export->type = be16toh(export->type);
	export->size = be64toh(export->size);
	export->transmission_flags = be16toh(export->transmission_flags);;
}

static inline void
nbd_info_block_size_ntoh(struct nbd_info_block_size *bs)
{
	bs->type = be16toh(bs->type);
	bs->minimum_blocksize = be32toh(bs->minimum_blocksize);
	bs->preferred_blocksize = be32toh(bs->preferred_blocksize);
	bs->maximum_payload = be32toh(bs->maximum_payload);
}

static int
nbd_client_negotiate_options(struct nbd_client *client, bool first)
{
	struct nbd_option_reply reply;
	struct gctl_req *req = client->req;
	uint8_t *buf, *p;
	uint16_t info_requests[] = {
		htobe16(NBD_INFO_EXPORT),
		htobe16(NBD_INFO_NAME),
		htobe16(NBD_INFO_DESCRIPTION),
		htobe16(NBD_INFO_BLOCK_SIZE),
	};
	uint32_t namelen = strlen(client->name);
	uint32_t be_namelen = htobe32(namelen);
	uint16_t n_info_requests = first ? nitems(info_requests) : 1;
	uint16_t be_n_info_requests = htobe16(n_info_requests);
	size_t buflen = sizeof(be_namelen) + namelen +
	    sizeof(be_n_info_requests) +
	    sizeof(info_requests[0]) * n_info_requests;

	/*
	 * Try to negotiate structured replies by default, but allow the user
	 * to opt out.  Fall back to simple replies if the server refuses the
	 * option.  The kernel handles all replies based on the reply header,
	 * regardless of what was negotiated.
	 */
	if (gctl_get_int(req, "simple") == 0) {
		if (nbd_client_send_option(client, NBD_OPTION_STRUCTURED_REPLY,
		    NULL, 0) != 0)
			return (-1);
		if (nbd_client_recv_option_reply(client, &reply,
		    NBD_OPTION_STRUCTURED_REPLY) != 0)
			return (-1);
		if (reply.type != NBD_REPLY_ACK)
			/* TODO: verbosity control */
			fprintf(stderr,
			    "Server rejected structured reply option\n");
	}
	p = buf = malloc(buflen);
	assert(buf != NULL); /* can't do much if ENOMEM */
	p = mempcpy(p, &be_namelen, sizeof(be_namelen));
	p = mempcpy(p, client->name, namelen);
	p = mempcpy(p, &be_n_info_requests, sizeof(be_n_info_requests));
	memcpy(p, info_requests, sizeof(info_requests[0]) * n_info_requests);
	if (nbd_client_send_option(client, NBD_OPTION_GO, buf, buflen) != 0) {
		free(buf);
		return (-1);
	}
	free(buf);
	for (bool saw_export = false;;) {
		uint16_t info_type;

		if (nbd_client_recv_option_reply(client, &reply, NBD_OPTION_GO)
		    != 0)
			return (-1);
		if (reply.type == NBD_REPLY_ACK) {
			if (!saw_export) {
				gctl_error(req,
				    "Negotiation ended prematurely.");
				return (-1);
			}
			return (0);
		}
		if ((reply.type & NBD_REPLY_ERROR) != 0) {
			if (reply.length > 0) {
				buf = malloc(reply.length);
				assert(buf != NULL);
				if (nbd_client_recv(client, buf, reply.length)
				    != 0)
					return (-1);
				switch (reply.type) {
				case NBD_REPLY_ERROR_UNSUPPORTED:
				case NBD_REPLY_ERROR_TLS_REQUIRED:
					break;
				default:
					gctl_error(req,
					    "Negotiation failed: %.*s",
					    reply.length, buf);
					break;
				}
				free(buf);
			}
			if (reply.type == NBD_REPLY_ERROR_TLS_REQUIRED)
				gctl_error(req, "Negotiation failed: "
				    "TLS required for this export");
			if (reply.type == NBD_REPLY_ERROR_UNSUPPORTED)
				return (nbd_client_negotiate_fallback(client));
			return (-1);
		}
		if (reply.type != NBD_REPLY_INFO) {
			gctl_error(req, "Unexpected option reply type.");
			return (-1);
		}
		assert(reply.length >= 2);
		buf = malloc(reply.length);
		assert(buf != NULL);
		if (nbd_client_recv(client, buf, reply.length) != 0) {
			free(buf);
			return (-1);
		}
		info_type = be16toh(*(uint16_t *)buf);
		switch (info_type) {
		case NBD_INFO_EXPORT: {
			struct nbd_info_export *export = (void *)buf;

			nbd_info_export_ntoh(export);
			client->size = export->size;
			client->transmission_flags = export->transmission_flags;
			saw_export = true;
			break;
		}
		case NBD_INFO_NAME: {
			struct nbd_info_name *name = (void *)buf;
			char *namebuf, *namep = (void *)(name + 1);

			asprintf(&namebuf, "%.*s",
			    reply.length - (int)sizeof(*name), namep);
			assert(namebuf != NULL);
			free(__DECONST(char *, client->name));
			client->name = namebuf;
			break;
		}
		case NBD_INFO_DESCRIPTION: {
			struct nbd_info_description *desc = (void *)buf;
			char *descbuf, *descp = (void *)(desc + 1);

			asprintf(&descbuf, "%.*s",
			    reply.length - (int)sizeof(*desc), descp);
			assert(descbuf != NULL);
			free(__DECONST(char *, client->description));
			client->description = descbuf;
			break;
		}
		case NBD_INFO_BLOCK_SIZE: {
			struct nbd_info_block_size *bs = (void *)buf;

			nbd_info_block_size_ntoh(bs);
			client->minimum_blocksize = bs->minimum_blocksize;
			client->preferred_blocksize = bs->preferred_blocksize;
			client->maximum_payload = bs->maximum_payload;
			break;
		}
		default:
			/* ignore unexpected info */
			break;
		}
		free(buf);
	}
	__unreachable();
}

static inline void
nbd_handshake_ntoh(struct nbd_handshake *handshake)
{
	handshake->magic = be64toh(handshake->magic);
	handshake->style = be64toh(handshake->style);
}

static int
nbd_client_negotiate(struct nbd_client *client, bool first)
{
	struct nbd_handshake handshake;
	struct gctl_req *req = client->req;
	ssize_t len;

	if (nbd_client_recv(client, &handshake, sizeof(handshake)) != 0)
		return (-1);
	nbd_handshake_ntoh(&handshake);
	if (handshake.magic != NBD_MAGIC) {
		gctl_error(req, "Handshake failed: invalid magic");
		return (-1);
	}
	if (handshake.style == NBD_OLDSTYLE_MAGIC) {
#ifdef WITH_OPENSSL
		if (client->ssl_ctx != NULL) {
			gctl_error(req, "Server does not support TLS.");
			return (-1);
		}
#endif
		return (nbd_client_oldstyle_negotiation(client));
	} else if (handshake.style == NBD_NEWSTYLE_MAGIC) {
		if (nbd_client_newstyle_negotiation(client) != 0)
			return (-1);
#ifdef WITH_OPENSSL
		if (client->ssl_ctx != NULL && nbd_client_starttls(client) != 0)
			return (-1);
#endif
		return (nbd_client_negotiate_options(client, first));
	}
	gctl_error(req, "Handshake failed: unknown style");
	return (-1);
}

static int *
make_connections(struct nbd_client *client, struct gctl_req *req, int nsockets,
    int delay)
{
	struct rlimit nofile;
	int *sockets;
	bool noretry = delay <= 0;

	if (getrlimit(RLIMIT_NOFILE, &nofile) != 0) {
		gctl_error(req, "Failed to get resource limits.");
		return (NULL);
	}
	if (nsockets > nofile.rlim_cur - 4 /* stdin, stdout, stderr, gctl */) {
		gctl_error(req, "Number of connections exceeds limits.");
		return (NULL);
	}
	thr_self(&client->tid);
	gctl_ro_param(req, "thread", sizeof(client->tid), &client->tid);
	sockets = malloc(sizeof(*sockets) * nsockets);
	assert(sockets != NULL); /* can't do much if ENOMEM */
	for (int i = 0; i < nsockets; i++) {
		while (nbd_client_connect(client, noretry) != 0) {
			if (noretry) {
				while (i > 0)
					close(sockets[--i]);
				free(sockets);
				return (NULL);
			}
			sleep(delay);
		}
		sockets[i] = client->socket;
		if (nbd_client_negotiate(client, i == 0) != 0) {
			while (i >= 0)
				close(sockets[i--]);
			free(sockets);
			return (NULL);
		}
	}
	gctl_ro_param(req, "sockets", sizeof(*sockets) * nsockets, sockets);
	return (sockets);
}

static int
issue(struct gctl_req *req)
{
	const char *errstr;

	errstr = gctl_issue(req);
	if (errstr != NULL) {
		/*
		 * XXX: Work around gctl_issue() setting req->error to an empty
		 * string and req->nerror to 0 while returning an actual error
		 * string for errno.
		 */
		if (req->error != NULL && req->error[0] == '\0') {
			req->nerror = errno;
			strlcpy(req->error, errstr, req->lerror + 1);
		}
		return (-1);
	}
	return (0);
}

/*
 * TODO: verbose output
 */
static void
nbd_connect(struct gctl_req *req, unsigned flags)
{
	char provider[PATH_MAX];
	struct nbd_client client = {};
	const char *name;
	int *sockets = NULL;
	intmax_t nconns;
	int nargs;
	bool tls = false;

	nargs = gctl_get_int(req, "nargs");
	if (nargs != 1) {
		gctl_error(req, "Invalid number of arguments.");
		return;
	}
	nconns = gctl_get_intmax(req, "connections");
	if (nconns < 1) {
		gctl_error(req, "Invalid number of connections.");
		return;
	}
	client.req = req;
	client.host = gctl_get_ascii(req, "arg0");
	client.port = gctl_get_ascii(req, "port");
#ifdef WITH_OPENSSL
	if (nbd_client_tls_init(&client) != 0)
		return;
	tls = client.ssl_ctx != NULL;
#endif
	gctl_ro_param(req, "tls", sizeof(tls), &tls);
	client.name = strdup(gctl_get_ascii(req, "name"));
	assert(client.name != NULL); /* can't do much if ENOMEM */
	sockets = make_connections(&client, req, nconns, 0);
	if (sockets == NULL)
		goto free;
	if ((client.transmission_flags & NBD_FLAG_CAN_MULTI_CONN) == 0 &&
	    nconns > 1) {
		gctl_error(req, "Server does not allow multiple connections.");
		goto close;
	}
	gctl_ro_param(req, "host", -1, client.host);
	gctl_ro_param(req, "port", -1, client.port);
	gctl_change_param(req, "name", -1, client.name);
	if (client.description != NULL)
		gctl_ro_param(req, "description", -1, client.description);
	gctl_ro_param(req, "size", sizeof(client.size), &client.size);
	gctl_ro_param(req, "flags", sizeof(client.flags), &client.flags);
	gctl_ro_param(req, "minimum_blocksize",
	    sizeof(client.minimum_blocksize), &client.minimum_blocksize);
	gctl_ro_param(req, "preferred_blocksize",
	    sizeof(client.preferred_blocksize), &client.preferred_blocksize);
	gctl_ro_param(req, "maximum_payload", sizeof(client.maximum_payload),
	    &client.maximum_payload);
	gctl_rw_param(req, "provider", sizeof(provider), provider);
	if (issue(req) != 0)
		goto close;
	provider[sizeof(provider) - 1] = '\0';
	puts(provider);
close:
	for (int i = 0; i < nconns; i++)
		close(sockets[i]); /* the kernel keeps its own ref */
free:
#ifdef WITH_OPENSSL
	SSL_CTX_free(client.ssl_ctx);
#endif
	free(sockets);
	free(__DECONST(char *, client.name));
	free(__DECONST(char *, client.description));
}

static inline void
nbd_option_reply_server_ntoh(struct nbd_option_reply_server *server_export)
{
	server_export->length = be32toh(server_export->length);
}

static int
nbd_client_list(struct nbd_client *client, nbd_client_list_cb cb, void *ctx)
{
	struct nbd_handshake handshake;
	struct nbd_option_reply reply;
	struct nbd_option_reply_server server_export;
	struct gctl_req *req = client->req;
	char *name, *description;
	size_t resid;
	ssize_t len;
	int s = client->socket;

	if (nbd_client_recv(client, &handshake, sizeof(handshake)) != 0)
		return (-1);
	nbd_handshake_ntoh(&handshake);
	if (handshake.magic != NBD_MAGIC) {
		gctl_error(req, "Handshake failed: invalid magic");
		return (-1);
	}
	if (handshake.style == NBD_OLDSTYLE_MAGIC) {
		puts("[default export]");
		return (0);
	}
	if (handshake.style != NBD_NEWSTYLE_MAGIC) {
		gctl_error(req, "Handshake failed: unknown style");
		return (-1);
	}
	if (nbd_client_newstyle_negotiation(client) != 0)
		return (-1);
#ifdef WITH_OPENSSL
	if (client->ssl_ctx != NULL && nbd_client_starttls(client) != 0)
		return (-1);
#endif
	if (nbd_client_send_option(client, NBD_OPTION_LIST, NULL, 0) != 0)
		return (-1);
	for (;;) {
		if (nbd_client_recv_option_reply(client, &reply,
		    NBD_OPTION_LIST) != 0)
			return (-1);
		if (reply.type == NBD_REPLY_ACK)
			break;
		if ((reply.type & NBD_REPLY_ERROR) != 0) {
			if (reply.length == 0)
				gctl_error(req, "Listing exports failed (%d)",
				    reply.type);
			else {
				uint8_t *buf;

				buf = malloc(reply.length);
				assert(buf != NULL);
				if (nbd_client_recv(client, buf, reply.length)
				    != 0)
					return (-1);
				gctl_error(req, "Listing exports failed: %.*s",
				    reply.length, buf);
				free(buf);
			}
			return (-1);
		}
		if (reply.type != NBD_REPLY_SERVER) {
			gctl_error(req, "Unexpected option reply type.");
			return (-1);
		}
		if (nbd_client_recv(client, &server_export,
		    sizeof(server_export)) != 0)
			return (-1);
		nbd_option_reply_server_ntoh(&server_export);
		assert((server_export.length + 4) <= reply.length);
		if (server_export.length == 0)
			name = NULL;
		else {
			resid = server_export.length;
			name = malloc(resid + 1);
			assert(name != NULL); /* hard to handle ENOMEM */
			if (nbd_client_recv(client, name, resid) != 0) {
				free(name);
				return (-1);
			}
			name[resid] = '\0';
		}
		resid = reply.length - (4 + server_export.length);
		if (resid == 0)
			description = NULL;
		else {
			description = malloc(resid + 1);
			assert(description != NULL); /* hard to handle ENOMEM */
			if (nbd_client_recv(client, description, resid) != 0) {
				free(description);
				free(name);
				return (-1);
			}
			description[resid] = '\0';
		}
		if (cb(ctx, name, description) != 0)
			return (-1);
	}
	return (0);
}

static int
list_callback(void *ctx __unused, char *name, char *description)
{
	if (name == NULL)
		printf("[default export]");
	else {
		printf("%s", name);
		free(name);
	}
	if (description == NULL)
		printf("\n");
	else {
		printf("\t%s\n", description);
		free(description);
	}
	/* TODO: verbosity control, more export info */
	return (0);
}

static int
nbd_client_abort(struct nbd_client *client)
{
	struct nbd_option_reply reply;
	struct nbd_option_reply_server server_export;
	struct gctl_req *req = client->req;

	if (nbd_client_send_option(client, NBD_OPTION_ABORT, NULL, 0) != 0)
		return (-1);
	if (nbd_client_recv_option_reply(client, &reply, NBD_OPTION_ABORT) != 0)
		return (-1);
	if (reply.type == NBD_REPLY_ACK)
		return (0);
	if ((reply.type & NBD_REPLY_ERROR) != 0) {
		if (reply.length == 0)
			gctl_error(req, "Abort option failed (%d)", reply.type);
		else {
			uint8_t *buf;

			buf = malloc(reply.length);
			assert(buf != NULL);
			if (nbd_client_recv(client, buf, reply.length)
			    != 0)
				return (-1);
			gctl_error(req, "Abort option failed: %.*s",
			    reply.length, buf);
			free(buf);
		}
		return (-1);
	}
	gctl_error(req, "Unexpected option reply type.");
	return (-1);
}

static void
nbd_client_shutdown(struct nbd_client *client)
{
	shutdown(client->socket, SHUT_RDWR);
}

static void
nbd_list(struct gctl_req *req, unsigned flags)
{
	struct nbd_client client = {};
	int nargs;

	nargs = gctl_get_int(req, "nargs");
	if (nargs != 1) {
		gctl_error(req, "Invalid number of arguments.");
		return;
	}
	client.req = req;
	client.host = gctl_get_ascii(req, "arg0");
	client.port = gctl_get_ascii(req, "port");
#ifdef WITH_OPENSSL
	if (nbd_client_tls_init(&client) != 0)
		return;
#endif
	if (nbd_client_connect(&client, true) != 0)
		return;
	if (nbd_client_list(&client, list_callback, NULL) != 0)
		return;
	if (nbd_client_abort(&client) != 0)
		return;
	nbd_client_shutdown(&client);
	close(client.socket);
}

static struct gclass *
find_class(struct gmesh *mesh, const char *name)
{
	struct gclass *mp;

	LIST_FOREACH(mp, &mesh->lg_class, lg_class)
		if (strcmp(mp->lg_name, name) == 0)
			return (mp);
	return (NULL);
}

static bool
geom_is_withered(struct ggeom *gp)
{
	struct gconfig *gc;

	LIST_FOREACH(gc, &gp->lg_config, lg_config)
		if (strcmp(gc->lg_name, "wither") == 0)
			return (true);
	return (false);
}

static struct ggeom *
find_geom(struct gclass *mp, const char *name)
{
	struct ggeom *gp, *wgp = NULL;

	if (strncmp(name, _PATH_DEV, sizeof(_PATH_DEV) - 1) == 0)
		name += sizeof(_PATH_DEV) - 1;
	LIST_FOREACH(gp, &mp->lg_geom, lg_geom) {
		if (strcmp(gp->lg_name, name) != 0)
			continue;
		if (!geom_is_withered(gp))
			return (gp);
		wgp = gp;
	}
	return (wgp);
}

static const char *
find_config(struct ggeom *gp, const char *name)
{
	struct gconfig *gc;

	LIST_FOREACH(gc, &gp->lg_config, lg_config) {
		if (strcmp(gc->lg_name, name) == 0) {
			if (gc->lg_val == NULL)
				/* libgeom replaced "" with NULL */
				return ("");
			return (gc->lg_val);
		}
	}
	return (NULL);
}

static void
scale_common(struct gctl_req *req, bool reconnect)
{
	struct nbd_client client = {};
	struct gmesh mesh;
	struct gclass *mp;
	struct ggeom *gp;
	const char *classname, *geomname, *name, *simple;
	const char *active, *connections, *tflags, *cfgtls;
	int *sockets = NULL;
	intmax_t nconns, delay;
	int nargs, nactive, nsockets, bsimple;
	bool tls;

	nargs = gctl_get_int(req, "nargs");
	if (nargs != 1) {
		gctl_error(req, "Invalid number of arguments.");
		return;
	}
	classname = gctl_get_ascii(req, "class");
	geomname = gctl_get_ascii(req, "arg0");
	if (geom_gettree_geom(&mesh, classname, geomname, 0) != 0) {
		gctl_error(req, "Cannot get GEOM tree.");
		return;
	}
	mp = find_class(&mesh, classname);
	if (mp == NULL) {
		gctl_error(req, "Cannot find GEOM class.");
		goto free;
	}
	gp = find_geom(mp, geomname);
	if (gp == NULL) {
		gctl_error(req, "Cannot find GEOM '%s'.", geomname);
		goto free;
	}
	active = find_config(gp, "ActiveConnections");
	if (active == NULL) {
		gctl_error(req, "Invalid config (missing ActiveConnections).");
		goto free;
	}
	errno = 0;
	nactive = strtol(active, NULL, 10);
	if (errno != 0) {
		gctl_error(req, "Invalid config (invalid ActiveConnections).");
		goto free;
	}
	if (reconnect) {
		delay = gctl_get_intmax(req, "seconds");
		connections = find_config(gp, "Connections");
		if (connections == NULL) {
			gctl_error(req,
			    "Invalid config (missing Connections).");
			goto free;
		}
		errno = 0;
		nconns = strtol(connections, NULL, 10);
		if (errno != 0) {
			gctl_error(req,
			    "Invalid config (invalid Connections).");
			goto free;
		}
		if (nconns <= nactive)
			/* Nothing to do. */
			goto free;
		gctl_ro_param(req, "connections", sizeof(nconns), &nconns);
		gctl_change_param(req, "verb", -1, "scale");
	} else {
		delay = 0;
		nconns = gctl_get_intmax(req, "connections");
		if (nconns < 1) {
			gctl_error(req, "Invalid number of connections.");
			goto free;
		}
		if (nconns <= nactive) {
			/* No new connections needed. */
			issue(req);
			goto free;
		}
		tflags = find_config(gp, "TransmissionFlags");
		if (tflags == NULL) {
			gctl_error(req,
			    "Invalid config (missing TransmissionFlags).");
			goto free;
		}
		if (strstr(tflags, "CAN_MULTI_CONN") == NULL && nconns > 1) {
			gctl_error(req,
			    "Server does not allow multiple connections.");
			goto free;
		}
	}
	nsockets = nconns - nactive;
	assert(nsockets > 0);
	client.req = req;
	client.host = find_config(gp, "Host");
	if (client.host == NULL) {
		gctl_error(req, "Invalid config (missing Host).");
		goto free;
	}
	client.port = find_config(gp, "Port");
	if (client.port == NULL) {
		gctl_error(req, "Invalid config (missing Port).");
		goto free;
	}
	cfgtls = find_config(gp, "TLS");
	if (cfgtls == NULL) {
		gctl_error(req, "Invalid config (missing TLS).");
		goto free;
	}
	tls = strcmp(cfgtls, "yes") == 0;
#ifdef WITH_OPENSSL
	if (nbd_client_tls_init(&client) != 0)
		goto free;
	if (tls && client.ssl_ctx == NULL) {
		gctl_error(req, "TLS is used on this device.");
		goto free;
	}
	if (!tls && client.ssl_ctx != NULL) {
		gctl_error(req, "TLS is not used on this device.");
		goto free;
	}
#else
	if (tls) {
		gctl_error(req, "TLS is used on this device.");
		goto free;
	}
#endif
	name = find_config(gp, "Name");
	if (name == NULL) {
		gctl_error(req, "Invalid config (missing Name).");
		goto free;
	}
	client.name = strdup(name);
	assert(client.name != NULL); /* can't do much if ENOMEM */
	simple = find_config(gp, "Simple");
	if (simple == NULL) {
		gctl_error(req, "Invalid config (missing Simple).");
		goto free;
	}
	bsimple = strcmp(simple, "yes") == 0;
	gctl_ro_param(req, "simple", sizeof(bsimple), &bsimple);
	sockets = make_connections(&client, req, nsockets, delay);
	if (sockets == NULL)
		goto free;
	gctl_ro_param(req, "nsockets", sizeof(nsockets), &nsockets);
	issue(req);
	for (int i = 0; i < nsockets; i++)
		close(sockets[i]); /* the kernel keeps its own ref */
free:
#ifdef WITH_OPENSSL
	SSL_CTX_free(client.ssl_ctx);
#endif
	free(sockets);
	/* Didn't ask for these, but in case we got them anyway... */
	free(__DECONST(char *, client.name));
	free(__DECONST(char *, client.description));
	geom_deletetree(&mesh);
}

static void
nbd_reconnect(struct gctl_req *req, unsigned flags)
{
	scale_common(req, true);
}

static void
nbd_scale(struct gctl_req *req, unsigned flags)
{
	scale_common(req, false);
}

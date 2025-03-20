/*
 * Copyright (c) 2025 Ryan Moeller
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */ 

#include <sys/param.h>
#include <sys/endian.h>
#include <sys/socket.h>
#include <sys/thr.h>

#include <assert.h>
#include <err.h>
#include <errno.h>
#include <netdb.h>
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
static void nbd_scale(struct gctl_req *req, unsigned flags);
static void nbd_info(struct gctl_req *req, unsigned flags);

/* TODO: connect to multiple given names, list, connect to all */
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
		{ 'c', "connections", "1", G_TYPE_NUMBER },
		{ 'n', "name", "", G_TYPE_STRING },
		{ 'p', "port", NBD_DEFAULT_PORT, G_TYPE_STRING },
#ifdef WITH_OPENSSL
		TLS_OPTS,
#endif
		G_OPT_SENTINEL
	    },
	    "[-c num] [-n name] [-p port] "
#ifdef WITH_OPENSSL
	    TLS_USAGE
#endif
	    "host"
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
	{ "info", 0, nbd_info,
	    { G_OPT_SENTINEL },
	    "prov"
	},
	{ "disconnect", 0, NULL,
	    {
		{ 'f', "force", NULL, G_TYPE_BOOL },
		G_OPT_SENTINEL
	    },
	    "[-f] prov"
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
#ifdef WITH_OPENSSL
	SSL_CTX *ssl_ctx;
#endif
};

#ifdef WITH_OPENSSL
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
	SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);
	SSL_CTX_set_min_proto_version(ctx, TLS1_VERSION);
	return (0);
}
#endif

static int
nbd_client_connect(struct nbd_client *client)
{
	struct gctl_req *req = client->req;
	struct addrinfo *first_ai, *ai;
	int s, on, error;

	error = getaddrinfo(client->host, client->port, NULL, &first_ai);
	if (error != 0) {
		gctl_error(req, "Failed to locate server (%s:%s): %s",
		    client->host, client->port, gai_strerror(error));
		return (-1);
	}
	on = 1;
	for (ai = first_ai; ai != NULL; ai = ai->ai_next) {
		s = socket(ai->ai_family, SOCK_STREAM, IPPROTO_TCP);
		if (s == -1)
			continue;
		if (setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on))
		    == -1)
			goto close;
		if (setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on))
		    == -1)
			goto close;
		if (connect(s, ai->ai_addr, sizeof(*ai->ai_addr)) == -1)
			goto close;
		break;
close:
		close(s);
		s = -1;
	}
	if (s == -1) {
		freeaddrinfo(first_ai);
		gctl_error(req, "Failed to create socket: %s",
		    strerror(errno));
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
	/* TODO: not clear if we need to set a servername callback on client */
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
	/* TODO: verify peer host name matches certificate? */
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

/*
 * TODO: structured replies
 */
static int
nbd_client_negotiate_options(struct nbd_client *client, bool first)
{
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
		struct nbd_option_reply reply;
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
					    "Negotiation failed: %*s",
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
		/* TODO: sanitize lengths throughout */
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

			asprintf(&namebuf, "%*s", reply.length - 2, namep);
			assert(namebuf != NULL);
			free(__DECONST(char *, client->name));
			client->name = namebuf;
			break;
		}
		case NBD_INFO_DESCRIPTION: {
			struct nbd_info_description *desc = (void *)buf;
			char *descbuf, *descp = (void *)(desc + 1);

			asprintf(&descbuf, "%*s", reply.length - 2, descp);
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
	int s = client->socket;

	while ((len = recv(s, &handshake, sizeof(handshake),
	    MSG_WAITALL)) != sizeof(handshake)) {
		if (len == -1) {
			if (errno == EINTR)
				continue;
			gctl_error(req, "Connection failed: %s",
			    strerror(errno));
			return (-1);
		}
	}
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

/*
 * TODO: verbose output, connect all listed by server
 */
static void
nbd_connect(struct gctl_req *req, unsigned flags)
{
	char provider[PATH_MAX];
	struct nbd_client client = {};
	int *sockets = NULL;
	intmax_t nconns;
	int nargs, nsockets;
	long tid;
	bool tls = false;

	nargs = gctl_get_int(req, "nargs");
	if (nargs != 1) {
		gctl_error(req, "Invalid number of arguments.");
		return;
	}
	nconns = gctl_get_intmax(req, "connections");
	/* TODO: could check process limits for max */
	if (nconns < 1) {
		gctl_error(req, "Invalid number of connections.");
		return;
	}
	nsockets = nconns;
	thr_self(&tid);
	gctl_ro_param(req, "thread", sizeof(tid), &tid);
	client.req = req;
	client.host = gctl_get_ascii(req, "arg0");
	client.port = gctl_get_ascii(req, "port");
#ifdef WITH_OPENSSL
	if (nbd_client_tls_init(&client) != 0)
		return;
	tls = client.ssl_ctx != NULL;
#endif
	gctl_ro_param(req, "tls", sizeof(tls), &tls);
	/*
	 * Default client properties that may be overridden by negotiation.
	 */
	client.minimum_blocksize = 1 << 9;	/* 512 */
	client.preferred_blocksize = 1 << 12;	/* 4096 */
	client.maximum_payload = 1 << 25;	/* 33554432 */
	sockets = malloc(sizeof(*sockets) * nsockets);
	assert(sockets != NULL); /* can't do much if ENOMEM */
	for (int i = 0; i < nsockets; i++) {
		if (nbd_client_connect(&client) != 0) {
			while (i-- > 0)
				close(sockets[i]);
			goto free;
		}
		sockets[i] = client.socket;
		if (client.name == NULL) {
			/* May be overridden during negotiation. */
			client.name = strdup(gctl_get_ascii(req, "name"));
			assert(client.name != NULL); /* can't do much */
		}
		if (nbd_client_negotiate(&client, i == 0) != 0)
			goto close;
	}
	if ((client.transmission_flags & NBD_FLAG_CAN_MULTI_CONN) == 0 &&
	    nsockets > 1) {
		gctl_error(req, "Server does not allow multiple connections.");
		goto close;
	}
	gctl_ro_param(req, "sockets", sizeof(*sockets) * nsockets, sockets);
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
	gctl_issue(req);
	provider[sizeof(provider) - 1] = '\0';
	puts(provider);
close:
	for (int i = 0; i < nsockets; i++)
		close(sockets[i]); /* the kernel keeps its own ref */
free:
#ifdef WITH_OPENSSL
	SSL_CTX_free(client.ssl_ctx);
#endif
	free(sockets);
	free(__DECONST(char *, client.name));
	free(__DECONST(char *, client.description));
}

static void
nbd_scale(struct gctl_req *req, unsigned flags)
{
	char name[PATH_MAX], host[PATH_MAX], port[32];
	struct nbd_client client = {};
	int *sockets = NULL;
	intmax_t nconns;
	union {
		uint32_t flags;
		struct {
			uint16_t handshake_flags;
			uint16_t transmission_flags;
		};
	} flags1;
	int nargs, nsockets;
	long tid;
	bool tls;

	nargs = gctl_get_int(req, "nargs");
	if (nargs != 1) {
		gctl_error(req, "Invalid number of arguments.");
		return;
	}
	nconns = gctl_get_intmax(req, "connections");
	/* TODO: could check process limits for max */
	if (nconns < 1) {
		gctl_error(req, "Invalid number of connections.");
		return;
	}
	gctl_change_param(req, "verb", -1, "info");
	gctl_rw_param(req, "name", sizeof(name), name);
	gctl_rw_param(req, "host", sizeof(host), host);
	gctl_rw_param(req, "port", sizeof(port), port);
	gctl_rw_param(req, "flags", sizeof(flags1), &flags1);
	gctl_rw_param(req, "tls", sizeof(tls), &tls);
	gctl_rw_param(req, "nsockets", sizeof(nsockets), &nsockets);
	gctl_issue(req);
	if (req->nerror != 0)
		return;
	if (req->error != NULL) {
		if (strcmp(req->error, "Could not allocate memory") != 0)
			free(req->error);
		req->error = NULL;
	}
	gctl_change_param(req, "verb", -1, "scale");
	gctl_delete_param(req, "name");
	gctl_delete_param(req, "host");
	gctl_delete_param(req, "port");
	gctl_delete_param(req, "flags");
	gctl_delete_param(req, "tls");
	gctl_delete_param(req, "nsockets");
	if ((flags1.transmission_flags & NBD_FLAG_CAN_MULTI_CONN) == 0 &&
	    nconns > 1) {
		gctl_error(req, "Server does not allow multiple connections.");
		return;
	}
	if (nsockets == nconns)
		/* Nothing to do. */
		return;
	if (nsockets > nconns) {
		/* Scale down. */
		gctl_issue(req);
		return;
	}
	nsockets = nconns - nsockets;
	assert(nsockets > 0);
	thr_self(&tid);
	gctl_ro_param(req, "thread", sizeof(tid), &tid);
	client.req = req;
	client.host = host;
	client.port = port;
#ifdef WITH_OPENSSL
	if (nbd_client_tls_init(&client) != 0)
		return;
	if (tls && client.ssl_ctx == NULL) {
		gctl_error(req, "TLS is used on this device.");
		return;
	}
	if (!tls && client.ssl_ctx != NULL) {
		gctl_error(req, "TLS is not used on this device.");
		return;
	}
#else
	if (tls) {
		gctl_error(req, "TLS is used on this device.");
		return;
	}
#endif
	client.name = strdup(name);
	assert(client.name != NULL); /* can't do much if ENOMEM */
	sockets = malloc(sizeof(*sockets) * nsockets);
	assert(sockets != NULL); /* can't do much if ENOMEM */
	for (int i = 0; i < nsockets; i++) {
		if (nbd_client_connect(&client) != 0) {
			while (i-- > 0)
				close(sockets[i]);
			goto free;
		}
		sockets[i] = client.socket;
		if (nbd_client_negotiate(&client, false) != 0)
			goto close;
	}
	gctl_ro_param(req, "nsockets", sizeof(nsockets), &nsockets);
	gctl_ro_param(req, "sockets", sizeof(*sockets) * nsockets, sockets);
	gctl_issue(req);
close:
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
}

static void
nbd_info(struct gctl_req *req, unsigned flags)
{
	char description[PAGE_SIZE]; /* oof */
	char name[PATH_MAX];
	char host[PATH_MAX];
	char port[32];
	uint64_t size;
	union {
		uint32_t flags;
		struct {
			uint16_t handshake_flags;
			uint16_t transmission_flags;
		};
	} flags1;
	uint32_t minblocksize;
	uint32_t prefblocksize;
	uint32_t maxpayload;
	u_int nsockets;
	int nargs;
	bool tls;

	nargs = gctl_get_int(req, "nargs");
	if (nargs != 1) {
		gctl_error(req, "Invalid number of arguments.");
		return;
	}
	gctl_rw_param(req, "name", sizeof(name), name);
	gctl_rw_param(req, "host", sizeof(host), host);
	gctl_rw_param(req, "port", sizeof(port), port);
	gctl_rw_param(req, "description", sizeof(description), description);
	gctl_rw_param(req, "size", sizeof(size), &size);
	gctl_rw_param(req, "flags", sizeof(flags1), &flags1);
	gctl_rw_param(req, "tls", sizeof(tls), &tls);
	gctl_rw_param(req, "minblocksize", sizeof(minblocksize), &minblocksize);
	gctl_rw_param(req, "prefblocksize", sizeof(prefblocksize),
	    &prefblocksize);
	gctl_rw_param(req, "maxpayload", sizeof(maxpayload), &maxpayload);
	gctl_rw_param(req, "nsockets", sizeof(nsockets), &nsockets);
	gctl_issue(req);
	name[sizeof(name) - 1] = '\0';
	description[sizeof(description) - 1] = '\0';
	host[sizeof(host) - 1] = '\0';
	port[sizeof(port) - 1] = '\0';
	printf("Name: %s\n", name);
	printf("Description: %s\n", description);
	printf("Host: %s\n", host);
	printf("Port: %s\n", port);
	printf("Size: %zd\n", size);
#define NBD_FLAG(id) { NBD_FLAG_ ## id, #id }
	printf("Handshake flags: 0x%04x", flags1.handshake_flags);
	if (flags1.handshake_flags != 0) {
		const struct { uint16_t flag; const char *name; } names[] = {
			NBD_FLAG(FIXED_NEWSTYLE),
			NBD_FLAG(NO_ZEROES),
		};
		uint32_t unknown, check = 0;
		int i;

		printf("<");
		for (i = 0; i < nitems(names); i++) {
			uint16_t flag = names[i].flag;

			if ((flags1.handshake_flags & flag) != 0) {
				printf("%s%s", check != 0 ? "," : "", names[i].name);
				check |= flag;
			}
		}
		unknown = flags1.handshake_flags & ~check;
		if (unknown != 0)
			printf("%s0x%x", check != 0 ? "," : "", unknown);
		printf(">");
	}
	printf("\n");
	printf("Transmission flags: 0x%04x", flags1.transmission_flags);
	if (flags1.transmission_flags != 0) {
		const struct { uint16_t flag; const char *name; } names[] = {
			NBD_FLAG(HAS_FLAGS),
			NBD_FLAG(READ_ONLY),
			NBD_FLAG(SEND_FLUSH),
			NBD_FLAG(SEND_FUA),
			NBD_FLAG(ROTATIONAL),
			NBD_FLAG(SEND_TRIM),
			NBD_FLAG(SEND_WRITE_ZEROES),
			NBD_FLAG(SEND_DF),
			NBD_FLAG(CAN_MULTI_CONN),
			NBD_FLAG(SEND_RESIZE),
			NBD_FLAG(SEND_CACHE),
			NBD_FLAG(SEND_FAST_ZERO),
			NBD_FLAG(BLOCK_STATUS_PAYLOAD),
		};
		uint32_t unknown, check = 0;
		int i;

		printf("<");
		for (i = 0; i < nitems(names); i++) {
			uint16_t flag = names[i].flag;

			if ((flags1.transmission_flags & flag) != 0) {
				printf("%s%s", check != 0 ? "," : "", names[i].name);
				check |= flag;
			}
		}
		unknown = flags1.transmission_flags & ~check;
		if (unknown != 0)
			printf("%s0x%x", check != 0 ? "," : "", unknown);
		printf(">");
	}
	printf("\n");
#undef NBD_FLAG
	printf("TLS: %s\n", tls ? "yes" : "no");
	printf("Minimum block size: %u\n", minblocksize);
	printf("Preferred block size: %u\n", prefblocksize);
	printf("Maximum payload: %u\n", maxpayload);
	printf("Number of connections: %u\n", nsockets);
}

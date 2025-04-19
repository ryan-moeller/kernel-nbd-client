/*
 * Copyright (c) 2025 Ryan Moeller
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/bio.h>
#include <sys/capsicum.h>
#include <sys/file.h>
#include <sys/kthread.h>
#include <sys/limits.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/module.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/protosw.h>
#include <sys/queue.h>
#include <sys/refcount.h>
#include <sys/sbuf.h>
#include <sys/sched.h>
#include <sys/sema.h>
#include <sys/sockbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sx.h>
#include <sys/sysctl.h>
#include <sys/uio.h>

#include <geom/geom.h>
#include <geom/geom_dbg.h>
#include <geom/geom_disk.h>

#include <machine/atomic.h>

#include <vm/uma.h>
#include <vm/vm_page.h>

#include "g_nbd.h"
#include "nbd-protocol.h"

FEATURE(geom_nbd, "GEOM NBD module");

SYSCTL_DECL(_kern_geom);
static SYSCTL_NODE(_kern_geom, OID_AUTO, nbd, CTLFLAG_RW | CTLFLAG_MPSAFE, 0,
    "GEOM NBD configuration");
static int g_nbd_debug = 0;
SYSCTL_INT(_kern_geom_nbd, OID_AUTO, debug, CTLFLAG_RWTUN, &g_nbd_debug, 0,
    "Debug level");
static int maxpayload = 256 * 1024;
SYSCTL_INT(_kern_geom_nbd, OID_AUTO, maxpayload, CTLFLAG_RWTUN, &maxpayload, 0,
    "Maximum payload size");
static int sendspace = 1536 * 1024;
SYSCTL_INT(_kern_geom_nbd, OID_AUTO, sendspace, CTLFLAG_RWTUN, &sendspace, 0,
    "Default socket send buffer size");
static int recvspace = 1536 * 1024;
SYSCTL_INT(_kern_geom_nbd, OID_AUTO, recvspace, CTLFLAG_RWTUN, &recvspace, 0,
    "Default socket receive buffer size");
static int identfmt = 0;
SYSCTL_INT(_kern_geom_nbd, OID_AUTO, identfmt, CTLFLAG_RWTUN, &identfmt, 0,
    "Format of GEOM::ident (0=host:port/name, 1=name||host:port/name, 2=name)");

enum {
	G_NBD_ERROR,
	G_NBD_WARN,
	G_NBD_INFO,
	G_NBD_TRACE,
	G_NBD_DEBUG0,
};

#define G_NBD_DEBUG(lvl, ...) \
    _GEOM_DEBUG("GEOM_NBD", g_nbd_debug, (lvl), NULL, __VA_ARGS__)
#define G_NBD_LOGREQ(lvl, bp, ...) \
    _GEOM_DEBUG("GEOM_NBD", g_nbd_debug, (lvl), (bp), __VA_ARGS__)

#define PRINT_SB_FLAGS "\20" \
    "\20TLS_RX_RESYNC" \
    "\17SPLICED" \
    "\16AIO_RUNNING" \
    "\15STOP" \
    "\14AUTOSIZE" \
    "\13IN_TOE" \
    "\12NOCOALESCE" \
    "\11KNOTE" \
    "\10AIO" \
    "\6UPCALL" \
    "\5ASYNC" \
    "\4SEL" \
    "\3WAIT" \
    "\2TLS_RX_RUNNING" \
    "\1TLS_RX"

struct g_nbd_softc;

enum nbd_conn_state {
	NBD_CONN_CONNECTED,
	NBD_CONN_SOFT_DISCONNECTING,
	NBD_CONN_HARD_DISCONNECTING,
	NBD_CONN_CLOSED,
};

struct nbd_inflight {
	struct bio	*ni_bio;
	uint64_t	ni_cookie;
	u_int		ni_refs;
	TAILQ_ENTRY(nbd_inflight)	ni_inflight;
};

struct nbd_conn {
	struct g_nbd_softc	*nc_softc;
	struct socket		*nc_socket;
	enum nbd_conn_state	nc_state;
	uint64_t		nc_seq;
	TAILQ_HEAD(, nbd_inflight)	nc_inflight;
	struct mtx		nc_inflight_mtx;
	struct sema		nc_receiver_done;
	SLIST_ENTRY(nbd_conn)	nc_connections;
};

struct g_nbd_softc {
	const char	*sc_host;
	const char	*sc_port;
	const char	*sc_name;
	const char	*sc_description;
	uint64_t	sc_size;
	union {
		uint32_t	sc_flags;
		struct {
			uint16_t	sc_handshake_flags;
			uint16_t	sc_transmission_flags;
		};
	};
	uint32_t	sc_minblocksize;
	uint32_t	sc_prefblocksize;
	uint32_t	sc_maxpayload;
	u_int		sc_unit;
	bool		sc_tls;
	struct g_geom	*sc_geom;
	struct g_provider	*sc_provider;
	struct bio_queue	sc_queue;
	struct mtx	sc_queue_mtx;
	SLIST_HEAD(, nbd_conn)	sc_connections;
	u_int		sc_nconns;
	struct mtx	sc_conns_mtx;
	bool		sc_flushing;
	struct sx	sc_flush_lock;
};

#define G_NBD_PROC_NAME "gnbd"
static struct proc *g_nbd_proc;
static u_int g_nbd_nconns;
static struct sx g_nbd_lock;
static struct unrhdr *g_nbd_unit;
static uma_zone_t g_nbd_inflight_zone;
static u_int g_nbd_tlsmax;

static inline int16_t
bio_to_nbd_cmd(struct bio *bp)
{
	switch (bp->bio_cmd) {
	case BIO_READ: return (NBD_CMD_READ);
	case BIO_WRITE: return (NBD_CMD_WRITE);
	case BIO_DELETE: return (NBD_CMD_TRIM);
	case BIO_FLUSH: return (NBD_CMD_FLUSH);
	default: return (-1);
	}
}

static inline __diagused const char *
bio_cmd_str(struct bio *bp)
{
	switch (bp->bio_cmd) {
#define CASE_STR(c) case c: return (#c)
	CASE_STR(BIO_READ);
	CASE_STR(BIO_WRITE);
	CASE_STR(BIO_DELETE);
	CASE_STR(BIO_GETATTR);
	CASE_STR(BIO_FLUSH);
	CASE_STR(BIO_CMD0);
	CASE_STR(BIO_CMD1);
	CASE_STR(BIO_CMD2);
	CASE_STR(BIO_ZONE);
	CASE_STR(BIO_SPEEDUP);
#undef CASE_STR
	default: return ("[unknown]");
	}
}

static inline struct nbd_inflight *
nbd_conn_enqueue_inflight(struct nbd_conn *nc, struct bio *bp)
{
	struct nbd_inflight *ni;

	G_NBD_LOGREQ(G_NBD_TRACE, bp, "%s cookie=%lu", __func__, nc->nc_seq);
	ni = uma_zalloc(g_nbd_inflight_zone, M_NOWAIT | M_ZERO);
	if (ni == NULL)
		return (NULL);
	ni->ni_bio = bp;
	ni->ni_cookie = nc->nc_seq++;
	ni->ni_refs = 1;
	mtx_lock(&nc->nc_inflight_mtx);
	TAILQ_INSERT_TAIL(&nc->nc_inflight, ni, ni_inflight);
	mtx_unlock(&nc->nc_inflight_mtx);
	return (ni);
}

static void
nbd_conn_remove_inflight_specific(struct nbd_conn *nc, struct nbd_inflight *ni)
{
	bool last;

	G_NBD_LOGREQ(G_NBD_TRACE, ni->ni_bio, "%s", __func__);
	mtx_lock(&nc->nc_inflight_mtx);
	TAILQ_REMOVE(&nc->nc_inflight, ni, ni_inflight);
	last = TAILQ_EMPTY(&nc->nc_inflight);
	mtx_unlock(&nc->nc_inflight_mtx);
	if (atomic_load_bool(&nc->nc_softc->sc_flushing)) {
		switch (ni->ni_bio->bio_cmd) {
		case BIO_DELETE:
		case BIO_WRITE:
			wakeup_one(ni);
		}
	}
	if (last && atomic_load_int(&nc->nc_state)
	    == NBD_CONN_SOFT_DISCONNECTING)
		wakeup_one(&nc->nc_inflight);
	G_NBD_LOGREQ(G_NBD_DEBUG0, ni->ni_bio, "%s last=%s", __func__,
	    last ? "true" : "false");
}

static inline void
nbd_inflight_deliver(struct nbd_inflight *ni, int error)
{
	struct bio *bp = ni->ni_bio;

	G_NBD_LOGREQ(G_NBD_TRACE, bp, "%s", __func__);
	atomic_cmpset_int(&bp->bio_error, 0, error);
	if (refcount_release(&ni->ni_refs)) {
		g_io_deliver(bp, bp->bio_error);
		uma_zfree(g_nbd_inflight_zone, ni);
	}
}

static void
nbd_inflight_free_mext(struct mbuf *m)
{
	struct nbd_inflight *ni = m->m_ext.ext_arg1;

	G_NBD_LOGREQ(G_NBD_TRACE, ni->ni_bio, "%s", __func__);
	nbd_inflight_deliver(ni, 0);
}

static inline const char *
nbd_conn_state_str(enum nbd_conn_state state)
{
	switch (state) {
#define CASE_STR(c) case c: return (#c)
	CASE_STR(NBD_CONN_CONNECTED);
	CASE_STR(NBD_CONN_SOFT_DISCONNECTING);
	CASE_STR(NBD_CONN_HARD_DISCONNECTING);
	CASE_STR(NBD_CONN_CLOSED);
#undef CASE_STR
	default: return "[unknown]";
	}
}

/*
 * Degrade nc->nc_state if possible, locklessly.
 */
static inline void
nbd_conn_degrade_state(struct nbd_conn *nc, enum nbd_conn_state state)
{
	KASSERT(NBD_CONN_CONNECTED < state && state < NBD_CONN_CLOSED,
	    ("tried degrading to an invalid state"));

	G_NBD_DEBUG(G_NBD_TRACE, "%s nc->nc_state=%s (%d) state=%s (%d)",
	    __func__, nbd_conn_state_str(nc->nc_state), nc->nc_state,
	    nbd_conn_state_str(state), state);
	if (atomic_cmpset_int(&nc->nc_state, NBD_CONN_CONNECTED, state))
		return;
	atomic_cmpset_int(&nc->nc_state, NBD_CONN_SOFT_DISCONNECTING, state);
}

static inline bool
nbd_conn_send_ok(struct nbd_conn *nc, struct bio *bp)
{
	struct socket *so = nc->nc_socket;

	SOCK_SENDBUF_LOCK_ASSERT(so);

	if (atomic_load_int(&nc->nc_state) != NBD_CONN_CONNECTED) {
		G_NBD_LOGREQ(G_NBD_DEBUG0, bp, "nc_state=%s",
		    nbd_conn_state_str(nc->nc_state));
		return (false);
	}
	if (so->so_error != 0) {
		G_NBD_LOGREQ(G_NBD_WARN, bp, "so_error=%d", so->so_error);
		return (false);
	}
	if ((so->so_state & SS_ISCONNECTED) == 0) {
		G_NBD_LOGREQ(G_NBD_DEBUG0, bp, "not connected");
		return (false);
	}
	if ((so->so_snd.sb_state & SBS_CANTSENDMORE) != 0) {
		G_NBD_LOGREQ(G_NBD_DEBUG0, bp, "cannot send more");
		return (false);
	}
	return (true);
}

static struct mbuf *
nbd_request_mbuf(bool tls, struct nbd_request **reqp)
{
	const size_t needed = sizeof(**reqp);
	struct mbuf *m;

	_Static_assert(needed <= MLEN, "mapped request truncated");
	_Static_assert(MLEN <= PAGE_SIZE, "unmapped request truncated");

	if (tls) {
		m = mb_alloc_ext_plus_pages(needed, M_NOWAIT);
		if (m == NULL)
			return (NULL);
		m->m_epg_last_len = needed;
		m->m_ext.ext_size = PAGE_SIZE;
		*reqp = (void *)PHYS_TO_DMAP(m->m_epg_pa[0]);
	} else {
		m = m_get(M_NOWAIT, MT_DATA);
		if (m == NULL)
			return (NULL);
		*reqp = mtod(m, void *);
	}
	m->m_len = needed;
	return (m);
}

static void
nbd_conn_send(struct nbd_conn *nc, struct nbd_inflight *ni)
{
	struct socket *so = nc->nc_socket;
	struct bio *bp = ni->ni_bio;
	struct nbd_request *req;
	struct mbuf *m;
	size_t needed;
	uint16_t flags = 0; /* no command flags supported currently */
	int16_t cmd = bio_to_nbd_cmd(bp);
	int error;
	bool tls = nc->nc_softc->sc_tls;

	KASSERT(cmd != -1, ("unsupported bio command queued: %s (%d)",
	    bio_cmd_str(bp), bp->bio_cmd));

	G_NBD_LOGREQ(G_NBD_TRACE, bp, "%s", __func__);
retry:
	m = nbd_request_mbuf(tls, &req);
	if (m == NULL) {
		nbd_conn_remove_inflight_specific(nc, ni);
		nbd_inflight_deliver(ni, ENOMEM);
		return;
	}
	req->magic = htobe32(NBD_REQUEST_MAGIC);
	req->flags = htobe16(flags);
	req->command = htobe16(cmd);
	req->cookie = htobe64(ni->ni_cookie);
	req->offset = htobe64(bp->bio_offset);
	req->length = htobe32(bp->bio_length);
	needed = sizeof(*req);
	if (cmd == NBD_CMD_WRITE) {
		struct mbuf *d;

		if ((bp->bio_flags & BIO_UNMAPPED) != 0) {
			struct mbuf *m_tail = m;
			size_t page_offset = bp->bio_ma_offset;
			size_t resid = bp->bio_length;
			size_t len;

			G_NBD_LOGREQ(G_NBD_DEBUG0, bp, "%s unmapped write",
			    __func__);
			d = NULL;
			for (int i = 0; resid > 0; i++) {
				if (d == NULL) {
					d = mb_alloc_ext_pgs(M_NOWAIT,
#if __FreeBSD_version > 1500026
					    nbd_inflight_free_mext, M_RDONLY);
#else
					    nbd_inflight_free_mext);
#endif
					if (d == NULL) {
						m_freem(m);
						nbd_conn_remove_inflight_specific(
						    nc, ni);
						nbd_inflight_deliver(ni,
						    ENOMEM);
						return;
					}
					refcount_acquire(&ni->ni_refs);
					d->m_ext.ext_arg1 = ni;
					d->m_epg_1st_off = page_offset;
				}
				len = MIN(resid, PAGE_SIZE - page_offset);
				d->m_epg_pa[d->m_epg_npgs++] =
				    VM_PAGE_TO_PHYS(bp->bio_ma[i]);
				d->m_epg_last_len = len;
				d->m_len += len;
				d->m_ext.ext_size += PAGE_SIZE;
				MBUF_EXT_PGS_ASSERT_SANITY(d);
				if (d->m_epg_npgs == MBUF_PEXT_MAX_PGS) {
					m_tail->m_next = d;
					m_tail = d;
					needed += d->m_len;
					d = NULL;
				}
				page_offset = 0;
				resid -= len;
			}
			if (d != NULL) {
				m_tail->m_next = d;
				needed += d->m_len;
			}
		} else if (tls) {
			struct mbuf *m_tail = m;
			c_caddr_t data = bp->bio_data;
			size_t resid = bp->bio_length;
			size_t len;

			G_NBD_LOGREQ(G_NBD_DEBUG0, bp, "%s mapped write (tls)",
			    __func__);
			needed += resid;
			while (resid > 0) {
				len = MIN(resid, MBUF_PEXT_MAX_PGS * PAGE_SIZE);
				d = mb_alloc_ext_plus_pages(len, M_NOWAIT);
				if (d == NULL) {
					m_free(m);
					nbd_conn_remove_inflight_specific(nc,
					    ni);
					nbd_inflight_deliver(ni, ENOMEM);
					return;
				}
				d->m_len = len;
				d->m_ext.ext_size = d->m_epg_npgs * PAGE_SIZE;
				d->m_epg_last_len =
				    PAGE_SIZE - (d->m_ext.ext_size - len);
				MBUF_EXT_PGS_ASSERT_SANITY(d);
				m_copyback(d, 0, len, data);
				m_tail->m_next = d;
				m_tail = d;
				data += len;
				resid -= len;
			}
		} else {
			G_NBD_LOGREQ(G_NBD_DEBUG0, bp, "%s mapped write",
			    __func__);
			d = m_get(M_NOWAIT, MT_DATA);
			if (d == NULL) {
				m_free(m);
				nbd_conn_remove_inflight_specific(nc, ni);
				nbd_inflight_deliver(ni, ENOMEM);
				return;
			}
			refcount_acquire(&ni->ni_refs);
			m_extadd(d, bp->bio_data, bp->bio_length,
			    nbd_inflight_free_mext, ni, NULL, M_RDONLY,
			    EXT_MOD_TYPE);
			d->m_len = bp->bio_length;
			needed += d->m_len;
			m->m_next = d;
		}
	}
	SOCK_SENDBUF_LOCK(so);
	so->so_snd.sb_lowat = MAX(needed, so->so_snd.sb_hiwat / 8);
	while (!sowriteable(so)) {
		if (!nbd_conn_send_ok(nc, bp)) {
			SOCK_SENDBUF_UNLOCK(so);
			G_NBD_LOGREQ(G_NBD_INFO, bp, "%s disconnecting",
			    __func__);
			nbd_conn_degrade_state(nc, NBD_CONN_HARD_DISCONNECTING);
			m_freem(m);
			nbd_conn_remove_inflight_specific(nc, ni);
			nbd_inflight_deliver(ni, ENXIO);
			return;
		}
		if (so->so_snd.sb_lowat > so->so_snd.sb_hiwat) {
			/* XXX: how did we get here? what if this fails? */
			G_NBD_LOGREQ(G_NBD_WARN, bp,
			    "%s reserving more snd space", __func__);
			G_NBD_LOGREQ(G_NBD_DEBUG0, bp,
			    "lowat=%d hiwat=%d ccc=%d acc=%d flags=%b",
			    so->so_snd.sb_lowat, so->so_snd.sb_hiwat,
			    so->so_snd.sb_ccc, so->so_snd.sb_acc,
			    so->so_snd.sb_flags & 0xffff, PRINT_SB_FLAGS);
			if (!sbreserve_locked(so, SO_SND, needed, curthread))
				G_NBD_LOGREQ(G_NBD_WARN, bp,
				    "sbreserve failed");
			so->so_snd.sb_flags |= SB_AUTOSIZE;
			continue;
		}
		sbwait(so, SO_SND);
	}
	SOCK_SENDBUF_UNLOCK(so);
	error = sosend(so, NULL, NULL, m, NULL, MSG_DONTWAIT, NULL);
	if (error == EWOULDBLOCK) {
		G_NBD_LOGREQ(G_NBD_WARN, bp, "%s sosend would block", __func__);
		goto retry;
	}
	if (error != 0) {
		G_NBD_LOGREQ(G_NBD_ERROR, bp, "%s sosend failed (%d)", __func__,
		    error);
		if (error != ENOMEM && error != EINTR && error != ERESTART)
			nbd_conn_degrade_state(nc, NBD_CONN_HARD_DISCONNECTING);
		nbd_conn_remove_inflight_specific(nc, ni);
		nbd_inflight_deliver(ni, error);
		return;
	}
}

static inline void
nbd_simple_reply_ntoh(struct nbd_simple_reply *reply)
{
	reply->magic = be32toh(reply->magic);
	reply->error = be32toh(reply->error);
	reply->cookie = be64toh(reply->cookie);
}

static inline bool
nbd_simple_reply_is_valid(struct nbd_simple_reply *reply)
{
	if (reply->magic != NBD_SIMPLE_REPLY_MAGIC) {
		G_NBD_DEBUG(G_NBD_INFO, "magic=0x%08x != 0x%08x", reply->magic,
		    NBD_SIMPLE_REPLY_MAGIC);
		return (false);
	}
	return (true);
}

static inline int
nbd_error_to_errno(uint32_t error)
{
	switch (error) {
	case NBD_EOVERFLOW: return (EOVERFLOW);
	case NBD_ESHUTDOWN: return (ESHUTDOWN);
	default: return (error);
	}
}

static inline bool
nbd_conn_recv_ok(struct nbd_conn *nc, struct bio *bp)
{
	struct socket *so = nc->nc_socket;

	SOCK_RECVBUF_LOCK_ASSERT(so);

	if (atomic_load_int(&nc->nc_state) == NBD_CONN_HARD_DISCONNECTING) {
		G_NBD_LOGREQ(G_NBD_DEBUG0, bp, "nc_state=%s",
		    nbd_conn_state_str(nc->nc_state));
		return (false);
	}
	if (so->so_error != 0) {
		G_NBD_LOGREQ(G_NBD_WARN, bp, "so_error=%d", so->so_error);
		return (false);
	}
	if ((so->so_rcv.sb_state & SBS_CANTRCVMORE) != 0) {
		G_NBD_LOGREQ(G_NBD_DEBUG0, bp, "cannot receive more");
		return (false);
	}
	return (true);
}

static struct nbd_inflight *
nbd_conn_remove_inflight(struct nbd_conn *nc, uint64_t cookie)
{
	struct nbd_inflight *ni, *ni2;
	bool last;

	G_NBD_DEBUG(G_NBD_TRACE, "%s cookie=%lu", __func__, cookie);
	mtx_lock(&nc->nc_inflight_mtx);
	TAILQ_FOREACH_SAFE(ni, &nc->nc_inflight, ni_inflight, ni2) {
		if (ni->ni_cookie == cookie) {
			TAILQ_REMOVE(&nc->nc_inflight, ni, ni_inflight);
			break;
		}
	}
	last = TAILQ_EMPTY(&nc->nc_inflight);
	mtx_unlock(&nc->nc_inflight_mtx);
	if (ni != NULL && atomic_load_bool(&nc->nc_softc->sc_flushing)) {
		switch (ni->ni_bio->bio_cmd) {
		case BIO_DELETE:
		case BIO_WRITE:
			wakeup_one(ni);
		}
	}
	if (last && atomic_load_int(&nc->nc_state)
	    == NBD_CONN_SOFT_DISCONNECTING)
		wakeup_one(&nc->nc_inflight);
	G_NBD_LOGREQ(G_NBD_DEBUG0, ni->ni_bio, "%s last=%s", __func__,
	    last ? "true" : "false");
	return (ni);
}

static int
nbd_conn_recv_mbufs(struct nbd_conn *nc, size_t len, struct mbuf **mp)
{
	struct uio uio;
	struct socket *so = nc->nc_socket;
	struct mbuf *m, *m_tail;
	size_t available, expected;
	int flags, error;

	G_NBD_DEBUG(G_NBD_TRACE, "%s len=%zu", __func__, len);
	m = NULL;
	while (len > 0) {
		SOCK_RECVBUF_LOCK(so);
		if (!nbd_conn_recv_ok(nc, NULL)) {
			SOCK_RECVBUF_UNLOCK(so);
			G_NBD_DEBUG(G_NBD_INFO, "%s disconnecting", __func__);
			nbd_conn_degrade_state(nc, NBD_CONN_HARD_DISCONNECTING);
			m_freem(m);
			return (ENXIO);
		}
		available = sbavail(&so->so_rcv);
		if (available < len) {
			so->so_rcv.sb_lowat = len;
			sbwait(so, SO_RCV);
			so->so_rcv.sb_lowat = so->so_rcv.sb_hiwat + 1;
			available = sbavail(&so->so_rcv);
		}
		SOCK_RECVBUF_UNLOCK(so);
		if (available == 0)
			continue;
		memset(&uio, 0, sizeof(uio));
		uio.uio_resid = expected = MIN(len, available);
		while (uio.uio_resid > 0) {
			struct mbuf *m1;

			flags = MSG_DONTWAIT;
			error = soreceive(so, NULL, &uio, &m1, NULL, &flags);
			if (error == EAGAIN) {
				G_NBD_DEBUG(G_NBD_DEBUG0,
				    "len=%zu avail=%zu expected=%zu resid=%zd",
				    len, available, expected, uio.uio_resid);
				break;
			}
			if (error != 0) {
				G_NBD_DEBUG(G_NBD_ERROR,
				    "%s soreceive failed (%d)", __func__,
				    error);
				if (error != ENOMEM && error != EINTR &&
				    error != ERESTART)
					nbd_conn_degrade_state(nc,
					    NBD_CONN_HARD_DISCONNECTING);
				m_freem(m);
				return (error);
			}
			if (m == NULL)
				m = m_tail = m1;
			else {
				while (m_tail->m_next != NULL)
					m_tail = m_tail->m_next;
				m_tail->m_next = m1;
				m_tail = m1;
			}
		}
		len -= expected - uio.uio_resid;
	}
	*mp = m;
	return (0);
}

static void
nbd_conn_recv(struct nbd_conn *nc)
{
	/* TODO: structured replies if negotiated */
	struct nbd_simple_reply reply;
	struct mbuf *m;
	struct nbd_inflight *ni;
	struct bio *bp;
	int error;

	G_NBD_DEBUG(G_NBD_TRACE, "%s", __func__);
	error = nbd_conn_recv_mbufs(nc, sizeof(reply), &m);
	if (error != 0)
		return;
	G_NBD_DEBUG(G_NBD_DEBUG0, "%s received reply", __func__);
	m_copydata(m, 0, sizeof(reply), (void *)&reply);
	m_freem(m);
	nbd_simple_reply_ntoh(&reply);
	if (!nbd_simple_reply_is_valid(&reply)) {
		G_NBD_DEBUG(G_NBD_ERROR, "%s received invalid reply", __func__);
		nbd_conn_degrade_state(nc, NBD_CONN_HARD_DISCONNECTING);
		return;
	}
	/* TODO: structured replies can have multiple replies per cookie */
	ni = nbd_conn_remove_inflight(nc, reply.cookie);
	if (ni == NULL) {
		G_NBD_DEBUG(G_NBD_ERROR,
		    "%s did not find inflight bio for cookie 0x%lx", __func__,
		    reply.cookie);
		nbd_conn_degrade_state(nc, NBD_CONN_SOFT_DISCONNECTING);
		return;
	}
	bp = ni->ni_bio;
	if (reply.error != 0) {
		G_NBD_LOGREQ(G_NBD_WARN, bp,
		    "%s received reply with error (%d)", __func__, reply.error);
		if (reply.error == NBD_ESHUTDOWN)
			nbd_conn_degrade_state(nc, NBD_CONN_SOFT_DISCONNECTING);
		nbd_inflight_deliver(ni, nbd_error_to_errno(reply.error));
		return;
	}
	if (bp->bio_cmd == BIO_READ) {
		error = nbd_conn_recv_mbufs(nc, bp->bio_length, &m);
		if (error != 0) {
			nbd_inflight_deliver(ni, error);
			return;
		}
		G_NBD_LOGREQ(G_NBD_DEBUG0, bp, "%s received read data",
		    __func__);
		if ((bp->bio_flags & BIO_UNMAPPED) != 0) {
			vm_offset_t vaddr;
			size_t page_offset = bp->bio_ma_offset;
			size_t resid = bp->bio_length;
			size_t offset = 0;
			size_t len;

			G_NBD_LOGREQ(G_NBD_DEBUG0, bp, "%s unmapped read",
			    __func__);
			for (int i = 0; resid > 0; i++) {
				len = MIN(resid, PAGE_SIZE - page_offset);
				vaddr = PHYS_TO_DMAP(VM_PAGE_TO_PHYS(
				    bp->bio_ma[i]));
				m_copydata(m, offset, len, (char *)vaddr +
				    page_offset);
				page_offset = 0;
				offset += len;
				resid -= len;
			}
		} else {
			G_NBD_LOGREQ(G_NBD_DEBUG0, bp, "%s mapped read",
			    __func__);
			m_copydata(m, 0, bp->bio_length, bp->bio_data);
		}
		m_freem(m);
	}
	bp->bio_completed = bp->bio_length;
	bp->bio_resid = 0;
	nbd_inflight_deliver(ni, 0);
}

static void
g_nbd_flush_wait(struct g_nbd_softc *sc)
{
	struct nbd_conn *nc;
	struct nbd_inflight *ni;

	mtx_lock(&sc->sc_conns_mtx);
	atomic_store_bool(&sc->sc_flushing, true);
	SLIST_FOREACH(nc, &sc->sc_connections, nc_connections) {
		mtx_lock(&nc->nc_inflight_mtx);
restart:
		TAILQ_FOREACH(ni, &nc->nc_inflight, ni_inflight) {
			switch (ni->ni_bio->bio_cmd) {
			case BIO_DELETE:
			case BIO_WRITE:
				mtx_sleep(ni, &nc->nc_inflight_mtx, PRIBIO,
				    "gnbd:flush", 0);
				/* Have to start over, the lock was dropped. */
				goto restart;
			}
		}
		mtx_unlock(&nc->nc_inflight_mtx);
	}
	atomic_store_bool(&sc->sc_flushing, false);
	mtx_unlock(&sc->sc_conns_mtx);
}

static inline bool
nbd_conn_soft_disconnect_ok(struct nbd_conn *nc)
{
	struct socket *so = nc->nc_socket;

	SOCK_SENDBUF_LOCK_ASSERT(so);

	if (atomic_load_int(&nc->nc_state) != NBD_CONN_SOFT_DISCONNECTING) {
		G_NBD_DEBUG(G_NBD_DEBUG0, "nc_state=%s",
		    nbd_conn_state_str(nc->nc_state));
		return (false);
	}
	if (so->so_error != 0) {
		G_NBD_DEBUG(G_NBD_WARN, "so_error=%d", so->so_error);
		return (false);
	}
	if ((so->so_snd.sb_state & SBS_CANTSENDMORE) != 0) {
		G_NBD_DEBUG(G_NBD_DEBUG0, "cannot send more");
		return (false);
	}
	return (true);
}

static void
nbd_conn_soft_disconnect(struct nbd_conn *nc)
{
	struct socket *so = nc->nc_socket;
	struct nbd_request *req;
	struct mbuf *m;
	size_t needed;
	int error;

	G_NBD_DEBUG(G_NBD_TRACE, "%s", __func__);
retry:
	m = nbd_request_mbuf(nc->nc_softc->sc_tls, &req);
	if (m == NULL) {
		atomic_store_int(&nc->nc_state,
		    NBD_CONN_HARD_DISCONNECTING);
		return;
	}
	memset(req, 0, sizeof(*req));
	req->magic = htobe32(NBD_REQUEST_MAGIC);
	req->command = htobe16(NBD_CMD_DISCONNECT);
	needed = sizeof(*req);
	SOCK_SENDBUF_LOCK(so);
	so->so_snd.sb_lowat = needed;
	while (!sowriteable(so)) {
		if (!nbd_conn_soft_disconnect_ok(nc)) {
			SOCK_SENDBUF_UNLOCK(so);
			G_NBD_DEBUG(G_NBD_INFO, "%s disconnecting", __func__);
			m_free(m);
			return;
		}
		if (so->so_snd.sb_lowat > so->so_snd.sb_hiwat) {
			/* XXX: how did we get here? what if this fails? */
			G_NBD_DEBUG(G_NBD_WARN, "%s reserving more snd space",
			    __func__);
			G_NBD_DEBUG(G_NBD_DEBUG0,
			    "lowat=%d hiwat=%d ccc=%d acc=%d flags=%b",
			    so->so_snd.sb_lowat, so->so_snd.sb_hiwat,
			    so->so_snd.sb_ccc, so->so_snd.sb_acc,
			    so->so_snd.sb_flags & 0xffff, PRINT_SB_FLAGS);
			if (!sbreserve_locked(so, SO_SND, needed, curthread))
				G_NBD_DEBUG(G_NBD_WARN, "sbreserve failed");
			so->so_snd.sb_flags |= SB_AUTOSIZE;
			continue;
		}
		sbwait(so, SO_SND);
	}
	SOCK_SENDBUF_UNLOCK(so);
	error = sosend(so, NULL, NULL, m, NULL, MSG_DONTWAIT, NULL);
	if (error == EWOULDBLOCK) {
		G_NBD_DEBUG(G_NBD_WARN, "%s sosend would block", __func__);
		goto retry;
	}
	if (error != 0) {
		G_NBD_DEBUG(G_NBD_ERROR, "%s sosend failed (%d)", __func__,
		    error);
		atomic_store_int(&nc->nc_state, NBD_CONN_HARD_DISCONNECTING);
		return;
	}
	soshutdown(so, SHUT_WR);
	while (atomic_load_int(&nc->nc_state) == NBD_CONN_SOFT_DISCONNECTING) {
		mtx_lock(&nc->nc_inflight_mtx);
		if (TAILQ_FIRST(&nc->nc_inflight) != NULL) {
			mtx_sleep(&nc->nc_inflight, &nc->nc_inflight_mtx,
			    PRIBIO | PDROP, "gnbd:inflight", 0);
			continue;
		}
		mtx_unlock(&nc->nc_inflight_mtx);
		break;
	}
	atomic_store_int(&nc->nc_state, NBD_CONN_HARD_DISCONNECTING);
}

static inline void
nbd_conn_close(struct nbd_conn *nc)
{
	struct socket *so = nc->nc_socket;

	G_NBD_DEBUG(G_NBD_TRACE, "%s", __func__);
	atomic_store_int(&nc->nc_state, NBD_CONN_CLOSED);
	soclose(so);
}

static inline void
nbd_conn_drain_inflight(struct nbd_conn *nc)
{
	struct nbd_inflight *ni;

	G_NBD_DEBUG(G_NBD_TRACE, "%s", __func__);
	mtx_lock(&nc->nc_inflight_mtx);
	while ((ni = TAILQ_FIRST(&nc->nc_inflight)) != NULL) {
		TAILQ_REMOVE(&nc->nc_inflight, ni, ni_inflight);
		nbd_inflight_deliver(ni, ENXIO);
	}
	mtx_unlock(&nc->nc_inflight_mtx);
}

static inline struct bio *
bio_queue_takefirst(struct bio_queue *queue)
{
	struct bio *bp;

	bp = TAILQ_FIRST(queue);
	if (bp != NULL)
		TAILQ_REMOVE(queue, bp, bio_queue);
	return (bp);
}

static inline void
g_nbd_drain_queue(struct g_nbd_softc *sc)
{
	struct bio *bp;

	G_NBD_DEBUG(G_NBD_TRACE, "%s", __func__);
	mtx_lock(&sc->sc_queue_mtx);
	while ((bp = bio_queue_takefirst(&sc->sc_queue)) != NULL)
		g_io_deliver(bp, ENXIO);
	mtx_unlock(&sc->sc_queue_mtx);
}

static inline bool
g_nbd_remove_conn(struct g_nbd_softc *sc, struct nbd_conn *nc)
{
	bool empty;

	KASSERT(nc->nc_state == NBD_CONN_CLOSED,
	    ("tried to remove open connection"));

	G_NBD_DEBUG(G_NBD_TRACE, "%s", __func__);

	mtx_lock(&sc->sc_conns_mtx);
	SLIST_REMOVE(&sc->sc_connections, nc, nbd_conn, nc_connections);
	empty = --sc->sc_nconns == 0;
	mtx_unlock(&sc->sc_conns_mtx);

	sx_xlock(&g_nbd_lock);
	if (--g_nbd_nconns == 0)
		/*
		 * We're exiting the last threads, so the process is dying.
		 * Make sure new connections create a new process.
		 */
		g_nbd_proc = NULL;
	sx_xunlock(&g_nbd_lock);

	sema_destroy(&nc->nc_receiver_done);
	mtx_destroy(&nc->nc_inflight_mtx);
	g_free(nc);
	return (empty);
}

static inline bool
bio_queue_empty(struct bio_queue *queue)
{
	return (TAILQ_EMPTY(queue));
}

static inline void
g_nbd_free(struct g_nbd_softc *sc)
{
	struct g_geom *gp = sc->sc_geom;

	KASSERT(sc->sc_nconns == 0, ("tried to free with connections"));
	KASSERT(bio_queue_empty(&sc->sc_queue),
	    ("tried to free with bios in queue"));

	G_NBD_DEBUG(G_NBD_TRACE, "%s", __func__);
	g_topology_lock();
	gp->softc = NULL;
	g_wither_geom(gp, ENXIO);
	g_topology_unlock();
	free_unr(g_nbd_unit, sc->sc_unit);
	sx_destroy(&sc->sc_flush_lock);
	mtx_destroy(&sc->sc_conns_mtx);
	mtx_destroy(&sc->sc_queue_mtx);
	g_free(__DECONST(char *, sc->sc_description));
	g_free(__DECONST(char *, sc->sc_name));
	g_free(__DECONST(char *, sc->sc_port));
	g_free(__DECONST(char *, sc->sc_host));
	g_free(sc);
	G_NBD_DEBUG(G_NBD_DEBUG0, "%s completed", __func__);
}

static void
nbd_conn_sender(void *arg)
{
	struct nbd_conn *nc = arg;
	struct g_nbd_softc *sc = nc->nc_softc;
	struct socket *so = nc->nc_socket;
	struct nbd_inflight *ni;
	struct bio *bp;

	G_NBD_DEBUG(G_NBD_TRACE, "%s", __func__);

	thread_lock(curthread);
	sched_prio(curthread, PRIBIO);
	thread_unlock(curthread);

	while (atomic_load_int(&nc->nc_state) == NBD_CONN_CONNECTED) {
		/*
		 * TODO: we're taking work before we know whether we will be
		 * able to complete it (due to lack of buffer space).  There
		 * could be another connection with more resources available.
		 * We should be able to leave bios queued until we're ready.
		 * Issue is we only wakeup one thread.
		 */
		mtx_lock(&sc->sc_queue_mtx);
		bp = bio_queue_takefirst(&sc->sc_queue);
		if (bp == NULL) {
			mtx_sleep(&sc->sc_queue, &sc->sc_queue_mtx,
			    PRIBIO | PDROP, "gnbd:queue", 0);
			continue;
		}
		mtx_unlock(&sc->sc_queue_mtx);
		if (bp->bio_cmd == BIO_FLUSH && sc->sc_nconns > 1) {
			/*
			 *  We take the lock exclusively here to ensure the FLUSH
			 *  is sent before subsequent bios by preventing
			 *  concurrent sends.
			 */
			sx_xlock(&sc->sc_flush_lock);
			g_nbd_flush_wait(sc);
			/*
			 * Put the bio in the inflight queue before sending the
			 * request to avoid racing with the receiver thread.
			 */
			ni = nbd_conn_enqueue_inflight(nc, bp);
			if (ni == NULL) {
				sx_xunlock(&sc->sc_flush_lock);
				g_io_deliver(bp, ENOMEM);
				continue;
			}
			nbd_conn_send(nc, ni);
			sx_xunlock(&sc->sc_flush_lock);
		} else {
			/*
			 * Put the bio in the inflight queue before sending the
			 * request to avoid racing with the receiver thread.
			 */
			if (sc->sc_nconns > 1) {
				/*
				 *  We share the lock here to allow concurrency
				 *  across the connections.
				 */
				sx_slock(&sc->sc_flush_lock);
				ni = nbd_conn_enqueue_inflight(nc, bp);
				sx_sunlock(&sc->sc_flush_lock);
			} else
				ni = nbd_conn_enqueue_inflight(nc, bp);
			if (ni == NULL) {
				g_io_deliver(bp, ENOMEM);
				continue;
			}
			nbd_conn_send(nc, ni);
		}
	}
	if (atomic_load_int(&nc->nc_state) == NBD_CONN_SOFT_DISCONNECTING)
		nbd_conn_soft_disconnect(nc);
	socantrcvmore(so);
	sema_wait(&nc->nc_receiver_done);
	nbd_conn_drain_inflight(nc);
	nbd_conn_close(nc);
	if (g_nbd_remove_conn(sc, nc)) {
		G_NBD_DEBUG(G_NBD_INFO, "%s last connection closed", __func__);
		g_wither_provider(sc->sc_provider, ENXIO);
		/* TODO: wait for access count to reach 0 */
		/* TODO: option to save the queue for a rescue operation */
		g_nbd_drain_queue(sc);
		g_nbd_free(sc);
	}
	kthread_exit();
}

static void
nbd_conn_receiver(void *arg)
{
	struct nbd_conn *nc = arg;
	struct g_nbd_softc *sc = nc->nc_softc;
	struct socket *so = nc->nc_socket;

	G_NBD_DEBUG(G_NBD_TRACE, "%s", __func__);

	thread_lock(curthread);
	sched_prio(curthread, PSOCK); /* XXX: or PRIBIO? */
	thread_unlock(curthread);

	while (atomic_load_int(&nc->nc_state) != NBD_CONN_HARD_DISCONNECTING)
		nbd_conn_recv(nc);
	socantsendmore(so);
	wakeup(&sc->sc_queue);
	sema_post(&nc->nc_receiver_done);
	kthread_exit();
}

/* Not in releases yet. */
#ifndef SLIST_EMPTY_ATOMIC
#define SLIST_EMPTY_ATOMIC(head) \
	(atomic_load_ptr(&(head)->slh_first) == NULL)
#endif

static void
g_nbd_add_conn(struct g_nbd_softc *sc, struct socket *so, const char *name,
    bool first)
{
	struct nbd_conn *nc;
	int rc;

	if (!first && SLIST_EMPTY_ATOMIC(&sc->sc_connections))
		return;

	nc = g_malloc(sizeof(*nc), M_WAITOK | M_ZERO);
	nc->nc_softc = sc;
	nc->nc_socket = so;
	nc->nc_state = NBD_CONN_CONNECTED;
	TAILQ_INIT(&nc->nc_inflight);
	mtx_init(&nc->nc_inflight_mtx, "gnbd:inflight", NULL, MTX_DEF);
	sema_init(&nc->nc_receiver_done, 0, "gnbd:receiver_done");

	mtx_lock(&sc->sc_conns_mtx);
	SLIST_INSERT_HEAD(&sc->sc_connections, nc, nc_connections);
	sc->sc_nconns++;
	mtx_unlock(&sc->sc_conns_mtx);

	sx_xlock(&g_nbd_lock);
	g_nbd_nconns++;
	rc = kproc_kthread_add(nbd_conn_sender, nc, &g_nbd_proc, NULL, 0, 0,
	    G_NBD_PROC_NAME, "gnbd %s sender", name);
	G_NBD_DEBUG(G_NBD_DEBUG0, "%s add sender rc=%d", __func__, rc);
	rc = kproc_kthread_add(nbd_conn_receiver, nc, &g_nbd_proc, NULL, 0, 0,
	    G_NBD_PROC_NAME, "gnbd %s receiver", name);
	G_NBD_DEBUG(G_NBD_DEBUG0, "%s add receiver rc=%d", __func__, rc);
	sx_xunlock(&g_nbd_lock);
}

static struct socket **
g_nbd_ctl_steal_sockets(struct gctl_req *req, int nsockets)
{
	cap_rights_t rights;
	struct thread *td;
	struct socket **sockets, *so;
	struct file *fp;
	long *tidp;
	int *sp;
	int error;

	G_NBD_DEBUG(G_NBD_TRACE, "%s", __func__);
	tidp = gctl_get_paraml(req, "thread", sizeof(*tidp));
	if (tidp == NULL) {
		gctl_error(req, "No 'thread' argument.");
		return (NULL);
	}
	sp = gctl_get_paraml(req, "sockets", sizeof(*sp) * nsockets);
	if (sp == NULL) {
		gctl_error(req, "No 'sockets' argument.");
		return (NULL);
	}
	sockets = g_malloc(sizeof(*sockets) * nsockets, M_WAITOK);
	td = tdfind(*tidp, -1);
	if (td == NULL) {
		gctl_error(req, "Invalid 'thread' argument.");
		return (NULL);
	}
	for (int i = 0; i < nsockets; i++) {
		error = getsock(td, sp[i],
		    cap_rights_init_one(&rights, CAP_SOCK_CLIENT), &fp);
		if (error != 0) {
			PROC_UNLOCK(td->td_proc);
			for (int j = 0; j < i; j++)
				soclose(sockets[j]);
			g_free(sockets);
			gctl_error(req, "Invalid socket (sockets[%d]=%d).",
			    i, sp[i]);
			return (NULL);
		}
		so = fp->f_data;
		if (so->so_type != SOCK_STREAM) {
			fdrop(fp, td);
			PROC_UNLOCK(td->td_proc);
			for (int j = 0; j < i; j++)
				soclose(sockets[j]);
			g_free(sockets);
			gctl_error(req, "Invalid socket type (sockets[%d]=%d).",
			    i, sp[i]);
			return (NULL);
		}
		/*
		 * Invalidate the file to take over the socket reference.
		 * Otherwise, soclose() will disconnect the socket when the
		 * process initiating this request ends and its file descriptors
		 * are closed.
		 */
		fp->f_ops = &badfileops;
		fp->f_data = NULL;
		fdrop(fp, td);
		/*
		 * Set the buffer reservations while we have the socket handy.
		 */
		error = soreserve(so, sendspace, recvspace);
		if (error != 0) {
			PROC_UNLOCK(td->td_proc);
			for (int j = 0; j < i; j++)
				soclose(sockets[j]);
			g_free(sockets);
			gctl_error(req, "soreserve failed (%d)", error);
			return (NULL);
		}
		so->so_snd.sb_flags |= SB_AUTOSIZE;
		so->so_rcv.sb_flags |= SB_AUTOSIZE;
		sockets[i] = so;
	}
	PROC_UNLOCK(td->td_proc);
	return (sockets);
}

static inline void
bio_queue_init(struct bio_queue *queue)
{
	TAILQ_INIT(queue);
}

static void
g_nbd_ctl_connect(struct gctl_req *req, struct g_class *mp)
{
	struct g_nbd_softc *sc;
	const char *host, *port, *name, *description;
	uint64_t *sizep;
	union {
		uint32_t flags;
		struct {
			uint16_t handshake_flags;
			uint16_t transmission_flags;
		};
	} *flagsp;
	uint32_t *minbsp, *prefbsp, *maxpayloadp;
	bool *tlsp;
	struct socket **sockets;
	struct g_geom *gp;
	struct g_provider *pp;
	intmax_t *cp;
	size_t limit, maxsz, minspace;
	int unit, nsockets;

	g_topology_assert();

	G_NBD_DEBUG(G_NBD_TRACE, "%s", __func__);
	unit = alloc_unr(g_nbd_unit);
	if (unit == -1) {
		gctl_error(req, "No free unit numbers.");
		return;
	}
	gp = g_new_geomf(mp, "nbd%d", unit);
	pp = g_provider_by_name(gp->name);
	if (pp != NULL) {
		g_destroy_geom(gp);
		free_unr(g_nbd_unit, unit);
		gctl_error(req, "Device '%s' already exists.", pp->name);
		return;
	}
	host = gctl_get_asciiparam(req, "host");
	port = gctl_get_asciiparam(req, "port");
	name = gctl_get_asciiparam(req, "name");
	description = gctl_get_asciiparam(req, "description");
	sizep = gctl_get_paraml(req, "size", sizeof(*sizep));
	if (sizep == NULL) {
		g_destroy_geom(gp);
		free_unr(g_nbd_unit, unit);
		gctl_error(req, "No 'size' argument.");
		return;
	}
	flagsp = gctl_get_paraml(req, "flags", sizeof(*flagsp));
	if (flagsp == NULL) {
		g_destroy_geom(gp);
		free_unr(g_nbd_unit, unit);
		gctl_error(req, "No 'flags' argument.");
		return;
	}
	tlsp = gctl_get_paraml(req, "tls", sizeof(*tlsp));
	if (tlsp == NULL) {
		g_destroy_geom(gp);
		free_unr(g_nbd_unit, unit);
		gctl_error(req, "No 'tls' argument.");
		return;
	}
	if (*tlsp && g_nbd_tlsmax == 0) {
		g_destroy_geom(gp);
		free_unr(g_nbd_unit, unit);
		gctl_error(req, "kern.ipc.tls.maxlen was not available when "
		   "module loaded");
		return;
	}
	minbsp = gctl_get_paraml(req, "minimum_blocksize", sizeof(*minbsp));
	if (minbsp == NULL) {
		g_destroy_geom(gp);
		free_unr(g_nbd_unit, unit);
		gctl_error(req, "No 'minimum_blocksize' argument.");
		return;
	}
	if (*minbsp > *sizep) {
		g_destroy_geom(gp);
		free_unr(g_nbd_unit, unit);
		gctl_error(req, "Invalid 'minimum_blocksize' argument.");
		return;
	}
	prefbsp = gctl_get_paraml(req, "preferred_blocksize", sizeof(*prefbsp));
	if (prefbsp == NULL) {
		g_destroy_geom(gp);
		free_unr(g_nbd_unit, unit);
		gctl_error(req, "No 'preferred_blocksize' argument.");
		return;
	}
	if (*minbsp > *prefbsp) {
		g_destroy_geom(gp);
		free_unr(g_nbd_unit, unit);
		gctl_error(req, "Invalid 'preferred_blocksize' argument.");
		return;
	}
	maxpayloadp = gctl_get_paraml(req, "maximum_payload",
	    sizeof(*maxpayloadp));
	if (maxpayloadp == NULL) {
		g_destroy_geom(gp);
		free_unr(g_nbd_unit, unit);
		gctl_error(req, "No 'maximum_payload' argument.");
		return;
	}
	maxsz = *maxpayloadp;
	limit = maxpayload;
	if (*tlsp && limit > g_nbd_tlsmax)
		limit = g_nbd_tlsmax;
	if (maxsz > limit) {
		G_NBD_DEBUG(1, "limiting max payload size to %zu", limit);
		maxsz = limit;
	}
	if (*minbsp > maxsz) {
		g_destroy_geom(gp);
		free_unr(g_nbd_unit, unit);
		gctl_error(req, "Invalid 'maximum_payload' argument.");
		return;
	}
	minspace = sizeof(struct nbd_request) + maxsz;
	if (sendspace < minspace) {
		G_NBD_DEBUG(G_NBD_WARN, "kern.geom.nbd.sendspace -> %zu",
		    minspace);
		sendspace = minspace;
	}
	/* TODO: support structured replies */
	minspace = sizeof(struct nbd_simple_reply) + maxsz;
	if (recvspace < minspace) {
		G_NBD_DEBUG(G_NBD_WARN, "kern.geom.nbd.recvspace -> %zu",
		    minspace);
		recvspace = minspace;
	}
	cp = gctl_get_paraml(req, "connections", sizeof(*cp));
	if (cp == NULL) {
		g_destroy_geom(gp);
		free_unr(g_nbd_unit, unit);
		gctl_error(req, "No 'connections' argument.");
		return;
	}
	nsockets = *cp;
	if (nsockets < 1) {
		g_destroy_geom(gp);
		free_unr(g_nbd_unit, unit);
		gctl_error(req, "Invalid 'connections' argument.");
		return;
	}
	if ((flagsp->transmission_flags & NBD_FLAG_CAN_MULTI_CONN) == 0 &&
	    nsockets > 1) {
		g_destroy_geom(gp);
		free_unr(g_nbd_unit, unit);
		gctl_error(req, "Server doesn't support multiple connections.");
		return;
	}
	sockets = g_nbd_ctl_steal_sockets(req, nsockets);
	if (sockets == NULL) {
		g_destroy_geom(gp);
		free_unr(g_nbd_unit, unit);
		return;
	}
	sc = g_malloc(sizeof(*sc), M_WAITOK | M_ZERO);
	sc->sc_host = strdup(host, M_GEOM);
	sc->sc_port = strdup(port, M_GEOM);
	sc->sc_name = strdup(name, M_GEOM);
	if (description != NULL)
		sc->sc_description = strdup(description, M_GEOM);
	sc->sc_size = *sizep;
	sc->sc_flags = flagsp->flags;
	/*
	 * NB: Servers may advertise minblocksize as small as 1 byte, but
	 * clients should make requests of at least 512 bytes.
	 */
	sc->sc_minblocksize = MAX(*minbsp, 1 << 9 /* 512 */);
	/* NB: Servers must abide this constraint, but we ensure it. */
	sc->sc_prefblocksize = MAX(*prefbsp, sc->sc_minblocksize);
	sc->sc_maxpayload = maxsz;
	sc->sc_unit = unit;
	sc->sc_tls = *tlsp;
	sc->sc_geom = gp;
	bio_queue_init(&sc->sc_queue);
	mtx_init(&sc->sc_queue_mtx, "gnbd:queue", NULL, MTX_DEF);
	SLIST_INIT(&sc->sc_connections);
	mtx_init(&sc->sc_conns_mtx, "gnbd:connections", NULL, MTX_DEF);
	sx_init(&sc->sc_flush_lock, "gnbd:flush");
	gp->softc = sc;
	pp = g_new_providerf(gp, "%s", gp->name);
	pp->flags |= G_PF_DIRECT_SEND | G_PF_DIRECT_RECEIVE |
	    G_PF_ACCEPT_UNMAPPED;
	pp->mediasize = sc->sc_size;
	pp->sectorsize = sc->sc_minblocksize;
	pp->stripesize = sc->sc_prefblocksize;
	sc->sc_provider = pp;
	g_error_provider(pp, 0);
	for (int i = 0; i < nsockets; i++)
		g_nbd_add_conn(sc, sockets[i], gp->name, i == 0);
	g_free(sockets);
	gctl_set_param_err(req, "provider", pp->name, strlen(pp->name) + 1);
}

static inline struct g_geom *
g_nbd_find_geom(struct g_class *mp, const char *name)
{
	struct g_nbd_softc *sc;
	struct g_geom *gp;

	LIST_FOREACH(gp, &mp->geom, geom) {
		sc = gp->softc;
		if (sc == NULL || sc->sc_nconns == 0)
			continue;
		if (strcmp(gp->name, name) == 0)
			break;
	}
	return (gp);
}

static void
g_nbd_ctl_scale(struct gctl_req *req, struct g_class *mp)
{
	struct g_nbd_softc *sc;
	struct g_geom *gp;
	const char *name;
	intmax_t *cp;
	struct socket **sockets;
	int *nsocketsp;
	int nconns, nsockets;

	g_topology_assert();

	G_NBD_DEBUG(G_NBD_TRACE, "%s", __func__);
	name = gctl_get_asciiparam(req, "arg0");
	if (name == NULL) {
		gctl_error(req, "Missing device.");
		return;
	}
	cp = gctl_get_paraml(req, "connections", sizeof(*cp));
	if (cp == NULL) {
		gctl_error(req, "No 'connections' argument.");
		return;
	}
	nconns = *cp;
	if (nconns < 1) {
		gctl_error(req, "Invalid 'connections' argument.");
		return;
	}
	gp = g_nbd_find_geom(mp, name);
	if (gp == NULL) {
		gctl_error(req, "Device '%s' is invalid.", name);
		return;
	}
	sc = gp->softc;
	if ((sc->sc_transmission_flags & NBD_FLAG_CAN_MULTI_CONN) == 0 &&
	    nconns > 1) {
		gctl_error(req, "Server doesn't support multiple connections.");
		return;
	}
	mtx_lock(&sc->sc_conns_mtx);
	if (sc->sc_nconns == nconns) {
		mtx_unlock(&sc->sc_conns_mtx);
		return;
	}
	if (sc->sc_nconns > nconns) {
		struct nbd_conn *nc;
		int n = sc->sc_nconns;

		/* TODO: scaling down is delivering errors, can we fix? */
		SLIST_FOREACH(nc, &sc->sc_connections, nc_connections) {
			nbd_conn_degrade_state(nc, NBD_CONN_SOFT_DISCONNECTING);
			if (--n == nconns)
				break;
		}
		mtx_unlock(&sc->sc_conns_mtx);
		wakeup(&sc->sc_queue);
		/* The sender threads will take care of the cleanup. */
		return;
	}
	mtx_unlock(&sc->sc_conns_mtx);
	nsocketsp = gctl_get_paraml(req, "nsockets", sizeof(nsockets));
	if (nsocketsp == NULL) {
		gctl_error(req, "No 'nsockets' argument.");
		return;
	}
	nsockets = *nsocketsp;
	sockets = g_nbd_ctl_steal_sockets(req, nsockets);
	if (sockets == NULL)
		return;
	for (int i = 0; i < nsockets; i++)
		g_nbd_add_conn(sc, sockets[i], gp->name, false);
	g_free(sockets);
}

static void
g_nbd_destroy(struct g_nbd_softc *sc)
{
	struct nbd_conn *nc;

	g_topology_assert();

	G_NBD_DEBUG(G_NBD_TRACE, "%s", __func__);
	mtx_lock(&sc->sc_conns_mtx);
	SLIST_FOREACH(nc, &sc->sc_connections, nc_connections)
		nbd_conn_degrade_state(nc, NBD_CONN_SOFT_DISCONNECTING);
	mtx_unlock(&sc->sc_conns_mtx);
	wakeup(&sc->sc_queue);
	/* The sender threads will take care of the cleanup. */
}

static void
g_nbd_ctl_disconnect(struct gctl_req *req, struct g_class *mp)
{
	struct g_geom *gp;
	const char *name;

	g_topology_assert();

	G_NBD_DEBUG(G_NBD_TRACE, "%s", __func__);
	name = gctl_get_asciiparam(req, "arg0");
	if (name == NULL) {
		gctl_error(req, "Missing device.");
		return;
	}
	gp = g_nbd_find_geom(mp, name);
	if (gp == NULL) {
		gctl_error(req, "Device '%s' is invalid.", name);
		return;
	}
	g_nbd_destroy(gp->softc);
}

static void
g_nbd_ctl_config(struct gctl_req *req, struct g_class *mp, const char *verb)
{
	uint32_t *version;

	g_topology_assert();

	G_NBD_DEBUG(G_NBD_TRACE, "%s", __func__);
	version = gctl_get_paraml(req, "version", sizeof(*version));
	if (version == NULL) {
		gctl_error(req, "No 'version' argument.");
		return;
	}
	if (*version != G_NBD_VERSION) {
		gctl_error(req, "Userland and kernel parts are out of sync.");
		return;
	}

	if (strcmp(verb, "connect") == 0) {
		g_nbd_ctl_connect(req, mp);
		return;
	} else if (strcmp(verb, "scale") == 0) {
		g_nbd_ctl_scale(req, mp);
		return;
	} else if (strcmp(verb, "disconnect") == 0) {
		g_nbd_ctl_disconnect(req, mp);
		return;
	}
	/* TODO: rescue? */

	gctl_error(req, "Unknown verb.");
}

static int
g_nbd_ctl_destroy(struct gctl_req *req __unused, struct g_class *mp __unused,
    struct g_geom *gp)
{
	struct g_nbd_softc *sc = gp->softc;

	g_topology_assert();

	G_NBD_DEBUG(G_NBD_TRACE, "%s", __func__);
	g_nbd_destroy(sc);
	return (EBUSY);
}

static void
g_nbd_init(struct g_class *mp __unused)
{
	size_t sz;

	G_NBD_DEBUG(G_NBD_TRACE, "%s", __func__);
	sx_init(&g_nbd_lock, "GEOM NBD connections");
	g_nbd_unit = new_unrhdr(0, INT_MAX, NULL);
	g_nbd_inflight_zone = uma_zcreate("nbd_inflight",
	    sizeof(struct nbd_inflight), NULL, NULL, NULL, NULL,
	    UMA_ALIGN_PTR, 0);
	sz = sizeof(g_nbd_tlsmax);
	if (kernel_sysctlbyname(curthread, "kern.ipc.tls.maxlen",
	    &g_nbd_tlsmax, &sz, NULL, 0, NULL, 0) != 0)
		g_nbd_tlsmax = 0;
}

static void
g_nbd_fini(struct g_class *mp __unused)
{
	G_NBD_DEBUG(G_NBD_TRACE, "%s", __func__);
	KASSERT(g_nbd_nconns == 0, ("connections still running"));
	uma_zdestroy(g_nbd_inflight_zone);
	delete_unrhdr(g_nbd_unit);
	sx_destroy(&g_nbd_lock);
}

static inline void
bio_queue_insert_tail(struct bio_queue *queue, struct bio *bp)
{
	TAILQ_INSERT_TAIL(queue, bp, bio_queue);
}

static inline bool
g_nbd_limit(struct g_nbd_softc *sc, struct bio *bp)
{
	off_t maxsz = sc->sc_maxpayload;

	if (bp->bio_length <= maxsz)
		return (false);
	bp->bio_length = maxsz;
	if ((bp->bio_flags & BIO_UNMAPPED) != 0)
		bp->bio_ma_n =
		    howmany(bp->bio_ma_offset + bp->bio_length, PAGE_SIZE);
	return (true);
}

static inline void
g_nbd_issue(struct g_nbd_softc *sc, struct bio *bp)
{
	bool first;

	mtx_lock(&sc->sc_queue_mtx);
	first = bio_queue_empty(&sc->sc_queue);
	bio_queue_insert_tail(&sc->sc_queue, bp);
	mtx_unlock(&sc->sc_queue_mtx);
	if (first)
		wakeup_one(&sc->sc_queue);
}

static void
g_nbd_done(struct bio *bp)
{
	struct bio *pbp;
	u_int inbed;

	pbp = bp->bio_parent;
	/*
	 * An error is set only once on the parent.  If there are multiple
	 * children with errors, the first to make it here wins.  We use atomic
	 * operations to guard against multiple child bios completing on
	 * different threads without contending for a lock.  See sys/geom/notes.
	 */
	atomic_cmpset_int(&pbp->bio_error, 0, bp->bio_error);
	atomic_add_64(&pbp->bio_completed, bp->bio_completed);
	inbed = atomic_fetchadd_int(&pbp->bio_inbed, 1) + 1;
	if (pbp->bio_children == inbed)
		g_io_deliver(pbp, pbp->bio_error);
	g_destroy_bio(bp);
}

static inline void
g_nbd_advance(struct bio *bp, off_t offset)
{
	bp->bio_offset += offset;
	bp->bio_length -= offset;
	if ((bp->bio_flags & BIO_UNMAPPED) != 0) {
		bp->bio_ma += offset / PAGE_SIZE;
		bp->bio_ma_offset += offset;
		bp->bio_ma_offset %= PAGE_SIZE;
		bp->bio_ma_n -= offset / PAGE_SIZE;
	} else {
		bp->bio_data += offset;
	}
}

static inline int
g_nbd_format_ident_full(struct g_nbd_softc *sc, struct bio *bp)
{
	if (snprintf(bp->bio_data, bp->bio_length, "%s:%s/%s",
	    sc->sc_host, sc->sc_port, sc->sc_name) >= bp->bio_length)
		return (EFAULT);
	return (0);
}

static inline int
g_nbd_format_ident_name(struct g_nbd_softc *sc, struct bio *bp)
{
	if (snprintf(bp->bio_data, bp->bio_length, "%s", sc->sc_name)
	    >= bp->bio_length)
		return (EFAULT);
	return (0);
}

static inline int
g_nbd_handleattr_ident(struct g_nbd_softc *sc, struct bio *bp)
{
	int error = 0;

	if (strcmp(bp->bio_attribute, "GEOM::ident") != 0)
		return (0);
	memset(bp->bio_data, 0, bp->bio_length);
	switch (identfmt) {
	default:
	case 0:
		error = g_nbd_format_ident_full(sc, bp);
		break;
	case 1:
		if (strcmp(sc->sc_name, "") == 0)
			error = g_nbd_format_ident_full(sc, bp);
		else
			error = g_nbd_format_ident_name(sc, bp);
		break;
	case 2:
		error = g_nbd_format_ident_name(sc, bp);
		break;
	}
	if (error == 0)
		bp->bio_completed = bp->bio_length;
	g_io_deliver(bp, error);
	return (1);
}

static void
g_nbd_start(struct bio *bp)
{
	struct g_geom *gp = bp->bio_to->geom;
	struct g_nbd_softc *sc = gp->softc;
	struct bio *bp1, *bp2;
	off_t offset;

	G_NBD_LOGREQ(G_NBD_TRACE, bp, "%s", __func__);
	if (sc == NULL) {
		G_NBD_LOGREQ(G_NBD_ERROR, bp, "%s softc NULL", __func__);
		g_io_deliver(bp, ENXIO);
		return;
	}
	/*
	 * XXX: Nothing seems to ever set this flag, and most GEOM
	 * classes never check for it.  Assume we will never see a bio
	 * with it for now.
	 */
	if ((bp->bio_flags & BIO_VLIST) != 0) {
		G_NBD_LOGREQ(G_NBD_ERROR, bp, "%s BIO_VLIST not implemented",
		    __func__);
		g_io_deliver(bp, EFAULT);
		return;
	}
	switch (bp->bio_cmd) {
	case BIO_DELETE:
	case BIO_FLUSH:
	case BIO_WRITE:
		if ((sc->sc_transmission_flags & NBD_FLAG_READ_ONLY) != 0) {
			G_NBD_LOGREQ(G_NBD_INFO, bp, "%s device is read only",
			    __func__);
			g_io_deliver(bp, EPERM);
			return;
		}
	}
	switch (bp->bio_cmd) {
	case BIO_DELETE:
		if ((sc->sc_transmission_flags & NBD_FLAG_SEND_TRIM) == 0) {
			G_NBD_LOGREQ(G_NBD_INFO, bp, "%s TRIM unsupported",
			    __func__);
			g_io_deliver(bp, EOPNOTSUPP);
			return;
		}
		break;
	case BIO_FLUSH:
		if ((sc->sc_transmission_flags & NBD_FLAG_SEND_FLUSH) == 0) {
			G_NBD_LOGREQ(G_NBD_INFO, bp, "%s FLUSH unsupported",
			    __func__);
			g_io_deliver(bp, EOPNOTSUPP);
			return;
		}
		break;
	case BIO_READ:
	case BIO_WRITE:
		bp1 = g_clone_bio(bp);
		if (bp1 == NULL) {
			g_io_deliver(bp, ENOMEM);
			return;
		}
		offset = 0;
		bp2 = NULL;
		for (;;) {
			if (g_nbd_limit(sc, bp1)) {
				offset += bp1->bio_length;
				/* Grab next bio now to avoid race. */
				bp2 = g_clone_bio(bp);
				if (bp2 == NULL)
					bp->bio_error = ENOMEM;
			}
			bp1->bio_done = g_nbd_done;
			bp1->bio_to = bp->bio_to;
			g_nbd_issue(sc, bp1);
			if (bp2 == NULL)
				break;
			bp1 = bp2;
			bp2 = NULL;
			g_nbd_advance(bp1, offset);
		}
		return;
	case BIO_GETATTR:
		if (g_handleattr_int(bp, "GEOM::candelete",
		    (sc->sc_transmission_flags & NBD_FLAG_SEND_TRIM) != 0))
			return;
		if (g_handleattr_uint16_t(bp, "GEOM::rotation_rate",
		    (sc->sc_transmission_flags & NBD_FLAG_ROTATIONAL) != 0 ?
		    DISK_RR_UNKNOWN : DISK_RR_NON_ROTATING))
			return;
		if (g_nbd_handleattr_ident(sc, bp) != 0)
			return;
		if (sc->sc_description != NULL &&
		    g_handleattr_str(bp, "GEOM::descr", sc->sc_description))
			return;
		G_NBD_LOGREQ(G_NBD_INFO, bp, "%s unsupported attribute",
		    __func__);
		g_io_deliver(bp, ENOIOCTL);
		return;
	default:
		G_NBD_LOGREQ(G_NBD_INFO, bp, "%s unsupported operation",
		    __func__);
		g_io_deliver(bp, EOPNOTSUPP);
		return;
	}
	g_nbd_issue(sc, bp);
}

static void
g_nbd_dumpconf(struct sbuf *sb, const char *indent, struct g_geom *gp,
    struct g_consumer *cp, struct g_provider *pp)
{
	struct g_nbd_softc *sc;

	g_topology_assert();

	G_NBD_DEBUG(G_NBD_TRACE, "%s", __func__);
	if (pp != NULL)
		return;
	sc = gp->softc;
	if (sc == NULL)
		return;
	sbuf_printf(sb, "%s<Host>%s</Host>\n", indent, sc->sc_host);
	sbuf_printf(sb, "%s<Port>%s</Port>\n", indent, sc->sc_port);
	sbuf_printf(sb, "%s<Name>%s</Name>\n", indent, sc->sc_name);
	if (sc->sc_description != NULL)
		sbuf_printf(sb, "%s<Description>%s</Description>\n", indent,
		    sc->sc_description);
	sbuf_printf(sb, "%s<Size>%lu</Size>\n", indent, sc->sc_size);
#define NBD_FLAG(id) { NBD_FLAG_ ## id, #id }
	sbuf_printf(sb, "%s<HandshakeFlags>", indent);
	if (sc->sc_handshake_flags == 0)
		sbuf_cat(sb, "NONE");
	else {
		const struct { uint16_t flag; const char *name; } flags[] = {
			NBD_FLAG(FIXED_NEWSTYLE),
			NBD_FLAG(NO_ZEROES),
		};
		uint16_t unknown, check = 0;

		for (int i = 0; i < nitems(flags); i++) {
			if ((sc->sc_handshake_flags & flags[i].flag) != 0) {
				if (check != 0)
					sbuf_cat(sb, ", ");
				sbuf_cat(sb, flags[i].name);
				check |= flags[i].flag;
			}
		}
		unknown = sc->sc_handshake_flags & ~check;
		if (unknown != 0) {
			if (check != 0)
				sbuf_cat(sb, ", ");
			sbuf_printf(sb, "0x%x", unknown);
		}
	}
	sbuf_cat(sb, "</HandshakeFlags>\n");
	sbuf_printf(sb, "%s<TransmissionFlags>", indent);
	if (sc->sc_transmission_flags == 0)
		sbuf_cat(sb, "NONE");
	else {
		const struct { uint16_t flag; const char *name; } flags[] = {
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
		uint16_t unknown, check = 0;

		for (int i = 0; i < nitems(flags); i++) {
			if ((sc->sc_transmission_flags & flags[i].flag) != 0) {
				if (check != 0)
					sbuf_cat(sb, ", ");
				sbuf_cat(sb, flags[i].name);
				check |= flags[i].flag;
			}
		}
		unknown = sc->sc_transmission_flags & ~check;
		if (unknown != 0) {
			if (check != 0)
				sbuf_cat(sb, ", ");
			sbuf_printf(sb, "0x%x", unknown);
		}
	}
	sbuf_cat(sb, "</TransmissionFlags>\n");
#undef NBD_FLAG
	sbuf_printf(sb, "%s<MinimumBlocksize>%u</MinimumBlocksize>\n", indent,
	    sc->sc_minblocksize);
	sbuf_printf(sb, "%s<PreferredBlocksize>%u</PreferredBlocksize>\n",
	    indent, sc->sc_prefblocksize);
	sbuf_printf(sb, "%s<MaximumPayload>%u</MaximumPayload>\n", indent,
	    sc->sc_maxpayload);
	sbuf_printf(sb, "%s<TLS>%s</TLS>\n", indent, sc->sc_tls ? "yes" : "no");
	sbuf_printf(sb, "%s<Connections>%u</Connections>\n", indent,
	    sc->sc_nconns);
}

static struct g_class g_nbd_class = {
	.name = G_NBD_CLASS_NAME,
	.version = G_VERSION,
	.ctlreq = g_nbd_ctl_config,
	.destroy_geom = g_nbd_ctl_destroy,
	.init = g_nbd_init,
	.fini = g_nbd_fini,
	.start = g_nbd_start,
	.dumpconf = g_nbd_dumpconf,
	.access = g_std_access,
};

DECLARE_GEOM_CLASS(g_nbd_class, g_nbd);
MODULE_VERSION(geom_nbd, 0);

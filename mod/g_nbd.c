/*
 * Copyright (c) 2025 Ryan Moeller
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <sys/param.h>
#include <sys/bio.h>
#include <sys/capsicum.h>
#include <sys/condvar.h>
#include <sys/counter.h>
#include <sys/file.h>
#include <sys/kthread.h>
#include <sys/ktr.h>
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
#include <sys/resourcevar.h>
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
#include <vm/vm_object.h>
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
static uint32_t maxpayload = 1 << 25;
SYSCTL_U32(_kern_geom_nbd, OID_AUTO, maxpayload, CTLFLAG_RWTUN, &maxpayload, 0,
    "Default maximum payload size");
static u_long sendspace = 1536 * 1024;
SYSCTL_ULONG(_kern_geom_nbd, OID_AUTO, sendspace, CTLFLAG_RWTUN, &sendspace, 0,
    "Default socket send buffer size");
static u_long recvspace = 1536 * 1024;
SYSCTL_ULONG(_kern_geom_nbd, OID_AUTO, recvspace, CTLFLAG_RWTUN, &recvspace, 0,
    "Default socket receive buffer size");
static int identfmt = 0;
SYSCTL_INT(_kern_geom_nbd, OID_AUTO, identfmt, CTLFLAG_RWTUN, &identfmt, 0,
    "Format of GEOM::ident (0=host:port/name, 1=name||host:port/name, 2=name)");

static SYSCTL_NODE(_kern_geom_nbd, OID_AUTO, stats, CTLFLAG_RW | CTLFLAG_MPSAFE,
    0, "GEOM NBD stats");
static COUNTER_U64_DEFINE_EARLY(g_nbd_write_copied);
SYSCTL_COUNTER_U64(_kern_geom_nbd_stats, OID_AUTO, write_copied, CTLFLAG_RD,
    &g_nbd_write_copied,
    "Number of bytes copied for write bios");
static COUNTER_U64_DEFINE_EARLY(g_nbd_enomems);
SYSCTL_COUNTER_U64(_kern_geom_nbd_stats, OID_AUTO, enomems, CTLFLAG_RD,
    &g_nbd_enomems,
    "Number of times allocation failed");
static COUNTER_U64_DEFINE_EARLY(g_nbd_write_truncs);
SYSCTL_COUNTER_U64(_kern_geom_nbd_stats, OID_AUTO, write_truncs, CTLFLAG_RD,
    &g_nbd_write_truncs,
    "Number of times write limit was truncated to a page boundary");
static COUNTER_U64_DEFINE_EARLY(g_nbd_read_truncs);
SYSCTL_COUNTER_U64(_kern_geom_nbd_stats, OID_AUTO, read_truncs, CTLFLAG_RD,
    &g_nbd_read_truncs,
    "Number of times read limit was truncated to a page boundary");

enum {
	G_NBD_ERROR,
	G_NBD_WARN,
	G_NBD_INFO,
	G_NBD_DEBUG,
};

#define G_NBD_LOG(lvl, ...) \
    _GEOM_DEBUG("GEOM_NBD", g_nbd_debug, (lvl), NULL, __VA_ARGS__)
#define G_NBD_LOGREQ(lvl, bp, ...) \
    _GEOM_DEBUG("GEOM_NBD", g_nbd_debug, (lvl), (bp), __VA_ARGS__)

#define KTR_NBD KTR_SPARE4

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
	struct cv		nc_send_cv;
	struct cv		nc_receive_cv;
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

	CTR4(KTR_NBD, "%s nc=%p bp=%p cookie=%lu", __func__, nc, bp,
	    nc->nc_seq);
	ni = uma_zalloc(g_nbd_inflight_zone, M_NOWAIT | M_ZERO);
	if (__predict_false(ni == NULL))
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
	CTR3(KTR_NBD, "%s nc=%p cookie=%lu", __func__, nc, ni->ni_cookie);
	mtx_lock(&nc->nc_inflight_mtx);
	TAILQ_REMOVE(&nc->nc_inflight, ni, ni_inflight);
	mtx_unlock(&nc->nc_inflight_mtx);
	if (__predict_false(atomic_load_bool(&nc->nc_softc->sc_flushing))) {
		switch (ni->ni_bio->bio_cmd) {
		case BIO_DELETE:
		case BIO_WRITE:
			wakeup_one(ni);
		}
	}
}

static inline void
nbd_inflight_deliver(struct nbd_inflight *ni, int error)
{
	struct bio *bp = ni->ni_bio;

	CTR3(KTR_NBD, "%s cookie=%lu error=%d", __func__, ni->ni_cookie, error);
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

	CTR2(KTR_NBD, "%s cookie=%lu", __func__, ni->ni_cookie);
	nbd_inflight_deliver(ni, 0);
}

#ifdef KTR
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
#endif

/*
 * Degrade nc->nc_state if possible, locklessly.
 */
static inline void
nbd_conn_degrade_state(struct nbd_conn *nc, enum nbd_conn_state state)
{
	KASSERT(NBD_CONN_CONNECTED < state && state < NBD_CONN_CLOSED,
	    ("tried degrading to an invalid state"));

	CTR6(KTR_NBD, "%s nc=%p nc_state=%s (%d) -> state=%s (%d)",
	    __func__, nc, nbd_conn_state_str(nc->nc_state), nc->nc_state,
	    nbd_conn_state_str(state), state);
	if (atomic_cmpset_int(&nc->nc_state, NBD_CONN_CONNECTED, state))
		return;
	atomic_cmpset_int(&nc->nc_state, NBD_CONN_SOFT_DISCONNECTING, state);
}

static inline bool
nbd_conn_send_ok(struct nbd_conn *nc, struct bio *bp)
{
	struct socket *so = nc->nc_socket;

	if (__predict_false(atomic_load_int(&nc->nc_state) !=
	    NBD_CONN_CONNECTED)) {
		CTR5(KTR_NBD, "%s nc=%p bp=%p nc_state=%s (%d)", __func__, nc,
		    bp, nbd_conn_state_str(nc->nc_state), nc->nc_state);
		return (false);
	}
	if (__predict_false(so->so_error != 0)) {
		G_NBD_LOGREQ(G_NBD_WARN, bp, "socket error %d", so->so_error);
		CTR4(KTR_NBD, "%s nc=%p bp=%p so_error=%d", __func__, nc, bp,
		    so->so_error);
		return (false);
	}
	if (__predict_false((so->so_state & SS_ISCONNECTED) == 0)) {
		CTR3(KTR_NBD, "%s nc=%p bp=%p socket not connected", __func__,
		    nc, bp);
		return (false);
	}
	if (__predict_false((so->so_snd.sb_state & SBS_CANTSENDMORE) != 0)) {
		CTR3(KTR_NBD, "%s nc=%p bp=%p socket cannot send more",
		    __func__, nc, bp);
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
		if (__predict_false(m == NULL))
			return (NULL);
		m->m_epg_last_len = needed;
		m->m_ext.ext_size = PAGE_SIZE;
		*reqp = (void *)PHYS_TO_DMAP(m->m_epg_pa[0]);
	} else {
		m = m_get(M_NOWAIT, MT_DATA);
		if (__predict_false(m == NULL))
			return (NULL);
		*reqp = mtod(m, void *);
	}
	m->m_len = needed;
	return (m);
}

static struct mbuf *
nbd_write_mbufs(struct nbd_inflight *ni, bool tls, size_t limit, size_t *offset)
{
	struct bio *bp = ni->ni_bio;
	vm_ooffset_t start = *offset;
	struct mbuf *m;

	KASSERT(limit > 0, ("%s limit is zero", __func__));
	KASSERT(start < bp->bio_length, ("%s offset %zu out of bounds",
	    __func__, start));

	CTR5(KTR_NBD, "%s cookie=%lu %s limit=%zu *offset=%zu", __func__,
	    ni->ni_cookie, tls ? "tls" : "notls", limit, start);
	if ((bp->bio_flags & BIO_UNMAPPED) != 0) {
		struct mbuf *d, *m_tail;
		size_t page_offset = start == 0 ? bp->bio_ma_offset : 0;
		size_t resid = bp->bio_length;
		size_t len;

		CTR3(KTR_NBD, "%s cookie=%lu unmapped write (%s)", __func__,
		    ni->ni_cookie, tls ? "tls" : "notls");
		if (resid > limit) {
			/* Reduce limit to end on a page boundary. */
			resid = trunc_page(limit - page_offset) + page_offset;
			counter_u64_add(g_nbd_write_truncs, 1);
		}
		*offset += resid;
		m = m_tail = d = NULL;
		for (int i = OFF_TO_IDX(start + page_offset);
		    resid > 0; i++) {
			if (d == NULL) {
				d = mb_alloc_ext_pgs(M_NOWAIT,
#if __FreeBSD_version > 1500026
				    nbd_inflight_free_mext, M_RDONLY);
#else
				    nbd_inflight_free_mext);
#endif
				if (__predict_false(d == NULL)) {
					m_freem(m);
					return (NULL);
				}
				refcount_acquire(&ni->ni_refs);
				d->m_ext.ext_arg1 = ni;
				d->m_epg_1st_off = page_offset;
				if (m == NULL)
					m = d;
			}
			len = MIN(resid, PAGE_SIZE - page_offset);
			MPASS(i < bp->bio_ma_n);
			d->m_epg_pa[d->m_epg_npgs++] =
			    VM_PAGE_TO_PHYS(bp->bio_ma[i]);
			d->m_epg_last_len = len;
			d->m_len += len;
			d->m_ext.ext_size += PAGE_SIZE;
			MBUF_EXT_PGS_ASSERT_SANITY(d);
			if (d->m_epg_npgs == MBUF_PEXT_MAX_PGS || (tls &&
			    d->m_epg_npgs == (g_nbd_tlsmax >> PAGE_SHIFT))) {
				if (m_tail != NULL)
					m_tail->m_next = d;
				m_tail = d;
				d = NULL;
			}
			page_offset = 0;
			resid -= len;
		}
		if (m_tail != NULL)
			m_tail->m_next = d;
	} else if (tls) {
		struct mbuf *d, *m_tail;
		off_t start = *offset;
		c_caddr_t data = bp->bio_data + start;
		size_t resid = bp->bio_length - start;
		size_t len;

		CTR2(KTR_NBD, "%s cookie=%lu mapped write (tls)", __func__,
		    ni->ni_cookie);
		if (resid > limit) {
			/* Reduce limit to end on a page boundary. */
			resid = trunc_page(limit);
			counter_u64_add(g_nbd_write_truncs, 1);
		}
		*offset += resid;
		m = NULL;
		while (resid > 0) {
			len = MIN(resid, MBUF_PEXT_MAX_PGS * PAGE_SIZE);
			len = MIN(len, g_nbd_tlsmax);
			d = mb_alloc_ext_plus_pages(len, M_NOWAIT);
			if (__predict_false(d == NULL)) {
				m_freem(m);
				return (NULL);
			}
			d->m_len = len;
			d->m_ext.ext_size = d->m_epg_npgs * PAGE_SIZE;
			d->m_epg_last_len =
			    PAGE_SIZE - (d->m_ext.ext_size - len);
			MBUF_EXT_PGS_ASSERT_SANITY(d);
			counter_u64_add(g_nbd_write_copied, len);
			/* XXX: any way to avoid this copy? */
			m_copyback(d, 0, len, data);
			if (m == NULL)
				m = m_tail = d;
			else {
				m_tail->m_next = d;
				m_tail = d;
			}
			data += len;
			resid -= len;
		}
	} else {
		size_t len = MIN(bp->bio_length - start, limit);

		CTR2(KTR_NBD, "%s cookie=%lu mapped write (notls)", __func__,
		    ni->ni_cookie);
		m = m_get(M_NOWAIT, MT_DATA);
		if (__predict_false(m == NULL))
			return (NULL);
		refcount_acquire(&ni->ni_refs);
		m_extadd(m, bp->bio_data + start, len, nbd_inflight_free_mext,
		    ni, NULL, M_RDONLY, EXT_MOD_TYPE);
		m->m_len = len;
		*offset += len;
	}
	return (m);
}

static void
nbd_conn_send(struct nbd_conn *nc, struct nbd_inflight *ni)
{
	struct socket *so = nc->nc_socket;
	struct bio *bp = ni->ni_bio;
	struct nbd_request *req;
	struct mbuf *m;
	size_t offset, resid;
	long needed, wanted; /* must be signed */
	uint16_t flags = 0; /* no command flags supported currently */
	int16_t cmd = bio_to_nbd_cmd(bp);
	int error;
	bool tls = nc->nc_softc->sc_tls;

	KASSERT(cmd != -1, ("unsupported bio command queued: %s (%d)",
	    bio_cmd_str(bp), bp->bio_cmd));

	CTR2(KTR_NBD, "%s cookie=%lu", __func__, ni->ni_cookie);
	m = nbd_request_mbuf(tls, &req);
	if (__predict_false(m == NULL)) {
		counter_u64_add(g_nbd_enomems, 1);
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
	needed = resid = sizeof(*req);
	if (cmd == NBD_CMD_WRITE)
		resid += bp->bio_length;
	offset = 0;
	do {
		if (cmd == NBD_CMD_WRITE) {
			size_t limit = so->so_snd.sb_hiwat - needed;
			size_t prev_offset = offset;
			struct mbuf *d;

			d = nbd_write_mbufs(ni, tls, limit, &offset);
			if (__predict_false(d == NULL)) {
				m_free(m);
				counter_u64_add(g_nbd_enomems, 1);
				nbd_conn_remove_inflight_specific(nc, ni);
				nbd_inflight_deliver(ni, ENOMEM);
				return;
			}
			if (m == NULL)
				m = d;
			else
				m->m_next = d;
			needed += offset - prev_offset;
		}
		MPASS(m != NULL);
		MPASS(needed == m_length(m, NULL));
		SOCK_SENDBUF_LOCK(so);
		for (;;) {
			if (__predict_false(!nbd_conn_send_ok(nc, bp))) {
				SOCK_SENDBUF_UNLOCK(so);
				G_NBD_LOGREQ(G_NBD_INFO, bp, "%s disconnecting",
				    __func__);
				nbd_conn_degrade_state(nc,
				    NBD_CONN_HARD_DISCONNECTING);
				m_freem(m);
				nbd_conn_remove_inflight_specific(nc, ni);
				nbd_inflight_deliver(ni, ENXIO);
				return;
			}
			if (sbspace(&so->so_snd) >= needed)
				break;
			/*
			 * Potentially wait for more space than we need, to
			 * reduce how frequently we sleep in exchange for how
			 * long we sleep.  This can also reduce contention for
			 * the sendbuf lock.
			 */
			wanted = MAX(needed, so->so_snd.sb_hiwat / 8);
			MPASS(wanted <= so->so_snd.sb_hiwat);
			so->so_snd.sb_lowat = wanted;
			cv_wait(&nc->nc_send_cv, SOCK_SENDBUF_MTX(so));
			so->so_snd.sb_lowat = so->so_snd.sb_hiwat + 1;
		}
		SOCK_SENDBUF_UNLOCK(so);
		error = sosend(so, NULL, NULL, m, NULL, MSG_DONTWAIT, NULL);
		if (__predict_false(error != 0)) {
			G_NBD_LOGREQ(G_NBD_ERROR, bp, "%s sosend failed (%d)",
			    __func__, error);
			nbd_conn_degrade_state(nc, NBD_CONN_HARD_DISCONNECTING);
			if (error == ENOMEM)
				counter_u64_add(g_nbd_enomems, 1);
			nbd_conn_remove_inflight_specific(nc, ni);
			nbd_inflight_deliver(ni, error);
			return;
		}
		resid -= needed;
		needed = 0;
		m = NULL;
	} while (resid > 0);
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
	if (__predict_false(reply->magic != NBD_SIMPLE_REPLY_MAGIC)) {
		G_NBD_LOG(G_NBD_INFO, "magic=0x%08x != 0x%08x", reply->magic,
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

/* Not in releases yet. */
#ifndef TAILQ_EMPTY_ATOMIC
#define TAILQ_EMPTY_ATOMIC(head) \
	(atomic_load_ptr(&(head)->tqh_first) == NULL)
#endif

static inline bool
nbd_conn_recv_ok(struct nbd_conn *nc)
{
	struct socket *so = nc->nc_socket;
	enum nbd_conn_state state = atomic_load_int(&nc->nc_state);

	if (__predict_false(state == NBD_CONN_HARD_DISCONNECTING)) {
		CTR4(KTR_NBD, "%s nc=%p nc_state=%s (%d)", __func__, nc,
		    nbd_conn_state_str(nc->nc_state), nc->nc_state);
		return (false);
	}
	if (__predict_false(state == NBD_CONN_SOFT_DISCONNECTING) &&
	    TAILQ_EMPTY_ATOMIC(&nc->nc_inflight)) {
		G_NBD_LOG(G_NBD_INFO, "soft disconnected");
		CTR2(KTR_NBD, "%s nc=%p soft disconnect done", __func__, nc);
		return (false);
	}
	if (__predict_false(so->so_error != 0)) {
		G_NBD_LOG(G_NBD_WARN, "socket error %d", so->so_error);
		CTR3(KTR_NBD, "%s nc=%p so_error=%d", __func__, nc,
		    so->so_error);
		return (false);
	}
	if (__predict_false(so->so_rerror != 0)) {
		G_NBD_LOG(G_NBD_WARN, "socket receive error %d", so->so_rerror);
		CTR3(KTR_NBD, "%s nc=%p so_rerror=%d", __func__, nc,
		    so->so_rerror);
		return (false);
	}
	return (true);
}

static struct nbd_inflight *
nbd_conn_remove_inflight(struct nbd_conn *nc, uint64_t cookie)
{
	struct nbd_inflight *ni, *ni2;

	CTR3(KTR_NBD, "%s nc=%p cookie=%lu", __func__, nc, cookie);
	mtx_lock(&nc->nc_inflight_mtx);
	TAILQ_FOREACH_SAFE(ni, &nc->nc_inflight, ni_inflight, ni2) {
		if (ni->ni_cookie == cookie) {
			TAILQ_REMOVE(&nc->nc_inflight, ni, ni_inflight);
			break;
		}
	}
	mtx_unlock(&nc->nc_inflight_mtx);
	if (__predict_false(ni != NULL &&
	    atomic_load_bool(&nc->nc_softc->sc_flushing))) {
		switch (ni->ni_bio->bio_cmd) {
		case BIO_DELETE:
		case BIO_WRITE:
			wakeup_one(ni);
		}
	}
	return (ni);
}

static int
nbd_conn_recv_mbufs(struct nbd_conn *nc, size_t len, struct mbuf **mp)
{
	struct uio uio;
	struct socket *so = nc->nc_socket;
	struct mbuf *m, *m_tail, *m1;
	size_t available, expected;
	int flags, error;

	CTR3(KTR_NBD, "%s nc=%p len=%zu", __func__, nc, len);
	m = NULL;
	while (len > 0) {
		SOCK_RECVBUF_LOCK(so);
		for (;;) {
			if (__predict_false(!nbd_conn_recv_ok(nc))) {
				SOCK_RECVBUF_UNLOCK(so);
				G_NBD_LOG(G_NBD_INFO, "%s disconnecting",
				    __func__);
				nbd_conn_degrade_state(nc,
				    NBD_CONN_HARD_DISCONNECTING);
				if (error == ENOMEM)
					counter_u64_add(g_nbd_enomems, 1);
				m_freem(m);
				return (ENXIO);
			}
			available = sbavail(&so->so_rcv);
			if (available >= len)
				break;
			/*
			 * XXX: We may have to receive with sbavail() < len if
			 * mb efficiency is very bad.  For example, GCE images
			 * have mtu 1460 on lo0 by default, causing the loopback
			 * interface to pass traffic in JUMBOP mbufs but
			 * utilizing less than half of the space.  With large
			 * buffers, we do not get the safety net of
			 * sb_efficiency making mbmax 8x hiwat, so we can be out
			 * of buffer space and unable to receive more while
			 * being under the low water mark.
			 *
			 * Check if we are out of space here to avoid blocking
			 * the receive thread indefinitely.  It's possible all
			 * space is used by encrypted TLS records and none is
			 * available yet.  If so, we still need to wait for data
			 * to become available.
			 */
			if (available > 0 && sbspace(&so->so_rcv) <= 0)
				break;
			/*
			 * XXX: We may have a complete TLS record in the receive
			 * buffer and not enough space for the next record.  Get
			 * it out of the way.
			 */
			if (so->so_rcv.sb_mbtail != NULL &&
			    (so->so_rcv.sb_mbtail->m_flags & M_EOR) != 0)
				break;
			so->so_rcv.sb_lowat = MIN(len, so->so_rcv.sb_hiwat);
			cv_wait(&nc->nc_receive_cv, SOCK_RECVBUF_MTX(so));
			so->so_rcv.sb_lowat = so->so_rcv.sb_hiwat + 1;
		}
		SOCK_RECVBUF_UNLOCK(so);
		MPASS(available > 0);
		memset(&uio, 0, sizeof(uio));
		uio.uio_resid = expected = MIN(len, available);
		/*
		 * XXX: With MSG_TLSAPPDATA, soreceive() will return
		 * ENXIO when a TLS alert record is received.  This
		 * would have to be decoded by userland.  We will
		 * treat it as a fatal error, which it probably is.
		 * The details of the error will be lost, as we do not
		 * have a userland daemon to understand it.
		 */
		flags = MSG_DONTWAIT | MSG_TLSAPPDATA;
		/*
		 * TODO: Looking at cxgbe, if we pass iovecs in the uio instead
		 * of asking for an mbuf chain then the TOE can do zero-copy DDP
		 * into the bio for reads.  For T6 with crypto offload this can
		 * even work with TLS.  The sockets require TCP_USE_DDP opt set.
		 */
		error = soreceive(so, NULL, &uio, &m1, NULL, &flags);
		if (__predict_false(error != 0)) {
			G_NBD_LOG(G_NBD_ERROR, "%s soreceive failed (%d)",
			    __func__, error);
			nbd_conn_degrade_state(nc,
			    NBD_CONN_HARD_DISCONNECTING);
			if (error == ENOMEM)
				counter_u64_add(g_nbd_enomems, 1);
			m_freem(m);
			return (error);
		}
		MPASS(m1 != NULL);
		if (m == NULL)
			m = m_tail = m1;
		else {
			while (m_tail->m_next != NULL)
				m_tail = m_tail->m_next;
			m_tail->m_next = m1;
			m_tail = m1;
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

	CTR2(KTR_NBD, "%s nc=%p", __func__, nc);
	error = nbd_conn_recv_mbufs(nc, sizeof(reply), &m);
	if (__predict_false(error != 0))
		return;
	CTR2(KTR_NBD, "%s nc=%p received reply", __func__, nc);
	m_copydata(m, 0, sizeof(reply), (void *)&reply);
	m_freem(m);
	nbd_simple_reply_ntoh(&reply);
	if (__predict_false(!nbd_simple_reply_is_valid(&reply))) {
		G_NBD_LOG(G_NBD_ERROR, "%s received invalid reply", __func__);
		nbd_conn_degrade_state(nc, NBD_CONN_HARD_DISCONNECTING);
		return;
	}
	/* TODO: structured replies can have multiple replies per cookie */
	ni = nbd_conn_remove_inflight(nc, reply.cookie);
	if (__predict_false(ni == NULL)) {
		G_NBD_LOG(G_NBD_ERROR,
		    "%s did not find inflight bio for cookie %lu", __func__,
		    reply.cookie);
		nbd_conn_degrade_state(nc, NBD_CONN_SOFT_DISCONNECTING);
		return;
	}
	bp = ni->ni_bio;
	if (__predict_false(reply.error != 0)) {
		G_NBD_LOGREQ(G_NBD_WARN, bp,
		    "%s received reply with error (%d)", __func__, reply.error);
		if (reply.error == NBD_ESHUTDOWN)
			nbd_conn_degrade_state(nc, NBD_CONN_SOFT_DISCONNECTING);
		nbd_inflight_deliver(ni, nbd_error_to_errno(reply.error));
		return;
	}
	/* TODO: see comment above soreceive in nbd_conn_recv_mbufs */
	if (bp->bio_cmd == BIO_READ) {
		size_t offset = 0;
		size_t resid = bp->bio_length;

		/* Perform the read in batches to limit the memory usage. */
		while (resid > 0) {
			/* TODO: this could be tunable, needs profiling */
			size_t limit = nc->nc_socket->so_rcv.sb_hiwat;
			size_t len = resid;

			if (len > limit) {
				len = trunc_page(limit);
				counter_u64_add(g_nbd_read_truncs, 1);
			}
			error = nbd_conn_recv_mbufs(nc, len, &m);
			if (__predict_false(error != 0)) {
				nbd_inflight_deliver(ni, error);
				return;
			}
			CTR3(KTR_NBD, "%s nc=%p cookie=%lu received read data",
			    __func__, nc, ni->ni_cookie);
			if ((bp->bio_flags & BIO_UNMAPPED) != 0) {
				vm_offset_t vaddr;
				size_t page_offset =
				    offset == 0 ? bp->bio_ma_offset : 0;
				size_t offset1 = 0;
				size_t resid1 = len;
				size_t len1;

				CTR3(KTR_NBD,
				    "%s nc=%p cookie=%lu unmapped read",
				    __func__, nc, ni->ni_cookie);
				for (int i = OFF_TO_IDX(offset + page_offset);
				    resid1 > 0; i++) {
					len1 = MIN(resid1,
					    PAGE_SIZE - page_offset);
					MPASS(i < bp->bio_ma_n);
					vaddr = PHYS_TO_DMAP(VM_PAGE_TO_PHYS(
					    bp->bio_ma[i]));
					/* XXX: any way to avoid this copy? */
					m_copydata(m, offset1, len1,
					    (char *)vaddr + page_offset);
					page_offset = 0;
					offset1 += len1;
					resid1 -= len1;
				}
			} else {
				CTR3(KTR_NBD, "%s nc=%p cookie=%lu mapped read",
				    __func__, nc, ni->ni_cookie);
				m_copydata(m, 0, len, bp->bio_data + offset);
			}
			m_freem(m);
			offset += len;
			resid -= len;
		}
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

	CTR2(KTR_NBD, "%s sc=%p", __func__, sc);
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

	if (atomic_load_int(&nc->nc_state) != NBD_CONN_SOFT_DISCONNECTING) {
		CTR4(KTR_NBD, "%s nc=%p nc_state=%s (%d)", __func__, nc,
		    nbd_conn_state_str(nc->nc_state), nc->nc_state);
		return (false);
	}
	if (so->so_error != 0) {
		G_NBD_LOG(G_NBD_WARN, "socket error %d", so->so_error);
		CTR3(KTR_NBD, "%s nc=%p so_error=%d", __func__, nc,
		    so->so_error);
		return (false);
	}
	if (__predict_false((so->so_state & SS_ISCONNECTED) == 0)) {
		CTR2(KTR_NBD, "%s nc=%p socket not connected", __func__, nc);
		return (false);
	}
	if ((so->so_snd.sb_state & SBS_CANTSENDMORE) != 0) {
		CTR2(KTR_NBD, "%s nc=%p socket cannot send more", __func__, nc);
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
	long needed; /* must be signed */
	int error;

	CTR2(KTR_NBD, "%s nc=%p", __func__, nc);
	m = nbd_request_mbuf(nc->nc_softc->sc_tls, &req);
	if (m == NULL)
		goto error;
	memset(req, 0, sizeof(*req));
	req->magic = htobe32(NBD_REQUEST_MAGIC);
	req->command = htobe16(NBD_CMD_DISCONNECT);
	needed = sizeof(*req);
	SOCK_SENDBUF_LOCK(so);
	for (;;) {
		if (!nbd_conn_soft_disconnect_ok(nc)) {
			SOCK_SENDBUF_UNLOCK(so);
			G_NBD_LOG(G_NBD_INFO, "%s disconnecting", __func__);
			m_free(m);
			goto error;
		}
		if (sbspace(&so->so_snd) >= needed)
			break;
		MPASS(needed <= so->so_snd.sb_hiwat);
		so->so_snd.sb_lowat = needed;
		cv_wait(&nc->nc_send_cv, SOCK_SENDBUF_MTX(so));
		so->so_snd.sb_lowat = so->so_snd.sb_hiwat + 1;
	}
	SOCK_SENDBUF_UNLOCK(so);
	error = sosend(so, NULL, NULL, m, NULL, MSG_DONTWAIT, NULL);
	if (error != 0) {
		G_NBD_LOG(G_NBD_ERROR, "%s sosend failed (%d)", __func__,
		    error);
		goto error;
	}
	soshutdown(so, SHUT_WR);
	return;
error:
	atomic_store_int(&nc->nc_state, NBD_CONN_HARD_DISCONNECTING);
}

static inline void
nbd_conn_close(struct nbd_conn *nc)
{
	struct socket *so = nc->nc_socket;

	CTR2(KTR_NBD, "%s nc=%p", __func__, nc);
	atomic_store_int(&nc->nc_state, NBD_CONN_CLOSED);
	SOCK_SENDBUF_LOCK(so);
	soupcall_clear(so, SO_SND);
	SOCK_SENDBUF_UNLOCK(so);
	SOCK_RECVBUF_LOCK(so);
	soupcall_clear(so, SO_RCV);
	SOCK_RECVBUF_UNLOCK(so);
	soclose(so);
}

static inline void
nbd_conn_drain_inflight(struct nbd_conn *nc)
{
	struct nbd_inflight *ni;

	CTR2(KTR_NBD, "%s nc=%p", __func__, nc);
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

	CTR2(KTR_NBD, "%s sc=%p", __func__, sc);
	mtx_lock(&sc->sc_queue_mtx);
	while ((bp = bio_queue_takefirst(&sc->sc_queue)) != NULL)
		g_io_deliver(bp, ENXIO);
	mtx_unlock(&sc->sc_queue_mtx);
}

static inline bool
g_nbd_remove_conn(struct g_nbd_softc *sc, struct nbd_conn *nc)
{
	bool last;

	KASSERT(nc->nc_state == NBD_CONN_CLOSED,
	    ("tried to remove open connection"));

	CTR3(KTR_NBD, "%s sc=%p nc=%p", __func__, sc, nc);

	mtx_lock(&sc->sc_conns_mtx);
	SLIST_REMOVE(&sc->sc_connections, nc, nbd_conn, nc_connections);
	last = --sc->sc_nconns == 0;
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
	cv_destroy(&nc->nc_receive_cv);
	cv_destroy(&nc->nc_send_cv);
	mtx_destroy(&nc->nc_inflight_mtx);
	g_free(nc);
	return (last);
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

	CTR2(KTR_NBD, "%s sc=%p", __func__, sc);
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
	CTR2(KTR_NBD, "%s sc=%p completed", __func__, sc);
}

static void
nbd_conn_sender(void *arg)
{
	struct nbd_conn *nc = arg;
	struct g_nbd_softc *sc = nc->nc_softc;
	struct socket *so = nc->nc_socket;
	struct nbd_inflight *ni;
	struct bio *bp;

	CTR3(KTR_NBD, "%s sc=%p nc=%p", __func__, sc, nc);

	thread_lock(curthread);
	sched_prio(curthread, PRIBIO);
	thread_unlock(curthread);

	while (__predict_true(atomic_load_int(&nc->nc_state)
	    == NBD_CONN_CONNECTED)) {
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
			if (__predict_false(ni == NULL)) {
				sx_xunlock(&sc->sc_flush_lock);
				counter_u64_add(g_nbd_enomems, 1);
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
			if (__predict_false(ni == NULL)) {
				counter_u64_add(g_nbd_enomems, 1);
				g_io_deliver(bp, ENOMEM);
				continue;
			}
			nbd_conn_send(nc, ni);
		}
	}
	if (atomic_load_int(&nc->nc_state) == NBD_CONN_SOFT_DISCONNECTING)
		nbd_conn_soft_disconnect(nc);
	else
		socantrcvmore(so);
	cv_signal(&nc->nc_receive_cv);
	sema_wait(&nc->nc_receiver_done);
	nbd_conn_drain_inflight(nc);
	nbd_conn_close(nc);
	if (g_nbd_remove_conn(sc, nc)) {
		G_NBD_LOG(G_NBD_INFO, "%s last connection closed", __func__);
		g_wither_provider(sc->sc_provider, ENXIO);
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

	CTR3(KTR_NBD, "%s sc=%p nc=%p", __func__, sc, nc);

	thread_lock(curthread);
	sched_prio(curthread, PSOCK); /* XXX: or PRIBIO? */
	thread_unlock(curthread);

	while (__predict_true(atomic_load_int(&nc->nc_state) ==
	    NBD_CONN_CONNECTED))
		nbd_conn_recv(nc);
	while (atomic_load_int(&nc->nc_state) == NBD_CONN_SOFT_DISCONNECTING &&
	    !TAILQ_EMPTY_ATOMIC(&nc->nc_inflight))
		nbd_conn_recv(nc);
	atomic_store_int(&nc->nc_state, NBD_CONN_HARD_DISCONNECTING);
	socantsendmore(so);
	cv_signal(&nc->nc_send_cv);
	wakeup(&sc->sc_queue);
	sema_post(&nc->nc_receiver_done);
	kthread_exit();
}

static int
nbd_conn_soupcall_snd(struct socket *so, void *arg, int waitflag __unused)
{
	struct nbd_conn *nc = arg;

	if (sowriteable(so))
		cv_signal(&nc->nc_send_cv);
	return (SU_OK);
}

static int
nbd_conn_soupcall_rcv(struct socket *so, void *arg, int waitflag __unused)
{
	struct nbd_conn *nc = arg;

	if (soreadabledata(so))
		cv_signal(&nc->nc_receive_cv);
	/*
	 * XXX: We may have to signal with sbavail() < lowat if mb efficiency is
	 * very bad.  For example, GCE images have mtu 1460 on lo0 by default,
	 * causing the loopback interface to pass traffic in JUMBOP mbufs but
	 * utilizing less than half of the space.  With large buffers, we do not
	 * get the safety net of sb_efficiency making mbmax 8x hiwat, so we can
	 * be out of buffer space and unable to receive more while being under
	 * the low water mark.
	 *
	 * Check if we are out of space here to avoid blocking the receive
	 * thread indefinitely.  It's possible all space is used by encrypted
	 * TLS records and none is available yet, so we must still check that
	 * some data is available before signaling the receive thread.
	 */
	else if (sbavail(&so->so_rcv) > 0 && sbspace(&so->so_rcv) <= 0)
		cv_signal(&nc->nc_receive_cv);
	/*
	 * XXX: We may have a complete TLS record in the receive
	 * buffer and not enough space for the next record.  Get
	 * it out of the way.
	 */
	else if (so->so_rcv.sb_mbtail != NULL &&
	    (so->so_rcv.sb_mbtail->m_flags & M_EOR) != 0)
		cv_signal(&nc->nc_receive_cv);
	return (SU_OK);
}

static int
g_nbd_add_conn(struct g_nbd_softc *sc, struct socket *so, const char *name,
    bool first)
{
	struct nbd_conn *nc;
	int error;

	/*
	 * TODO: Allow recovery when all connections have failed.  For now we
	 * must assume the device is in the process of shutting down and cannot
	 * continue.
	 */
	if (!first && sc->sc_nconns == 0)
		return (ENXIO);

	nc = g_malloc(sizeof(*nc), M_WAITOK | M_ZERO);
	nc->nc_softc = sc;
	nc->nc_socket = so;
	nc->nc_state = NBD_CONN_CONNECTED;
	TAILQ_INIT(&nc->nc_inflight);
	mtx_init(&nc->nc_inflight_mtx, "gnbd:inflight", NULL, MTX_DEF);
	cv_init(&nc->nc_send_cv, "gnbd:send");
	cv_init(&nc->nc_receive_cv, "gnbd:receive");
	sema_init(&nc->nc_receiver_done, 0, "gnbd:receiver_done");

	mtx_lock(&sc->sc_conns_mtx);
	SLIST_INSERT_HEAD(&sc->sc_connections, nc, nc_connections);
	sc->sc_nconns++;
	mtx_unlock(&sc->sc_conns_mtx);

	SOCK_SENDBUF_LOCK(so);
	so->so_snd.sb_lowat = so->so_snd.sb_hiwat + 1;
	soupcall_set(so, SO_SND, nbd_conn_soupcall_snd, nc);
	SOCK_SENDBUF_UNLOCK(so);
	SOCK_RECVBUF_LOCK(so);
	so->so_rcv.sb_lowat = so->so_rcv.sb_hiwat + 1;
	soupcall_set(so, SO_RCV, nbd_conn_soupcall_rcv, nc);
	SOCK_RECVBUF_UNLOCK(so);

	sx_xlock(&g_nbd_lock);
	g_nbd_nconns++;
	error = kproc_kthread_add(nbd_conn_sender, nc, &g_nbd_proc, NULL, 0, 0,
	    G_NBD_PROC_NAME, "gnbd %s sender", name);
	if (error != 0) {
		sx_xunlock(&g_nbd_lock);
		G_NBD_LOG(G_NBD_ERROR, "%s failed to add sender thread (%d)",
		    __func__, error);
		return (error);
	}
	error = kproc_kthread_add(nbd_conn_receiver, nc, &g_nbd_proc, NULL, 0,
	    0, G_NBD_PROC_NAME, "gnbd %s receiver", name);
	if (error != 0) {
		sx_xunlock(&g_nbd_lock);
		G_NBD_LOG(G_NBD_ERROR, "%s failed to add receiver thread (%d)",
		    __func__, error);
		return (error);
	}
	sx_xunlock(&g_nbd_lock);
	return (0);
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

	CTR1(KTR_NBD, "%s", __func__);
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
	uint64_t size;
	union {
		uint32_t flags;
		struct {
			uint16_t handshake_flags;
			uint16_t transmission_flags;
		};
	} *flagsp;
	uint32_t *minbsp, *prefbsp, *maxpayloadp;
	uint32_t minbs, prefbs, maxpl;
	bool *tlsp;
	bool tls;
	struct socket **sockets;
	struct g_geom *gp;
	struct g_provider *pp;
	intmax_t *cp;
	rlim_t sbsize;
	u_long minspace;
	int unit, nsockets, error;

	g_topology_assert();

	CTR1(KTR_NBD, "%s", __func__);
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
	size = *sizep;
	if (size == 0) {
		g_destroy_geom(gp);
		free_unr(g_nbd_unit, unit);
		gctl_error(req, "Invalid 'size' argument.");
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
	tls = *tlsp;
	if (tls && g_nbd_tlsmax == 0) {
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
	minbs = *minbsp;
	/*
	 * Servers may advertise minblocksize as small as 1 byte, but clients
	 * should make requests of at least 512 bytes.  We'll cap the blocksize
	 * at the size of the export, in case the server exports a small file.
	 */
	minbs = MAX(minbs, 512);
	minbs = MIN(minbs, size);
	prefbsp = gctl_get_paraml(req, "preferred_blocksize", sizeof(*prefbsp));
	if (prefbsp == NULL) {
		g_destroy_geom(gp);
		free_unr(g_nbd_unit, unit);
		gctl_error(req, "No 'preferred_blocksize' argument.");
		return;
	}
	prefbs = *prefbsp;
	if (prefbs == 0)
		prefbs = PAGE_SIZE; /* TODO: default could be tunable */
	prefbs = MAX(prefbs, minbs);
	prefbs = MIN(prefbs, size);
	/*
	 * Observe socket buffer size limits.
	 */
#define BUF_MAX_ADJ(_sz) (((u_quad_t)(_sz)) * MCLBYTES / (MSIZE + MCLBYTES))
	sbsize = MIN(BUF_MAX_ADJ(sb_max), lim_cur(curthread, RLIMIT_SBSIZE));
	maxpayloadp = gctl_get_paraml(req, "maximum_payload",
	    sizeof(*maxpayloadp));
	if (maxpayloadp == NULL) {
		g_destroy_geom(gp);
		free_unr(g_nbd_unit, unit);
		gctl_error(req, "No 'maximum_payload' argument.");
		return;
	}
	maxpl = *maxpayloadp;
	maxpl = MIN(maxpl, maxpayload);
	if (maxpl == 0 /* unset */)
		maxpl = maxpayload; /* tunable default */
	/*
	 * Ensure minimum default sendspace/recvspace sizes can fit the minimum
	 * block size.  Actual sizes should be much higher (up to sbsize).
	 */
	minspace = sizeof(struct nbd_request) + minbs;
	if (sendspace < minspace) {
		G_NBD_LOG(G_NBD_WARN, "kern.geom.nbd.sendspace %lu -> %lu",
		    sendspace, minspace);
		sendspace = minspace;
	}
	if (sendspace > sbsize) {
		G_NBD_LOG(G_NBD_WARN, "kern.geom.nbd.sendspace %lu -> %lu",
		    sendspace, sbsize);
		sendspace = sbsize;
	}
	/* TODO: support structured replies */
	minspace = sizeof(struct nbd_simple_reply) + minbs;
	if (recvspace < minspace) {
		G_NBD_LOG(G_NBD_WARN, "kern.geom.nbd.recvspace %lu -> %lu",
		    recvspace, minspace);
		recvspace = minspace;
	}
	if (recvspace > sbsize) {
		G_NBD_LOG(G_NBD_WARN, "kern.geom.nbd.recvspace %lu -> %lu",
		    recvspace, sbsize);
		recvspace = sbsize;
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
	sc->sc_size = size;
	sc->sc_flags = flagsp->flags;
	sc->sc_minblocksize = minbs;
	sc->sc_prefblocksize = prefbs;
	sc->sc_maxpayload = maxpl;
	sc->sc_unit = unit;
	sc->sc_tls = tls;
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
	for (int i = 0; i < nsockets; i++) {
		error = g_nbd_add_conn(sc, sockets[i], gp->name, i == 0);
		if (error != 0) {
			/* TODO: handle this rare error */
		}
	}
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
	int nconns, nsockets, error;

	g_topology_assert();

	CTR1(KTR_NBD, "%s", __func__);
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
	for (int i = 0; i < nsockets; i++) {
		error = g_nbd_add_conn(sc, sockets[i], gp->name, false);
		if (error != 0) {
			/* TODO: handle this rare error */
		}
	}
	g_free(sockets);
}

static void
g_nbd_destroy(struct g_nbd_softc *sc)
{
	struct nbd_conn *nc;

	g_topology_assert();

	CTR1(KTR_NBD, "%s", __func__);
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

	CTR1(KTR_NBD, "%s", __func__);
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

	CTR1(KTR_NBD, "%s", __func__);
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

	CTR1(KTR_NBD, "%s", __func__);
	g_nbd_destroy(sc);
	return (EBUSY);
}

static void
g_nbd_init(struct g_class *mp __unused)
{
	size_t sz;

	CTR1(KTR_NBD, "%s", __func__);
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
	CTR1(KTR_NBD, "%s", __func__);
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
	if (__predict_true(error == 0))
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

	CTR2(KTR_NBD, "%s bp=%p", __func__, bp);
	if (__predict_false(sc == NULL)) {
		G_NBD_LOGREQ(G_NBD_ERROR, bp, "%s softc NULL", __func__);
		g_io_deliver(bp, ENXIO);
		return;
	}
	/*
	 * XXX: Nothing seems to ever set this flag, and most GEOM
	 * classes never check for it.  Assume we will never see a bio
	 * with it for now.
	 */
	if (__predict_false((bp->bio_flags & BIO_VLIST) != 0)) {
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
		if (__predict_false(bp1 == NULL)) {
			counter_u64_add(g_nbd_enomems, 1);
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
				if (__predict_false(bp2 == NULL)) {
					counter_u64_add(g_nbd_enomems, 1);
					bp->bio_error = ENOMEM;
				}
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

	CTR1(KTR_NBD, "%s", __func__);
	if (pp != NULL)
		return;
	sc = gp->softc;
	if (sc == NULL)
		return;
	sbuf_printf(sb, "%s<State>%s</State>\n", indent, sc->sc_nconns > 0 ?
	    "CONNECTED" : "DISCONNECTED");
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

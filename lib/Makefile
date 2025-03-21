SRCTOP?=	/usr/src

GEOM_CLASS=	nbd
.if !defined(COMPAT_libcompat)
GEOM_CLASS_DIR?=/lib/geom
.else
GEOM_CLASS_DIR?=/usr/lib${COMPAT_libcompat}/geom
.endif

SHLIBDIR=${GEOM_CLASS_DIR}
SHLIB_NAME?=geom_${GEOM_CLASS}.so
MAN=	g${GEOM_CLASS}.8
SRCS+=	geom_${GEOM_CLASS}.c subr.c
CFLAGS+=-I${SRCTOP}/sbin/geom -I../mod
#.if ${MK_OPENSSL} != "no"
LIBEVENT_SAMPLES=${SRCTOP}/contrib/libevent/sample
.PATH: ${LIBEVENT_SAMPLES}
SRCS+=	hostcheck.c openssl_hostname_validation.c
CFLAGS+=-I${LIBEVENT_SAMPLES} -DWITH_OPENSSL
#LIBADD=	ssl crypto
LDADD+=	-lssl -lcrypto
#.endif

# Not needed when in tree
LINKS=	/sbin/geom /sbin/gnbd

.PATH: ${SRCTOP}/sbin/geom/misc

.include <bsd.lib.mk>

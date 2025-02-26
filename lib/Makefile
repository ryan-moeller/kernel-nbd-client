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

.PATH: ${SRCTOP}/sbin/geom/misc

.include <bsd.lib.mk>

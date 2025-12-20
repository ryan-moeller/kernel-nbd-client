KMOD=	geom_nbd
SRCS=	g_nbd.c

.include <bsd.kmod.mk>

.if defined(DEBUG_FLAGS) && !defined(INSTALL_NODEBUG)
.ORDER: installdirs _kmodinstall
_kmodinstall: installdirs
DIRS=	KMOD_DEBUGDIR
KMOD_DEBUGDIR=	${KERN_DEBUGDIR}${KMODDIR}
.endif

.include <bsd.dirs.mk>

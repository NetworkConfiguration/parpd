# Makefile based on BSD make.
# Our mk stubs also work with GNU make.
# Copyright (c) 2008 Roy Marples <roy@marples.name>

PROG=		parpd
SRCS=		parpd.c ${SRC_PF}

BINDIR=		${PREFIX}/sbin

MAN=		parpd.conf.5 parpd.8
CLEANFILES=	parpd.8

CPPFLAGS+=	-DSYSCONFDIR=\"${SYSCONFDIR}\"
.SUFFIXES:	.in
.in:
	${SED} -e 's:@SYSCONFDIR@:${SYSCONFDIR}:g' $< >$@

MK=		mk
include ${MK}/sys.mk
include ${MK}/os.mk
include ${MK}/prog.mk

# Makefile based on BSD make.
# Our mk stubs also work with GNU make.
# Copyright 2008 Roy Marples <roy@marples.name>

PROG=		parpd
SRCS=		common.c parpd.c
SRCS+=		${SRC_IF} ${SRC_PF}

BINDIR=		${PREFIX}/sbin

MAN=		parpd.conf.5 parpd.8

FILES=		parpd.conf
FILESDIR=	${SYSCONFDIR}

MK=		mk
include ${MK}/sys.mk
include ${MK}/os.mk
include ${MK}/prog.mk

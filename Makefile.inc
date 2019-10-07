# System definitions

PICFLAG?=	-fPIC

BINMODE?=	0555
NONBINMODE?=	0444
MANMODE?=	${NONBINMODE}
CONFMODE?=	0644

CC?=		cc
ECHO?=		echo
INSTALL?=	install
LINT?=		lint
SED?=		sed
HOST_SH?=	/bin/sh

# This isn't very portable, but I generaly make releases from NetBSD
CKSUM?=		cksum -a SHA256
PGP?=		netpgp

SED_RUNDIR=		-e 's:@RUNDIR@:${RUNDIR}:g'
SED_SYS=		-e 's:@SYSCONFDIR@:${SYSCONFDIR}:g'

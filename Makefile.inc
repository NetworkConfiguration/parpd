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

SHA256?=	sha256
PGP?=		gpg

SED_RUNDIR=		-e 's:@RUNDIR@:${RUNDIR}:g'
SED_SYS=		-e 's:@SYSCONFDIR@:${SYSCONFDIR}:g'

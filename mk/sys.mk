# Simple defaults

PREFIX?=	/usr
BINDIR?=	${PREFIX}/bin
BINMODE?=	0755
NONBINMODE?=	0644

_SYSCONFDIR!=	if test "${PREFIX}" = "/usr"; then \
		echo ""; else echo "${PREFIX}"; fi
SYSCONFDIR?=	${_SYSCONFDIR}/etc

INSTALL?=	install
SED?=		sed

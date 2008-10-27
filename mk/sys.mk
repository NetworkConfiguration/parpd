# Simple defaults

PREFIX?=	/usr
BINDIR?=	${PREFIX}/bin
BINMODE?=	0755
NONBINMODE?=	0644

_SYSCONFDIR_SH=	if test "${PREFIX}" = "/usr"; then \
		echo ""; else echo "${PREFIX}"; fi
__SYSCONFDIR!=	${_SYSCONFDIR_SH}
_SYSCONFDIR=	${__SYSCONFDIR}$(shell ${_SYSCONFDIR_SH})
SYSCONFDIR?=	${_SYSCONFDIR}/etc

INSTALL?=	install
SED?=		sed

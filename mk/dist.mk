# rules to make a distribution tarball
# Copyright 2008 Roy Marples <roy@marples.name>

_VERSION_SH=	sed -n 's/\#define VERSION[[:space:]]*"\(.*\)".*/\1/p' parpd.h
_VERSION!=	${_VERSION_SH}
VERSION=	${_VERSION}$(shell ${_VERSION_SH})

PACKAGE?=	${PROG}
PKG?=		${PACKAGE}-${VERSION}

GITREF?=	HEAD
DISTPREFIX?=	${PKG}
DISTFILE?=	${DISTPREFIX}.tar.bz2

CLEANFILES+=	*.tar.bz2

_SNAP_SH=	date -u +%Y%m%d%H%M
_SNAP!=		${_SNAP_SH}
SNAP=		${_SNAP}$(shell ${_SNAP_SH})
SNAPDIR=	${DISTPREFIX}-${SNAP}
SNAPFILE=	${SNAPDIR}.tar.bz2

_DIST_SH=	if test -d .git; then echo "dist-git"; \
		elif test -d .svn; then echo "dist-svn"; \
		else echo "dist-inst"; fi
_DIST!=		${_DIST_SH}
DIST=		${_DIST}$(shell ${_DIST_SH})

dist-git:
	git archive --prefix=${DISTPREFIX}/ ${GITREF} | bzip2 >${DISTFILE}

dist-svn:
	svn export . ${DISTPREFIX}
	tar cjpf ${DISTFILE} ${DISTPREFIX}
	rm -rf ${DISTPREFIX}

dist-inst:
	mkdir /tmp/${DISTPREFIX}
	cp -RPp * /tmp/${DISTPREFIX}
	(cd /tmp/${DISTPREFIX}; make clean)
	tar -cvjpf ${DISTFILE} -C /tmp ${DISTPREFIX}
	rm -rf /tmp/${DISTPREFIX}

dist: ${DIST}

snapshot:
	mkdir /tmp/${SNAPDIR}
	cp -RPp * /tmp/${SNAPDIR}
	(cd /tmp/${SNAPDIR}; make clean)
	tar -cvjpf ${SNAPFILE} -C /tmp ${SNAPDIR}
	rm -rf /tmp/${SNAPDIR}
	ls -l ${SNAPFILE}

snap: snapshot

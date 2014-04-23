# rules to make a distribution tarball
# Copyright 2008 Roy Marples <roy@marples.name>

VERSION!=	sed -n 's/\#define VERSION[[:space:]]*"\(.*\)".*/\1/p' parpd.h

PACKAGE?=	${PROG}
PKG?=		${PACKAGE}-${VERSION}

FOSSILID?=	current
GITREF?=	HEAD
DISTPREFIX?=	${PKG}
DISTFILEGZ?=	${DISTPREFIX}.tar.gz
DISTFILE?=	${DISTPREFIX}.tar.bz2

CLEANFILES+=	*.tar.bz2

SNAP!=		date -u +%Y%m%d%H%M
SNAPDIR=	${DISTPREFIX}-${SNAP}
SNAPFILE=	${SNAPDIR}.tar.bz2

DIST!=		if test -f .fslckout; then echo "dist-fossil"; \
		elif test -d .git; then echo "dist-git"; \
		elif test -d .svn; then echo "dist-svn"; \
		else echo "dist-inst"; fi

dist-fossil:
	fossil tarball --name ${DISTPREFIX} ${FOSSILID} ${DISTFILEGZ}
	gunzip -c ${DISTFILEGZ} |  bzip2 >${DISTFILE}
	rm ${DISTFILEGZ}

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

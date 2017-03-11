# rules to make a distribution tarball
# Copyright 2008 Roy Marples <roy@marples.name>

VERSION!=	sed -n 's/\#define VERSION[[:space:]]*"\(.*\)".*/\1/p' parpd.h

PACKAGE?=	${PROG}
PKG?=		${PACKAGE}-${VERSION}

FOSSILID?=	current
GITREF?=	HEAD
DISTPREFIX?=	${PKG}
DISTFILEGZ?=	${DISTPREFIX}.tar.gz
DISTFILE?=	${DISTPREFIX}.tar.xz
DISTINFO=	${DISTFILE}.distinfo
DISTINFOSIGN=	${DISTINFO}.asc
CKSUM?=		cksum -a SHA256
PGP?=		netpgp

CLEANFILES+=	*.tar.bz2

SNAP!=		date -u +%Y%m%d%H%M
SNAPDIR=	${DISTPREFIX}-${SNAP}
SNAPFILE=	${SNAPDIR}.tar.xz

DIST!=		if test -f .fslckout; then echo "dist-fossil"; \
		elif test -d .git; then echo "dist-git"; \
		else echo "dist-inst"; fi

dist-fossil:
	fossil tarball --name ${DISTPREFIX} ${FOSSILID} ${DISTFILEGZ}
	gunzip -c ${DISTFILEGZ} | xz >${DISTFILE}
	rm ${DISTFILEGZ}

dist-git:
	git archive --prefix=${DISTPREFIX}/ ${GITREF} | xz >${DISTFILE}

dist-inst:
	mkdir /tmp/${DISTPREFIX}
	cp -RPp * /tmp/${DISTPREFIX}
	(cd /tmp/${DISTPREFIX}; make clean)
	tar -cvjpf ${DISTFILE} -C /tmp ${DISTPREFIX}
	rm -rf /tmp/${DISTPREFIX}

dist: ${DIST}

distinfo: dist
	rm -f ${DISTINFO} ${DISTINFOSIGN}
	${CKSUM} ${DISTFILE} >${DISTINFO}
	#printf "SIZE (${DISTFILE}) = %s\n" $$(wc -c <${DISTFILE}) >>${DISTINFO}
	${PGP} --clearsign --output=${DISTINFOSIGN} ${DISTINFO}
	chmod 644 ${DISTINFOSIGN}
	ls -l ${DISTFILE} ${DISTINFO} ${DISTINFOSIGN}

distclean: clean
	rm -f *.bz2 *.xz *.distinfo *.asc

snapshot: distclean
	mkdir /tmp/${SNAPDIR}
	cp -RPp * /tmp/${SNAPDIR}
	(cd /tmp/${SNAPDIR}; make clean)
	tar -cvjpf ${SNAPFILE} -C /tmp ${SNAPDIR}
	rm -rf /tmp/${SNAPDIR}
	ls -l ${SNAPFILE}

snap: snapshot

PROG=		parpd
SRCS=		parpd.c eloop.c ${SRC_PF}

BINDIR=		${PREFIX}/sbin

MAN5=		parpd.conf.5
MAN8=		parpd.8
MAN=		${MAN5} ${MAN8}
CLEANFILES=	parpd.8

TOP?=		..
include ${TOP}/iconfig.mk
CPPFLAGS+=	-I${TOP} -I${TOP}/src -I ${TOP}/compat

PCOMPAT_SRCS=	${COMPAT_SRCS:compat/%=${TOP}/compat/%}
OBJS=		${SRCS:.c=.o} ${PCOMPAT_SRCS:.c=.o}

.SUFFIXES:	.in
.in:
	${SED} -e 's:@SYSCONFDIR@:${SYSCONFDIR}:g' $< >$@

.c.o:
	${CC} ${CFLAGS} ${CPPFLAGS} -c $< -o $@

all: ${TOP}/config.h ${PROG} ${MAN}

${PROG}: ${DEPEND} ${OBJS}
	${CC} ${LDFLAGS} -o $@ ${OBJS} ${LDADD}

clean:
	rm -f ${OBJS} ${PROG} ${PROG}.core ${CLEANFILES}

distclean: clean

proginstall:
	${INSTALL} -d ${DESTDIR}${SBINDIR}
	${INSTALL} -m ${BINMODE} ${PROG} ${DESTDIR}${SBINDIR}

_maninstall: ${MAN}
	${INSTALL} -d ${DESTDIR}${MANDIR}/man5
	${INSTALL} -m ${MANMODE} ${MAN5} ${DESTDIR}${MANDIR}/man5
	${INSTALL} -d ${DESTDIR}${MANDIR}/man8
	${INSTALL} -m ${MANMODE} ${MAN8} ${DESTDIR}${MANDIR}/man8

install: proginstall _maninstall

_import-src: ${SRCS}
	${INSTALL} -d ${DESTDIR}/src
	cp parpd.h ${SRCS} ${SRC_PF} parpd.conf.5 parpd.8.in ${DESTDIR}/src
	if [ -n "${COMPAT_SRCS}" ]; then \
		${INSTALL} -d ${DESTDIR}/compat; \
		cd ..; \
		touch compat/rb.h; \
		cp ${COMPAT_SRCS} ${COMPAT_SRCS:.c=.h} ${DESTDIR}/compat; \
		rm compat/rb.h; \
		rm -f ${DESTDIR}/compat/rb.h; \
	fi
	if [ -e ${DESTDIR}/compat/rb.c ]; then \
		cp ../compat/rbtree.h ${DESTDIR}/compat; \
	fi

include ${TOP}/Makefile.inc

PROG=		parpd
SRCS=		parpd.c eloop.c ${SRC_PF}

BINDIR=		${PREFIX}/sbin

MAN=		parpd.conf.5 parpd.8
CLEANFILES=	parpd.8

TOP?=		..
include ${TOP}/iconfig.mk
CPPFLAGS+=	-I${TOP} -I${TOP}/src

OBJS=		${SRCS:.c=.o}

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

_import-src: ${SRCS}
	${INSTALL} -d ${DESTDIR}/src
	cp parpd.h ${SRCS} ${SRC_PF} parpd.conf.5 parpd.8.in ${DESTDIR}/src

include ${TOP}/Makefile.inc

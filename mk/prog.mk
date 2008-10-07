# rules to build a program 
# based on FreeBSD's bsd.prog.mk

# Copyright 2008 Roy Marples <roy@marples.name>

include ${MK}/cc.mk

OBJS+=		${SRCS:.c=.o}

all: ${PROG} ${SCRIPTS} _man

.c.o:
	${CC} ${CFLAGS} ${CPPFLAGS} -c $< -o $@

${PROG}: ${OBJS}
	${CC} ${LDFLAGS} -o $@ ${OBJS} ${LDADD}

_proginstall: ${PROG}
	${INSTALL} -d ${DESTDIR}${BINDIR}
	${INSTALL} -m ${BINMODE} ${PROG} ${DESTDIR}${BINDIR}
	${INSTALL} -d ${DESTDIR}${DBDIR}

include ${MK}/depend.mk
include ${MK}/files.mk
include ${MK}/man.mk
include ${MK}/dist.mk

install: _proginstall _maninstall
	for x in ${SUBDIRS}; do cd $$x; ${MAKE} $@; cd ..; done

clean:
	rm -f ${OBJS} ${PROG} ${PROG}.core ${CLEANFILES}

LINTFLAGS?=	-hx
LINTFLAGS+=	-X 159,247,352

lint: ${SRCS:.c=.c}
	${LINT} ${LINTFLAGS} ${CFLAGS:M-[DIU]*} $^ ${.ALLSRC}

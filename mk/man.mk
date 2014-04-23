# rules to install manpages
# Copyright 2008 Roy Marples <roy@marples.name>

_MANPREFIX!=	if test "${PREFIX}" = "/usr"; then echo "/usr/share"; else echo "${PREFIX}"; fi
MANPREFIX?=	${_MANPREFIX}

MANDIR?=	${MANPREFIX}/man/man
MANMODE?=	0444

MAN5!=	for man in ${MAN}; do case $$man in *.5) echo $$man;; esac; done
MAN8!=	for man in ${MAN}; do case $$man in *.8) echo $$man;; esac; done

_man: ${MAN}

_maninstall: _man
	${INSTALL} -d ${DESTDIR}${MANDIR}5
	${INSTALL} -m ${MANMODE} ${MAN5} ${DESTDIR}${MANDIR}5
	${INSTALL} -d ${DESTDIR}${MANDIR}8
	${INSTALL} -m ${MANMODE} ${MAN8} ${DESTDIR}${MANDIR}8

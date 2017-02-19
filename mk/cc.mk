# Copyright 2008 Roy Marples <roy@marples.name>

# Setup some good default CFLAGS
CFLAGS?=	-O2

# Try and use some good cc flags if we're building from git
# We don't use -pedantic as it will warn about our perfectly valid
# use of %m in our logger.
_CCFLAGS=	-g -Wall -Wextra
_CCFLAGS+=	-Wmissing-prototypes -Wmissing-declarations
_CCFLAGS+=	-Wmissing-format-attribute -Wnested-externs
_CCFLAGS+=	-Winline -Wcast-align -Wcast-qual -Wpointer-arith
_CCFLAGS+=	-Wreturn-type -Wswitch -Wshadow
_CCCFLAGS+=	-Wcast-qual -Wwrite-strings
_CCFLAGS+=	-Wformat=2
_CCFLAGS+=	-Wpointer-sign -Wmissing-noreturn

_CC_FLAGS!=	if ! test -f .fslckout && ! test -d .git && ! test -d .svn; \
		then echo ""; else for f in ${_CCFLAGS}; do \
		if echo "int main(void) { return 0;} " | \
		${CC} $$f -S -xc -o /dev/null - ; \
		then printf "%s" "$$f "; fi \
		done; fi
CFLAGS+=	${_CC_FLAGS}

# Copyright 2008 Roy Marples <roy@marples.name>

# Setup some good default CFLAGS
CFLAGS?=	-Os

# Try and use some good cc flags if we're building from git
# We don't use -pedantic as it will warn about our perfectly valid
# use of %m in our logger.
_CCFLAGS=	-Wall -Wextra -Wimplicit -Wshadow -Wformat=2 \
		-Wmissing-prototypes -Wmissing-declarations \
		-Wmissing-noreturn -Wmissing-format-attribute \
		-Wredundant-decls  -Wnested-externs \
		-Winline -Wwrite-strings -Wcast-align -Wcast-qual \
		-Wpointer-arith \
		-Wdeclaration-after-statement -Wsequence-point -Wconversion
_CC_FLAGS!=	if ! test -f .fslckout && ! test -d .git && ! test -d .svn; \
		then echo ""; else for f in ${_CCFLAGS}; do \
		if echo "int main(void) { return 0;} " | \
		${CC} $$f -S -xc -o /dev/null - ; \
		then printf "%s" "$$f "; fi \
		done; fi
CFLAGS+=	${_CC_FLAGS}

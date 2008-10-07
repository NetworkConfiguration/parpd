/* 
 * parpd - Proxy ARP Daemon
 * Copyright 2008 Roy Marples <roy@marples.name>
 * All rights reserved

 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>

#include <fcntl.h>
#ifdef BSD
#  include <paths.h>
#endif
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#include "common.h"

#ifndef _PATH_DEVNULL
#  define _PATH_DEVNULL "/dev/null"
#endif

/* Handy routine to read very long lines in text files.
 * This means we read the whole line and avoid any nasty buffer overflows. */
ssize_t
get_line(char **line, size_t *len, FILE *fp)
{
	char *p;
	size_t last = 0;

	while(!feof(fp)) {
		if (*line == NULL || last != 0) {
			*len += BUFSIZ;
			*line = xrealloc(*line, *len);
		}
		p = *line + last;
		memset(p, 0, BUFSIZ);
		fgets(p, BUFSIZ, fp);
		last += strlen(p);
		if (last && (*line)[last - 1] == '\n') {
			(*line)[last - 1] = '\0';
			break;
		}
	}
	return last;
}

/* strlcpy is nice, shame glibc does not define it */
#if HAVE_STRLCPY
#else
size_t
strlcpy(char *dst, const char *src, size_t size)
{
	const char *s = src;
	size_t n = size;

	if (n && --n)
		do {
			if (!(*dst++ = *src++))
				break;
		} while (--n);

	if (!n) {
		if (size)
			*dst = '\0';
		while (*src++);
	}

	return src - s - 1;
}
#endif

#if HAVE_CLOSEFROM
#else
int
closefrom(int fd)
{
	int max = getdtablesize();
	int i;
	int r = 0;

	for (i = fd; i < max; i++)
		r += close(i);
	return r;
}
#endif

void *
xmalloc(size_t s)
{
	void *value = malloc(s);

	if (value)
		return value;
	syslog(LOG_ERR, "memory exhausted (xalloc %zu bytes)", s);
	exit (EXIT_FAILURE);
	/* NOTREACHED */
}

void *
xrealloc(void *ptr, size_t s)
{
	void *value = realloc(ptr, s);

	if (value)
		return (value);
	syslog(LOG_ERR, "memory exhausted (xrealloc %zu bytes)", s);
	exit(EXIT_FAILURE);
	/* NOTREACHED */
}

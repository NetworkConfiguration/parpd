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

const char copyright[] = "Copyright (c) 2008 Roy Marples";

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "parpd.h"

static struct interface *ifaces;
static const char *cffile = PARPD_CONF;
static time_t config_mtime;
static struct pent *pents;

static char hwaddr_buffer[(HWADDR_LEN * 3) + 1];

static void
usage(void)
{
	printf("usage: parpd [-dfl] [-c file] [interface [...]]\n");
}

#ifndef BSD
/* fgetln is a BSD specific function.
 * This implementation only supports one buffer instead of one per stream. */
static char *
fgetln(FILE *stream, size_t *len)
{
	static char *fbuf;
	static size_t fbuf_len;

#if defined(__GLIBC__) && defined(_GNU_SOURCE)
	/* glibc has the getline function which is almost equivalent.
	 * Some libc's claim to emulate glibc, but lack glibc extensions
	 * like getline, so to get this you'll have to add _GNU_SOURCE to
	 * your CPPFLAGS. */
	if (getline(&fbuf, &fbuf_len, stream) == -1) {
		*len = 0;
		return NULL;
	}
	*len = strlen(fbuf);
	return fbuf;
#else
	size_t pos, nlen;
	int c;
	char *nbuf;

	if (!fbuf) {
		fbuf_len = BUFSIZ;
		fbuf = malloc(fbuf_len);
		if (!fbuf) {
			*len = 0;
			return NULL;
		}
	}

	pos = 0;
	while ((c = fgetc(stream)) != EOF) {
		if (pos > fbuf_len) {
			nlen = fbuf_len + BUFSIZ;
			nbuf = realloc(fbuf, nlen);
			if (!nbuf) {
				free(fbuf);
				fbuf = NULL;
				*len = 0;
				return NULL;
			}
			fbuf = nbuf;
			fbuf_len = nlen;
		}
		fbuf[pos++] = c;
		if (c == '\n')
			break;
	}
	*len = pos;
	return pos == 0 ? NULL : fbuf;
#endif
}
#endif

/* Like ether_aton, but works with longer addresses */
static size_t
hwaddr_aton(unsigned char *buffer, const char *addr)
{
	char c[3];
	const char *p = addr;
	unsigned char *bp = buffer;
	size_t len = 0;

	c[2] = '\0';
	while (*p) {
		c[0] = *p++;
		c[1] = *p++;
		/* Ensure that digits are hex */
		if (isxdigit((unsigned char)c[0]) == 0 ||
		    isxdigit((unsigned char)c[1]) == 0)
		{
			errno = EINVAL;
			return 0;
		}
		/* We should have at least two entries 00:01 */
		if (len == 0 && *p == '\0') {
			errno = EINVAL;
			return 0;
		}
		/* Ensure that next data is EOL or a seperator with data */
		if (!(*p == '\0' || (*p == ':' && *(p + 1) != '\0'))) {
			errno = EINVAL;
			return 0;
		}
		if (*p)
			p++;
		if (bp)
			*bp++ = (unsigned char)strtol(c, NULL, 16);
		len++;
	}
	return len;
}

/* Like ether_aton, but works with longer addresses */
static char *
hwaddr_ntoa(const unsigned char *hwaddr, size_t hwlen)
{
	char *p = hwaddr_buffer;
	size_t i;

	for (i = 0; i < hwlen && i < HWADDR_LEN; i++) {
		if (i > 0)
			*p ++= ':';
		p += snprintf(p, 3, "%.2x", hwaddr[i]);
	}

	*p ++= '\0';

	return hwaddr_buffer;
}

static void
free_pents(struct pent *pp)
{
	struct pent *pn;

	while (pp) {
		pn = pp->next;
		free(pp);
		pp = pn;
	}
	pents = NULL;
}

/* Because fgetln does not return C strings, we cannot use
 * functions such as strsep and friends to extract words.
 * This is no bad thing this below code handles extracting words
 * from a string boundary and should result in smaller code
 * compared to using true C strings and strsep style functions. */
static char *
get_word(char **s, const char *e)
{
	char *p, *w = NULL;

	if (!s)
		return NULL;
	p = *s;
	while (p < e && (*p == ' ' || *p == '\t' || *p == '\n'))
		p++;
	if (p < e) {
		w = p++;
		for (; p < e; p++) {
			if (*p == ' ' || *p == '\t' || *p == '\n') {
				*p++ = '\0';
				break;
			}
		}
	}
	*s = p;
	return w;
}

static int
load_config(void)
{
	struct stat st;
	FILE *f;
	char *buf, *cmd, *match, *hwaddr, *p, *e, *r;
	size_t buf_len, len;
	struct pent *pp;
	int act, cidr, in_interface;
	struct in_addr ina;
	in_addr_t net;
	struct interface *iface;

	if (stat(cffile, &st) == -1) {
		free_pents(pents);
		for (iface = ifaces; iface; iface = iface->next)
			free_pents(iface->pents);
		return -1;
	}
	if (config_mtime == st.st_mtime)
		return 0;

	free_pents(pents);
	for (iface = ifaces; iface; iface = iface->next)
		free_pents(iface->pents);
	f = fopen(cffile, "r");
	if (f == NULL)
		return -1;
	config_mtime = st.st_mtime;
	iface = NULL;
	in_interface = 0;
	while ((buf = fgetln(f, &buf_len))) {
		e = buf + buf_len;
		cmd = get_word(&buf, e);
		if (!cmd || *cmd == '\n' || *cmd == '#' || *cmd == ';')
			continue;
		match = get_word(&buf, e);
		if (strcmp(cmd, "proxy") == 0)
			act = 1;
		else if (strcmp(cmd, "ignore") == 0)
			act = 0;
		else if (strcmp(cmd, "interface") == 0) {
			in_interface = 1;
			for (iface = ifaces; iface; iface = iface->next)
				if (strcmp(iface->name, match) == 0)
					break;
			if (!iface)
				syslog(LOG_ERR,
				       "%s: unknown interface", match);
			continue;
		} else {
			syslog(LOG_ERR, "%s: unknown command", cmd);
			continue;
		}
		if (in_interface && !iface)
			continue;
		hwaddr = get_word(&buf, e);
		if (!match) {
			syslog(LOG_DEBUG, "no ip/cidr given");
			continue;
		}
		net = ~0U;
		p = strchr(match, '/');
		if (p) {
			*p++ = '\0';
			if (*p) {
				errno = 0;
				cidr = strtol(p, &r, 10);
				if (errno == 0 && !*r) {
					if (cidr < 0 || cidr > 32) {
						syslog(LOG_DEBUG,
						       "%s: invalid cidr", p);
						continue;
					}
					net <<= (32 - cidr);
					net = htonl(net);
				} else {
					if (inet_aton(p, &ina) == 0) {
						syslog(LOG_DEBUG,
						       "%s: invalid mask", p);
						continue;
					}
					net = ina.s_addr;
				}
			}
		}
		if (inet_aton(match, &ina) == 0) {
			syslog(LOG_DEBUG, "%s: invalid inet addr", match);
			continue;
		}
		if (hwaddr) {
			if (*hwaddr == '#' || *hwaddr == ';') {
				hwaddr = NULL;
			} else {
				len = hwaddr_aton(NULL, hwaddr);
				if (len == 0) {
					syslog(LOG_DEBUG,
					       "%s: invalid hw addr", hwaddr);
					continue;
				}
				if (len > HWADDR_LEN) {
					syslog(LOG_DEBUG,
					       "%s: hw addr too long", hwaddr);
					continue;
				}
			}
		}
		/* OK, good to add now. */
		pp = malloc(sizeof(*pp));
		if (!pp) {
			syslog(LOG_ERR, "memory exhausted");
			exit(EXIT_FAILURE);
		}
		pp->action = act;
		pp->ip = ina.s_addr & net;
		pp->net = net;
		if (hwaddr)
			pp->hwlen = hwaddr_aton(pp->hwaddr, hwaddr);
		else
			pp->hwlen = 0;
		if (iface) {
			pp->next = iface->pents;
			iface->pents = pp;
		} else {
			pp->next = pents;
			pents = pp;
		}
	}
	fclose(f);
	return 0;
}

static int
proxy(const struct pent *ps, in_addr_t ip, const uint8_t **hw, size_t *hwlen)
{
	const struct pent *pp;

	if (load_config() == -1)
		return -1;

	for (pp = ps; pp; pp = pp->next) {
		if (pp->ip == (ip & pp->net) ||
		    pp->ip == INADDR_ANY) {
			if (pp->action == 1) {
				if (hw)
					*hw = pp->hwaddr;
				if (hwlen)
					*hwlen = pp->hwlen;
			}
			return pp->action;
		}
	}
	return 0;
}

#define ARP_LEN \
	(sizeof(struct arphdr) + (2 * sizeof(uint32_t)) + (2 * HWADDR_LEN))
/* Does what is says on the tin - sends an ARP message */
static int
send_arp(const struct interface *iface, int op, size_t hlen,
	 const uint8_t *sha, in_addr_t sip, const uint8_t *tha, in_addr_t tip)
{
	uint8_t arp_buffer[ARP_LEN];
	struct arphdr ar;
	size_t len;
	uint8_t *p;
	int retval;

	ar.ar_hrd = htons(iface->family);
	ar.ar_pro = htons(ETHERTYPE_IP);
	ar.ar_hln = hlen;
	ar.ar_pln = sizeof(sip);
	ar.ar_op = htons(op);
	memcpy(arp_buffer, &ar, sizeof(ar));
	p = arp_buffer + sizeof(ar);
	memcpy(p, sha, hlen);
	p += hlen;
	memcpy(p, &sip, sizeof(sip));
	p += sizeof(sip);
	memcpy(p, tha, hlen);
	p += hlen;
	memcpy(p, &tip, sizeof(tip));
	p += sizeof(tip);
	len = p - arp_buffer;
	retval = send_raw_packet(iface, tha, hlen, arp_buffer, len);
	return retval;
}

/* Checks an incoming ARP message to see if we should proxy for it. */
static void
handle_arp(struct interface *iface)
{
	uint8_t arp_buffer[ARP_LEN], *shw, *thw;
	const uint8_t *phw;
	struct arphdr ar;
	in_addr_t sip, tip;
	size_t hwlen;
	ssize_t bytes;
	struct in_addr ina;

	for(;;) {
		bytes = get_raw_packet(iface, arp_buffer, sizeof(arp_buffer));
		if (bytes == 0 || bytes == -1)
			return;
		/* We must have a full ARP header */
		if ((size_t)bytes < sizeof(ar))
			continue;
		memcpy(&ar, arp_buffer, sizeof(ar));
		/* Protocol must be IP. */
		if (ar.ar_pro != htons(ETHERTYPE_IP))
			continue;
		if (ar.ar_pln != sizeof(sip))
			continue;
		/* We presently only work with REQUEST.
		 * Should we make REPLY knock out our config entries? */
		if (ar.ar_op != htons(ARPOP_REQUEST))
			continue;

		/* Get pointers to the hardware addreses */
		shw = arp_buffer + sizeof(ar);
		thw = shw + ar.ar_hln + ar.ar_pln;
		/* Ensure we got all the data */
		if ((thw + ar.ar_hln + ar.ar_pln) - arp_buffer > bytes)
			continue;
		/* Ignore messages from ourself */
		if (ar.ar_hln == iface->hwlen &&
		    memcmp(shw, iface->hwaddr, iface->hwlen) == 0)
			continue;
		/* Copy out the IP addresses */
		memcpy(&tip, thw + ar.ar_hln, ar.ar_pln);
		memcpy(&sip, shw + ar.ar_hln, ar.ar_pln);
		ina.s_addr = tip;
		syslog(LOG_DEBUG, "%s: received ARPOP_REQUEST for %s",
		       iface->name, inet_ntoa(ina));
		if (proxy(iface->pents, tip, &phw, &hwlen) != 1 &&
		    proxy(pents, tip, &phw, &hwlen) != 1)
			continue;
		if (!hwlen) {
			phw = iface->hwaddr;
			hwlen = iface->hwlen;
		}
		/* Our address lengths need to be the same */
		if (hwlen != iface->hwlen) {
			syslog(LOG_DEBUG, "%s: hwlen different, not replying",
			       iface->name);
			continue;
		}
		ina.s_addr = tip;
		syslog(LOG_INFO, "%s: sending ARPOP_REPLY %s (%s)",
		       iface->name, inet_ntoa(ina), hwaddr_ntoa(phw, hwlen));
		send_arp(iface, ARPOP_REPLY, hwlen, phw, tip, shw, sip);
	}
}

int
main(int argc, char **argv)
{
	struct interface *iface, *ifl, *ifn;
	int opt, fflag = 0;
	int nfds = 0, i;
	struct pollfd *fds;

	openlog("parpd", LOG_PERROR, LOG_DAEMON);
	setlogmask(LOG_UPTO(LOG_NOTICE));

	while ((opt = getopt(argc, argv, "c:dfl")) != -1)
	{
		switch (opt) {
		case 'c':
			cffile = optarg;
			break;
		case 'd':
			setlogmask(LOG_UPTO(LOG_DEBUG));
			/* FALLTHROUGH */
		case 'f':
			fflag++;
			break;
		case 'l':
			setlogmask(LOG_UPTO(LOG_INFO));
			break;
		case '?':
			usage();
			exit(EXIT_FAILURE);
		}
	}
	argc -= optind;
	argv += optind;

	ifaces = discover_interfaces(argc, argv);
	for (i = 0; i < argc; i++) {
		for (iface = ifaces; iface; iface = iface->next)
			if (strcmp(iface->name, argv[i]) == 0)
				break;
		if (!iface) {
			syslog(LOG_ERR, "%s: no such interface",
			       argv[i]);
			exit(EXIT_FAILURE);
		}
	}
	if (!ifaces) {
		syslog(LOG_ERR, "no suitable interfaces found");
		exit(EXIT_FAILURE);
	}

	if (load_config() == -1) {
		syslog(LOG_ERR, "%s: %m", cffile);
		exit(EXIT_FAILURE);
	}
	if (!pents) {
		/* No global entries, so remove interfaces without any
		 * either as they'll do nothing. */
		ifl = NULL;
		for (iface = ifaces;
		     iface && (ifn = iface->next, 1);
		     iface = ifn)
		{
			if (iface->pents) {
				ifl = iface;
				continue;
			}
			if (ifl)
				ifl->next = iface->next;
			else
				ifaces = iface->next;
			free(iface);
		}
		if (!ifaces) {
			syslog(LOG_ERR, "%s: no valid entries", cffile);
			exit(EXIT_FAILURE);
		}
	}

	if (!fflag)
		daemon(0, 0);

	nfds = 0;
	for (iface = ifaces; iface; iface = iface->next)
		nfds++;
	fds = malloc(sizeof(*fds) * nfds);
	if (!fds) {
		syslog(LOG_ERR, "memory exhausted");
		exit(EXIT_FAILURE);
	}
	i = 0;
	for (iface = ifaces; iface; iface = iface->next) {
		syslog(LOG_DEBUG, "proxying on %s", iface->name);
		fds[i].fd = iface->fd;
		fds[i].events = POLLIN;
		fds[i].revents = 0;
		i++;
	}

	for (;;) {
		i = poll(fds, nfds, -1);
		if (i == -1) {
			if (errno == EAGAIN || errno == EINTR)
				continue;
			syslog(LOG_ERR, "poll: %m");
			exit(EXIT_FAILURE);
		}
		if (i == 0)
			continue; /* should never happen */
		for (i = 0; i < nfds; i++) {
			if (!(fds[i].revents & (POLLIN | POLLHUP)))
				continue;
			for (iface = ifaces; iface; iface = iface->next)
				handle_arp(iface);
		}
	}
	/* NOTREACHED */
	return 0;
}

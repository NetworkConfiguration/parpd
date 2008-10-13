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

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>

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
static const char *cffile = "/etc/parpd.conf";
static time_t config_mtime;

static struct pent {
	char action;
	in_addr_t ip;
	in_addr_t net;
	uint8_t hwaddr[HWADDR_LEN];
	size_t hwlen;
	struct pent *next;
} *pents;

static char *buf;
static size_t buflen;
static char hwaddr_buffer[(HWADDR_LEN * 3) + 1];

static void
usage(void)
{
	printf("usage: parpd [-dfl] [-c file] [interface [...]]\n");
}

/* Handy routine to read very long lines in text files.
 * This means we read the whole line and avoid any nasty buffer overflows. */
static ssize_t
get_line(char **line, size_t *len, FILE *fp)
{
	char *p;
	size_t last = 0;

	while(!feof(fp)) {
		if (*line == NULL || last != 0) {
			*len += BUFSIZ;
			*line = realloc(*line, *len);
			if (!*line) {
				syslog(LOG_ERR, "memory exhausted");
				exit(EXIT_FAILURE);
			}
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
free_pents(void)
{
	struct pent *pp, *pn;

	pp = pents;
	while (pp) {
		pn = pp->next;
		free(pp);
		pp = pn;
	}
	pents = NULL;
}

static int
proxy(in_addr_t ip, uint8_t **hw, size_t *hwlen)
{
	struct stat st;
	FILE *f;
	char *cmd, *match, *hwaddr, *p, *r;
	size_t len;
	struct pent *pp;
	int act, cidr;
	struct in_addr ina;
	in_addr_t net;

	if (stat(cffile, &st) == -1) {
		free_pents();
		return -1;
	}
	if (config_mtime != st.st_mtime) {
		free_pents();
		f = fopen(cffile, "r");
		if (f == NULL)
			return -1;
		config_mtime = st.st_mtime;
		while ((get_line(&buf, &buflen, f))) {
			if (*buf == '\0' || *buf == ';' || *buf == '#')
				continue;
			p = buf;
			cmd = match = hwaddr = NULL;
			act = -1;
			net = ~0;
			while ((cmd = strsep(&p, " \t")))
				if (*cmd)
					break;
			if (strcmp(cmd, "proxy") == 0)
				act = 1;
			else if (strcmp(cmd, "ignore") == 0)
				act = 0;
			else {
				syslog(LOG_DEBUG, "%s: invalid command", cmd);
				continue;
			}
			while ((match = strsep(&p, " \t")))
				if (*match)
					break;
			if (!match) {
				syslog(LOG_DEBUG, "no ip/cidr given");
				continue;
			}
			while ((hwaddr = strsep(&p, " \t")))
				if (*hwaddr)
					break;
			p = strchr(match, '/');
			if (p) {
				*p++ = '\0';
				if (*p) {
					errno = 0;
					cidr = strtol(p, &r, 10);
					if (errno == 0 && !*r) {
						if (cidr < 0 || cidr > 32) {
							syslog(LOG_DEBUG,
							       "%s: invalid "
							       "cidr", p);
							continue;
						}
						net <<= (32 - cidr);
						net = htonl(net);
					} else {
						if (inet_aton(p, &ina) == 0) {
							syslog(LOG_DEBUG,
							       "%s: invalid "
						               "netmask", p);
							continue;
						}
						net = ina.s_addr;
					}
				}
			}
			if (inet_aton(match, &ina) == 0) {
				syslog(LOG_DEBUG, "%s: invalid inet addr",
				       match);
				continue;
			}
			if (hwaddr) {
				len = hwaddr_aton(NULL, hwaddr);
				if (!len) {
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
			/* OK, good to add now. */
			pp = malloc(sizeof(*pp));
			if (!pp) {
				syslog(LOG_ERR, "memory exhausted");
				exit(EXIT_FAILURE);
			}
			pp->action = act;
			pp->ip = ina.s_addr;
			pp->net = net;
			if (hwaddr)
				pp->hwlen = hwaddr_aton(pp->hwaddr, hwaddr);
			else
				pp->hwlen = 0;
			pp->next = pents;
			pents = pp;
		}
		fclose(f);
	}

	for (pp = pents; pp; pp = pp->next) {
		if (pp->ip == ip ||
		    pp->ip == INADDR_ANY ||
		    pp->ip == (ip & pp->net)) {
			if (hw)
				*hw = pp->hwaddr;
			if (hwlen)
				*hwlen = pp->hwlen;
			return pp->action;
		}
	}

	return 0;
}

#define ARP_LEN \
	(sizeof(struct arphdr) + (2 * sizeof(uint32_t)) + (2 * HWADDR_LEN))

static int
send_arp(const struct interface *iface, int op, size_t hlen,
	 uint8_t *sha, in_addr_t sip, uint8_t *tha, in_addr_t tip)
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

static void
handle_arp(struct interface *iface)
{
	uint8_t arp_buffer[ARP_LEN], *shw, *thw, *phw;
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
		if (proxy(tip, &phw, &hwlen) != 1)
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
	struct interface *iface;
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

	if (proxy(0, NULL, NULL) == -1) {
		syslog(LOG_ERR, "%s: %m", cffile);
		exit(EXIT_FAILURE);
	}
	if (!pents) {
		syslog(LOG_ERR, "%s: no valid entries", cffile);
		exit(EXIT_FAILURE);
	}

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
/*
 * parpd: Proxy ARP Daemon
 * Copyright (c) 2008-2024 Roy Marples <roy@marples.name>
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

const char copyright[] = "Copyright (c) 2008-2024 Roy Marples";

#include <sys/ioctl.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <net/if.h>
#ifdef AF_LINK
#  include <net/if_dl.h>
#  include <net/if_types.h>
#endif
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#ifdef AF_PACKET
#  include <netpacket/packet.h>
#endif

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <ifaddrs.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "common.h"
#include "config.h"
#include "parpd.h"
#include "eloop.h"

static char hwaddr_buffer[(HWADDR_LEN * 3) + 1];

static void
usage(void)
{

	printf("usage: parpd [-dfl] [-c file] [interface [...]]\n");
}

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

static void
free_prefix(__unused void *arg, __unused const void *key, __unused size_t len,
    void *val)
{

	free(val);
}

static void free_prefixes(lpm_t **prefixes)
{

	if (*prefixes == NULL)
		return;

	lpm_clear(*prefixes, free_prefix, NULL);
	free(*prefixes);
	*prefixes = NULL;
}

static void
free_config(struct ctx *ctx)
{
	struct interface *ifp;

	free_prefixes(&ctx->prefixes);
	TAILQ_FOREACH(ifp, &ctx->ifaces, next) {
		free_prefixes(&ifp->prefixes);
	}
}

static int
load_config(struct ctx *ctx)
{
	int error = -1;
	struct stat st;
	FILE *f;
	char *buf, *cmd, *match, *hwaddr, *bp, *p, *e, *r, act;
	size_t buf_len;
	ssize_t len;
	struct prefix *pp;
	long plen;
	int in_interface;
	struct in_addr ina;
	struct interface *ifp;
	lpm_t *prefixes;

	if (stat(ctx->cffile, &st) == -1) {
		free_config(ctx);
		return -1;
	}
	if (ctx->config_mtime == st.st_mtime)
		return 0;

	free_config(ctx);
	f = fopen(ctx->cffile, "r");
	if (f == NULL)
		return -1;

	ctx->config_mtime = st.st_mtime;
	ifp = NULL;
	in_interface = 0;
	buf = NULL;
	buf_len = 0;

	while ((len = getline(&buf, &buf_len, f)) != -1) {
		bp = buf;
		e = buf + len;
		cmd = get_word(&bp, e);
		if (!cmd || *cmd == '\n' || *cmd == '#' || *cmd == ';')
			continue;
		match = get_word(&bp, e);
		if (strcmp(cmd, "proxy") == 0)
			act = PARPD_PROXY;
		else if (strcmp(cmd, "half") == 0 ||
		    strcmp(cmd, "halfproxy") == 0)
			act = PARPD_HALFPROXY;
		else if (strcmp(cmd, "attack") == 0)
			act = PARPD_ATTACK;
		else if (strcmp(cmd, "ignore") == 0)
			act = PARPD_IGNORE;
		else if (strcmp(cmd, "interface") == 0) {
			TAILQ_FOREACH(ifp, &ctx->ifaces, next) {
				if (strcmp(ifp->ifname, match) == 0)
					break;
			}
			if (ifp == NULL)
				syslog(LOG_ERR,
				    "%s: unknown interface", match);
			continue;
		} else {
			syslog(LOG_ERR, "%s: unknown command", cmd);
			continue;
		}
		if (in_interface && ifp == NULL)
			continue;
		hwaddr = get_word(&bp, e);
		if (!match) {
			syslog(LOG_DEBUG, "no ip/cidr given");
			continue;
		}
		plen = 32;
		p = strchr(match, '/');
		if (p) {
			*p++ = '\0';
			if (*p) {
				errno = 0;
				plen = strtol(p, &r, 10);
				if (errno == 0 && !*r) {
					if (plen < 0 || plen > 32) {
						syslog(LOG_DEBUG,
						    "%s: invalid cidr", p);
						continue;
					}
				} else {
					if (inet_aton(p, &ina) == 0) {
						syslog(LOG_DEBUG,
						    "%s: invalid mask", p);
						continue;
					}
					plen = 0;
					while (ina.s_addr) {
						plen++;
						ina.s_addr <<= 1;
					}
				}
			}
		}
		if (inet_pton(AF_INET, match, &ina) <= 0) {
			syslog(LOG_DEBUG, "%s: invalid inet addr", match);
			continue;
		}
		if (hwaddr != NULL) {
			if (*hwaddr == '#' || *hwaddr == ';') {
				hwaddr = NULL;
			} else {
				size_t hlen = hwaddr_aton(NULL, hwaddr);

				if (hlen == 0) {
					syslog(LOG_DEBUG,
					    "%s: invalid hw addr", hwaddr);
					continue;
				}
				if (hlen > HWADDR_LEN) {
					syslog(LOG_DEBUG,
					    "%s: hw addr too long", hwaddr);
					continue;
				}
			}
		}

		if (ifp != NULL) {
			if (ifp->prefixes == NULL)
				ifp->prefixes = lpm_create();
			prefixes = ifp->prefixes;
		} else {
			if (ctx->prefixes == NULL)
				ctx->prefixes = lpm_create();
			prefixes = ctx->prefixes;
		}
		if (prefixes == NULL) {
			syslog(LOG_ERR, "lpm_create: %m");
			goto err;
		}

		/* Check if we have already added the prefix,
		 * overwrite it if we have. */
		pp = lpm_lookup_prefix(prefixes, &ina.s_addr,
		    sizeof(ina.s_addr), (unsigned int)plen);
		if (pp == NULL) {
			pp = malloc(sizeof(*pp));
			if (pp == NULL)
				goto err;
			pp->ip = ina.s_addr;
			pp->plen = (unsigned int)plen;
			if (lpm_insert(prefixes, &pp->ip, sizeof(pp->ip),
			    pp->plen, pp) == -1)
			{
				syslog(LOG_ERR, "lpm_insert: %m");
				free(pp);
				goto err;
			}
		}

		pp->action = act;
		if (hwaddr == NULL)
			pp->hwlen = 0;
		else
			pp->hwlen = hwaddr_aton(pp->hwaddr, hwaddr);
	}

	error = 0;

err:
	fclose(f);
	free(buf);
	return error;
}

static int
proxy(struct ctx *ctx, struct interface *ifp, in_addr_t ip,
    const uint8_t **hw, size_t *hwlen)
{
	struct prefix *pp;

	if (load_config(ctx) == -1)
		return -1;

	if (ifp->prefixes != NULL)
		pp = lpm_lookup(ifp->prefixes, &ip, sizeof(ip));
	else
		pp = NULL;
	if (pp == NULL && ctx->prefixes != NULL)
		pp = lpm_lookup(ctx->prefixes, &ip, sizeof(ip));
	if (pp == NULL)
		return PARPD_IGNORE;

	if (pp->action) {
		*hw = pp->hwaddr;
		*hwlen = pp->hwlen;
	}
	return pp->action;
}

#define ARP_LEN								      \
	(sizeof(struct arphdr) + (2 * sizeof(uint32_t)) + (2 * HWADDR_LEN))
/* Does what is says on the tin - sends an ARP message */
static ssize_t
send_arp(const struct interface *ifp, uint16_t op, size_t hlen,
    const uint8_t *sha, in_addr_t sip, const uint8_t *tha, in_addr_t tip)
{
	uint8_t arp_buffer[ARP_LEN];
	struct arphdr ar;
	size_t len;
	uint8_t *p;

	ar.ar_hrd = htons(ifp->family);
	ar.ar_pro = htons(ETHERTYPE_IP);
	ar.ar_hln = (uint8_t)hlen;
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
	len = (size_t)(p - arp_buffer);
	return bpf_write(ifp, tha, hlen, arp_buffer, len);
}

static void
expire_ipaddr(void *arg)
{
	struct ipaddr *ipa = arg;

	ipaddr_map_erase(&ipa->ifp->ipaddrs, ipa->ipaddr);
	free(ipa);
}

/* Checks an incoming ARP message to see if we should proxy for it. */
static void
handle_arp(void *arg, unsigned short events)
{
	struct interface *ifp = arg;
	struct ctx *ctx = ifp->ctx;
	uint8_t arp_buffer[ARP_LEN], *shw, *thw;
	const uint8_t *phw;
	struct arphdr ar;
	in_addr_t sip, tip;
	size_t hwlen;
	ssize_t bytes;
	struct in_addr ina;
	int action;
	struct ipaddr *ipa;
	ipaddr_map_itr itr;

	if (events != ELE_READ)
		syslog(LOG_ERR, "%s: unexpected event 0x%04x",
		    __func__, events);

	for(;;) {
		bytes = bpf_read(ifp, arp_buffer, sizeof(arp_buffer));
		if (bytes == 0 || bytes == -1)
			return;
		/* We must have a full ARP header */
		if ((size_t)bytes < sizeof(ar))
			continue;
		memcpy(&ar, arp_buffer, sizeof(ar));

		/* Below checks are now enforced by BPF */
#if 0
		/* Protocol must be IP. */
		if (ar.ar_pro != htons(ETHERTYPE_IP))
			continue;
		if (ar.ar_pln != sizeof(sip))
			continue;
		/* We presently only work with REQUEST.
		 * Should we make REPLY knock out our config entries? */
		if (ar.ar_op != htons(ARPOP_REQUEST))
			continue;
#endif

		/* Get pointers to the hardware addreses */
		shw = arp_buffer + sizeof(ar);
		thw = shw + ar.ar_hln + ar.ar_pln;
		/* Ensure we got all the data */
		if ((thw + ar.ar_hln + ar.ar_pln) - arp_buffer > bytes)
			continue;
		/* Ignore messages from ourself */
		if (ar.ar_hln == ifp->hwlen &&
		    memcmp(shw, ifp->hwaddr, ifp->hwlen) == 0)
			continue;
		/* Copy out the IP addresses */
		memcpy(&tip, thw + ar.ar_hln, ar.ar_pln);
		memcpy(&sip, shw + ar.ar_hln, ar.ar_pln);
		ina.s_addr = tip;
		syslog(LOG_DEBUG, "%s: received ARPOP_REQUEST for %s",
		    ifp->ifname, inet_ntoa(ina));
		if ((action = proxy(ctx, ifp, tip, &phw, &hwlen)) == -1)
		{
			syslog(LOG_ERR, "proxy: %m");
			continue;
		}
		if (action == PARPD_IGNORE)
			continue;
		if (action == PARPD_HALFPROXY && sip == INADDR_ANY)
			continue;

		if (action == PARPD_ATTACK) {
			/* Only attack announcements. */
			if (tip != sip)
				continue;

			ipa = calloc(1, sizeof(*ipa));
			if (ipa == NULL) {
				syslog(LOG_ERR, "calloc: %m");
				continue;
			}
			ipa->ifp = ifp;
			ipa->ipaddr = sip;
			itr = ipaddr_map_get_or_insert(&ifp->ipaddrs,
			    ipa->ipaddr, ipa);
			if (ipaddr_map_is_end(itr)) {
				syslog(LOG_ERR, "ipaddr_insert: %m");
				continue;
			} else if (itr.data->val != ipa) {
				free(ipa);
				ipa = itr.data->val;
			}

			/* Expire the entry if no follow-up. */
			eloop_timeout_add_sec(ctx->eloop, ATTACK_EXPIRE,
			    expire_ipaddr, ipa);

			/* Only attack fully announced. */
			if (++ipa->nannounced < ANNOUNCE_NUM)
				continue;
		}

		/* If no hardware address specified in config,
		 * use the interface hardware address */
		if (hwlen == 0) {
			phw = ifp->hwaddr;
			hwlen = ifp->hwlen;
		}
		/* Our address lengths need to be the same */
		if (hwlen != ifp->hwlen) {
			syslog(LOG_DEBUG, "%s: hwlen different, not replying",
			    ifp->ifname);
			continue;
		}
		ina.s_addr = tip;
		syslog(LOG_INFO, "%s: sending ARPOP_REPLY %s (%s)",
		    ifp->ifname, inet_ntoa(ina), hwaddr_ntoa(phw, hwlen));
		send_arp(ifp, ARPOP_REPLY, hwlen, phw, tip, shw, sip);
	}
}

static int
ifa_valid(int s, const struct ifaddrs *ifa)
{
	struct ifreq ifr;

	if (ifa->ifa_addr == NULL)
		return 0;
#ifdef AF_LINK
	if (ifa->ifa_addr->sa_family != AF_LINK)
		return 0;
#elif AF_PACKET
	if (ifa->ifa_addr->sa_family != AF_PACKET)
		return 0;
#endif

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifa->ifa_name, sizeof(ifr.ifr_name));
	if (ioctl(s, SIOCGIFFLAGS, &ifr) == -1) {
		syslog(LOG_ERR, "%s: SIOGIFFLAGS: %m", ifa->ifa_name);
		return -1;
	}
	if (ifr.ifr_flags & IFF_LOOPBACK ||
	    ifr.ifr_flags & IFF_POINTOPOINT ||
	    ifr.ifr_flags & IFF_NOARP)
		return 0;

	return 1;
}

static void
discover_interfaces(struct ctx *ctx, int argc, char * const *argv)
{
	struct ifaddrs *ifaddrs, *ifa;
	int s, i;
	struct interface *ifp;
#ifdef AF_LINK
	const struct sockaddr_dl *sdl;
#elif AF_PACKET
	const struct sockaddr_ll *sll;
#endif

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		syslog(LOG_ERR, "socket: %m");
		return;
	}
	if (getifaddrs(&ifaddrs) == -1) {
		syslog(LOG_ERR, "getifaddrs: %m");
		close(s);
		return;
	}

	for (ifa = ifaddrs; ifa; ifa = ifa->ifa_next) {
		if (ifa_valid(s, ifa) != 1)
			continue;

		if (argc > 0) {
			for (i = 0; i < argc; i++)
				if (strcmp(argv[i], ifa->ifa_name) == 0)
					break;
			if (i == argc)
				continue;
		}

		/* Some systems have more than one AF_LINK.
		 * The first one returned is the active one. */
		TAILQ_FOREACH(ifp, &ctx->ifaces, next) {
			if (strcmp(ifp->ifname, ifa->ifa_name) == 0)
				break;
		}
		if (ifp != NULL)
			continue;

		ifp = calloc(1, sizeof(*ifp));
		if (ifp == NULL) {
			syslog(LOG_ERR, "calloc: %m");
			break;
		}
		strlcpy(ifp->ifname, ifa->ifa_name, sizeof(ifp->ifname));
		ifp->ctx = ctx;
		ifp->fd = -1;

#ifdef AF_LINK
		sdl = (const struct sockaddr_dl *)(void *)ifa->ifa_addr;
		switch(sdl->sdl_type) {
		case IFT_ETHER:
			ifp->family = ARPHRD_ETHER;
			break;
		case IFT_IEEE1394:
			ifp->family = ARPHRD_IEEE1394;
			break;
		}
		ifp->hwlen = sdl->sdl_alen;
#ifndef CLLADDR
#  define CLLADDR(s) ((const char *)((s)->sdl_data + (s)->sdl_nlen))
#endif
		memcpy(ifp->hwaddr, CLLADDR(sdl), ifp->hwlen);
#elif AF_PACKET
		sll = (const struct sockaddr_ll *)(void *)ifa->ifa_addr;
		ifp->family = sll->sll_hatype;
		ifp->hwlen = sll->sll_halen;
		if (ifp->hwlen != 0)
			memcpy(ifp->hwaddr, sll->sll_addr, ifp->hwlen);
#endif

		vt_init(&ifp->ipaddrs);

		TAILQ_INSERT_TAIL(&ctx->ifaces, ifp, next);
	}
	freeifaddrs(ifaddrs);
	close(s);
}

const int parpd_signals[] = {
	SIGTERM,
	SIGINT
};
const size_t parpd_signals_len =
    sizeof(parpd_signals) / sizeof(parpd_signals[0]);

static void
parpd_signal_cb(int sig, void *arg)
{

	syslog(LOG_ERR, "received SIG%s(%d)",
	    sig == SIGTERM ? "TERM" : sig == SIGINT ? "INT" : "UNKNOWN",
	    sig);
	eloop_exit(arg, sig == SIGTERM ? EXIT_SUCCESS : EXIT_FAILURE);
}

int
main(int argc, char **argv)
{
	struct ctx ctx = { .cffile = PARPD_CONF };
	struct interface *ifp;
	int opt, fflag = 0, i;
	struct eloop *eloop;
	sigset_t sigset;

	opt = EXIT_FAILURE;
	openlog("parpd", LOG_PERROR, LOG_DAEMON);
	setlogmask(LOG_UPTO(LOG_NOTICE));

	if ((ctx.eloop = eloop = eloop_new()) == NULL) {
		syslog(LOG_ERR, "eloop_new: %m");
		goto out;
	}
	if (eloop_signal_set_cb(eloop,
	    parpd_signals, parpd_signals_len, parpd_signal_cb, eloop) == -1) {
		syslog(LOG_ERR, "eloop_signal_set_cb: %m");
		goto out;
	}
	if (eloop_signal_mask(eloop, &sigset) == -1) {
		syslog(LOG_ERR, "eloop_signal_mask: %m");
		goto out;
	}

	while ((opt = getopt(argc, argv, "c:dfl")) != -1)
	{
		switch (opt) {
		case 'c':
			ctx.cffile = optarg;
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

	opt = EXIT_FAILURE;

	TAILQ_INIT(&ctx.ifaces);
	discover_interfaces(&ctx, argc, argv);

	for (i = 0; i < argc; i++) {
		TAILQ_FOREACH(ifp, &ctx.ifaces, next) {
			if (strcmp(ifp->ifname, argv[i]) == 0)
				break;
		}
		if (ifp == NULL) {
			syslog(LOG_ERR, "%s: no such interface", argv[i]);
			goto out;
		}
	}
	if (TAILQ_FIRST(&ctx.ifaces) == NULL) {
		syslog(LOG_ERR, "no suitable interfaces found");
		goto out;
	}

	if (load_config(&ctx) == -1) {
		syslog(LOG_ERR, "%s: %m", ctx.cffile);
		goto out;
	}

	i = 0;
	TAILQ_FOREACH(ifp, &ctx.ifaces, next) {
		if (ctx.prefixes == NULL && ifp->prefixes == NULL)
			continue;

		if ((ifp->fd = bpf_open_arp(ifp)) == -1) {
			syslog(LOG_ERR, "%s: bpf_open_arp: %m", ifp->ifname);
			continue;
		}

		syslog(LOG_DEBUG, "proxying on %s", ifp->ifname);
		eloop_event_add(eloop, ifp->fd, ELE_READ, handle_arp, ifp);
		i = 1;
	}
	if (i == 0) {
		syslog(LOG_ERR, "%s: nothing todo", ctx.cffile);
		goto out;
	}

	if (!fflag) {
		if (daemon(0, 0) == -1) {
			syslog(LOG_ERR, "daemon: %m");
			goto out;
		}

		/* At least for kqueue, poll_fd gets invalidated by fork */
                if (eloop_forked(eloop) == -1) {
                        syslog(LOG_ERR, "eloop_requeue after fork: %m");
                        goto out;
                }
	}

	opt = eloop_start(eloop, &sigset);

out:
#ifdef SANITIZE_MEMORY
	free_config(&ctx);
	while ((ifp = TAILQ_FIRST(&ctx.ifaces)) != NULL) {
		ipaddr_map_itr itr;

		TAILQ_REMOVE(&ctx.ifaces, ifp, next);
		for (itr = ipaddr_map_first(&ifp->ipaddrs);
		    !ipaddr_map_is_end(itr);
		    itr = ipaddr_map_next(itr))
		{
			free(itr.data->val);
		}
		if (ifp->fd != -1)
			close(ifp->fd);
		free(ifp->buffer);
		free(ifp);
	}

	eloop_free(eloop);
#endif

	return opt;
}

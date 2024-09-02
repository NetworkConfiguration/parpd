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

static void
in_len2mask(in_addr_t *mask, unsigned int len)
{
	unsigned int i;
	uint8_t *p;

	p = (uint8_t *)mask;
	memset(mask, 0, sizeof(*mask));
	for (i = 0; i < len / 8; i++)
		p[i] = 0xff;
	if (len % 8)
		p[i] = (uint8_t)((0xff00 >> (len % 8)) & 0xff);
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
pm_init(pstore_t *store) {
	unsigned int plen;
	pbucket_t *bucket;

	for (plen = 0; plen <= PREFIX_MAX_LEN; plen++) {
		bucket = &store->buckets[plen];
		bucket->plen = plen;
		in_len2mask(&bucket->mask, bucket->plen);
		bucket->set = false;
		paction_map_init(&bucket->prefixes);
	}
}

static void
pm_cleanup(pstore_t *store)
{
	unsigned int plen;
	pbucket_t *bucket;

	for (plen = 0; plen <= PREFIX_MAX_LEN; plen++) {
		bucket = &store->buckets[plen];
		paction_map_cleanup(&bucket->prefixes);
		bucket->set = false;
	}
}

static bool
pm_anyset(pstore_t *store)
{
	unsigned int plen;

	for (plen = 0; plen <= PREFIX_MAX_LEN; plen++) {
		if (store->buckets[plen].set)
			return true;
	}
	return false;
}

static paction_t *
pm_get(pstore_t *store, in_addr_t ip, unsigned int plen)
{
	pbucket_t *bucket;
	paction_map_itr itr;

	bucket = &store->buckets[plen];
	if (!bucket->set)
		return NULL;

	itr = paction_map_get(&bucket->prefixes, ip);
	if (paction_map_is_end(itr))
		return NULL;

	return itr.data->val;
}

static paction_t *
pm_lookup(pstore_t *store, in_addr_t ip)
{
	paction_map_itr itr;
	int plen = PREFIX_MAX_LEN;
	pbucket_t *bucket;
	in_addr_t addr;

	for (plen = PREFIX_MAX_LEN; plen >= 0; plen--) {
		bucket = &store->buckets[plen];
		if (!bucket->set) {
			continue;
		}

		addr = ip & bucket->mask;
		itr = paction_map_get(&bucket->prefixes, addr);
		if (!paction_map_is_end(itr))
			return itr.data->val;
	}

	return NULL;
}

static int
pm_insert(pstore_t *store, in_addr_t ip, unsigned int plen, paction_t *pa)
{
	pbucket_t *bucket;
	paction_map_itr itr;

	bucket = &store->buckets[plen];
	ip &= bucket->mask;
	itr = paction_map_insert(&store->buckets[plen].prefixes, ip, pa);
	if (paction_map_is_end(itr))
		return -1;

	bucket->set = true;
	return 0;
}

static void
free_config(struct ctx *ctx)
{
	struct interface *ifp;

	pm_cleanup(&ctx->pstore);
	TAILQ_FOREACH(ifp, &ctx->ifaces, next) {
		pm_cleanup(&ifp->pstore);
	}
}

static int
load_config(struct ctx *ctx)
{
	int error = -1;
	struct stat st;
	FILE *f;
	char *buf, *cmd, *match, *hwaddr, *bp, *p, *e, *r, act, *rangep;
	size_t buf_len;
	ssize_t len;
	long plen, range, range_end;
	struct in_addr ina;
	struct interface *ifp;
	paction_t *pa;
	pstore_t *pstore;
	struct timespec now;

	/* clock_gettime is more efficient than stat on bare-metal. */
	clock_gettime(CLOCK_MONOTONIC, &now);
	if (timespecisset(&ctx->config_cache)) {
		unsigned long long secs;

		secs = eloop_timespec_diff(&now, &ctx->config_cache, NULL);
		if (secs < CONFIG_CACHE_SECS) {
			return 0;
		}
	}
	ctx->config_cache = now;

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

		p = strchr(match, '-');
		if (p) {
			char *dash, *end, *endp;

			rangep = end = p;
			*end++ = '\0';
			rangep--;
			while (rangep > match && *rangep != '.')
				rangep--;
			if (*rangep == '.')
				rangep++;
			errno = 0;
			range = strtol(rangep, &dash, 10);
			if (errno == 0 && dash == p) {
				if (range < 0 || range > 255) {
					syslog(LOG_DEBUG,
					    "%s: invalid range", rangep);
					continue;
				}
			} else {
				if (errno == 0)
					errno = EINVAL;
				syslog(LOG_ERR, "%s: %m", rangep);
				continue;
			}

			range_end = strtol(end, &endp, 10);
			if (errno == 0) {
				if (range_end < 0 || range_end > 255) {
					syslog(LOG_DEBUG,
					    "%s: invalid range", end);
					continue;
				}
			} else {
				syslog(LOG_ERR, "%s: %m", end);
				continue;
			}
			if (range_end <= range) {
				syslog(LOG_DEBUG, "invalid end range (%ld<%ld)",
				    range_end, range);
				continue;
			}
		} else {
			range = range_end = -1;
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

		pstore = ifp != NULL ? &ifp->pstore : &ctx->pstore;

		for (; range <= range_end; range++) {
			if (range != -1) {
				// We know this is safe because the range string
				// must be bigger than the target we write.
				sprintf(rangep, "%ld", range);
			}

			if (inet_pton(AF_INET, match, &ina) <= 0) {
				syslog(LOG_DEBUG, "%s: invalid inet addr",
				    match);
				break;
			}

			/* Check if we have already added the prefix,
			 * overwrite it if we have. */
			pa = pm_get(pstore, ina.s_addr, (unsigned int)plen);
			if (pa == NULL) {
				pa = malloc(sizeof(*pa));
				if (pa == NULL)
					goto err;
				pa->ip = ina.s_addr;
				pa->plen = (unsigned int)plen;
				if (pm_insert(pstore, pa->ip, pa->plen, pa) == -1)
				{
					syslog(LOG_ERR, "pm_insert: %m");
					free(pa);
					goto err;
				}
			}

			pa->action = act;
			if (hwaddr == NULL)
				pa->hwlen = 0;
			else
				pa->hwlen = hwaddr_aton(pa->hwaddr, hwaddr);
		}
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
	paction_t *pa;

	if (load_config(ctx) == -1)
		return -1;

	pa = pm_lookup(&ifp->pstore, ip);
	if (pa == NULL)
		pa = pm_lookup(&ctx->pstore, ip);
	if (pa == NULL)
		return PARPD_IGNORE;

	if (pa->action) {
		*hw = pa->hwaddr;
		*hwlen = pa->hwlen;
	}
	return pa->action;
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

		pm_init(&ifp->pstore);
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

	pm_init(&ctx.pstore);
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
		if (!pm_anyset(&ctx.pstore) && !pm_anyset(&ifp->pstore))
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

	syslog(LOG_NOTICE, "parpd-%s started", VERSION);
	opt = eloop_start(eloop, &sigset);

out:
#ifdef SANITIZE_MEMORY
	free_config(&ctx);
	while ((ifp = TAILQ_FIRST(&ctx.ifaces)) != NULL) {
		TAILQ_REMOVE(&ctx.ifaces, ifp, next);
		ipaddr_map_cleanup(&ifp->ipaddrs);
		if (ifp->fd != -1)
			close(ifp->fd);
		free(ifp->buffer);
		free(ifp);
	}

	eloop_free(eloop);
#endif

	return opt;
}

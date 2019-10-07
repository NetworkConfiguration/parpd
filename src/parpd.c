/*
 * parpd: Proxy ARP Daemon
 * Copyright (c) 2008-2017 Roy Marples <roy@marples.name>
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

const char copyright[] = "Copyright (c) 2008-2017 Roy Marples";

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

static const char *cffile = PARPD_CONF;
static time_t config_mtime;

static rb_tree_t ifaces;
static rb_tree_t pents;

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

static int
if_compare(__unused void *context, const void *node1, const void *node2)
{
        const struct interface *if1 = node1, *if2 = node2;

	return strcmp(if1->ifname, if2->ifname);
}

static const rb_tree_ops_t if_compare_ops = {
	.rbto_compare_nodes = if_compare,
	.rbto_compare_key = if_compare,
	.rbto_node_offset = offsetof(struct interface, rbtree),
	.rbto_context = NULL
};

static int
p_compare(__unused void *context, const void *node1, const void *node2)
{
        const struct pent *p1 = node1, *p2 = node2;
	in_addr_t p2net;

	/* When searching for a node, the node we're finding is based on
	 * node 2. As far as pard is concerned, we only find an ip address
	 * so we need to compare it to the network from node 1.
	 * But we also need to allow node 2 to have a valid configuration
	 * when we initially load it. */
	if (p2->net != INADDR_ANY || p2->ip == INADDR_ANY)
		p2net = p2->net;
	else
		p2net = p1->net;

	return (int)((p1->ip & p1->net) - (p2->ip & p2net));
}

static const rb_tree_ops_t p_compare_ops = {
	.rbto_compare_nodes = p_compare,
	.rbto_compare_key = p_compare,
	.rbto_node_offset = offsetof(struct pent, rbtree),
	.rbto_context = NULL
};

static void
free_pents(rb_tree_t *pp)
{
	struct pent *pn;

	while ((pn = RB_TREE_MIN(pp)) != NULL) {
		rb_tree_remove_node(pp, pn);
		free(pn);
	}
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
free_config(void)
{
	struct interface *ifp;

	free_pents(&pents);
	RB_TREE_FOREACH(ifp, &ifaces)
		free_pents(&ifp->pents);
}

static int
load_config(void)
{
	struct stat st;
	FILE *f;
	char *buf, *cmd, *match, *hwaddr, *bp, *p, *e, *r, act;
	size_t buf_len;
	ssize_t len;
	struct pent *pp;
	long cidr;
	int in_interface;
	struct in_addr ina;
	in_addr_t net;
	struct interface *ifp;

	if (stat(cffile, &st) == -1) {
		free_config();
		return -1;
	}
	if (config_mtime == st.st_mtime)
		return 0;

	free_config();
	f = fopen(cffile, "r");
	if (f == NULL)
		return -1;

	config_mtime = st.st_mtime;
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
		else if (strcmp(cmd, "ignore") == 0)
			act = PARPD_IGNORE;
		else if (strcmp(cmd, "interface") == 0) {
			struct interface iff = { .fd = -1 };

			strlcpy(iff.ifname, match, sizeof(iff.ifname));
			ifp = rb_tree_find_node(&ifaces, &iff);
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

		/* OK, good to add now. */
		pp = malloc(sizeof(*pp));
		if (pp == NULL) {
			free_config();
			return -1;
		}
		pp->action = act;
		pp->ip = ina.s_addr & net;
		pp->net = net;
		if (hwaddr == NULL)
			pp->hwlen = 0;
		else
			pp->hwlen = hwaddr_aton(pp->hwaddr, hwaddr);
		if (ifp)
			rb_tree_insert_node(&ifp->pents, pp);
		else
			rb_tree_insert_node(&pents, pp);
	}
	fclose(f);
	free(buf);
	return 0;
}

static int
proxy(rb_tree_t *ps, in_addr_t ip, const uint8_t **hw, size_t *hwlen)
{
	struct pent pf = { .ip = ip }, *pp;

	if (load_config() == -1)
		return -1;

	pp = rb_tree_find_node(ps, &pf);
	if (pp == NULL) {
		pf.ip = INADDR_ANY;
		pp = rb_tree_find_node(ps, &pf);
		if (pp == NULL)
			 return PARPD_IGNORE;
	}

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
send_arp(const struct interface *ifp, int op, size_t hlen,
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

/* Checks an incoming ARP message to see if we should proxy for it. */
static void
handle_arp(void *arg)
{
	struct interface *ifp = arg;
	uint8_t arp_buffer[ARP_LEN], *shw, *thw;
	const uint8_t *phw;
	struct arphdr ar;
	in_addr_t sip, tip;
	size_t hwlen;
	ssize_t bytes;
	struct in_addr ina;
	int action;

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
		if ((action = proxy(&ifp->pents, tip, &phw, &hwlen)) == -1) {
			syslog(LOG_ERR, "proxy: %m");
			continue;
		}
		if (action == PARPD_IGNORE &&
		    (action = proxy(&pents, tip, &phw, &hwlen)) == -1)
		{
			syslog(LOG_ERR, "proxy: %m");
			continue;
		}
		if (action == PARPD_IGNORE)
			continue;
		if (action == PARPD_HALFPROXY && sip == INADDR_ANY)
			continue;
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
discover_interfaces(int argc, char * const *argv)
{
	struct ifaddrs *ifaddrs, *ifa;
	int s, i;
	struct interface *ifs, *ifp;
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

	ifs = NULL;
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

		ifp = calloc(1, sizeof(*ifp));
		if (ifp == NULL) {
			syslog(LOG_ERR, "calloc: %m");
			break;
		}
		strlcpy(ifp->ifname, ifa->ifa_name, sizeof(ifp->ifname));
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

		rb_tree_init(&ifp->pents, &p_compare_ops);

		/* Some systems have more than one AF_LINK.
		 * The first one returned is the active one. */
		ifs = rb_tree_insert_node(&ifaces, ifp);
		if (ifs != ifp) {
			free(ifp);
			continue;
		}
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
	struct interface *ifp, *pifp;
	int opt, fflag = 0, i;
	struct eloop *eloop;
	sigset_t sigset;
	bool have_pents = false;

	opt = EXIT_FAILURE;
	openlog("parpd", LOG_PERROR, LOG_DAEMON);
	setlogmask(LOG_UPTO(LOG_NOTICE));

	if ((eloop = eloop_new()) == NULL) {
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

	opt = EXIT_FAILURE;

	rb_tree_init(&ifaces, &if_compare_ops);
	rb_tree_init(&pents, &p_compare_ops);

	discover_interfaces(argc, argv);
	for (i = 0; i < argc; i++) {
		struct interface iff = { .fd = -1 };

		strlcpy(iff.ifname, argv[i], sizeof(iff.ifname));
		ifp = rb_tree_find_node(&ifaces, &iff);
		if (ifp == NULL) {
			syslog(LOG_ERR, "%s: no such interface", argv[i]);
			goto out;
		}
	}
	if (RB_TREE_MIN(&ifaces) == NULL) {
		syslog(LOG_ERR, "no suitable interfaces found");
		goto out;
	}

	if (load_config() == -1) {
		syslog(LOG_ERR, "%s: %m", cffile);
		goto out;
	}

	have_pents = (RB_TREE_MIN(&pents) != NULL);
	pifp = NULL;
	RB_TREE_FOREACH(ifp, &ifaces) {
		bool if_have_pents = (RB_TREE_MIN(&ifp->pents) != NULL);

		if (if_have_pents)
			pifp = ifp;
		if (!if_have_pents && !have_pents)
			continue;

		if ((ifp->fd = bpf_open_arp(ifp)) == -1) {
			syslog(LOG_ERR, "%s: bpf_open_arp: %m", ifp->ifname);
			continue;
		}

		syslog(LOG_DEBUG, "proxying on %s", ifp->ifname);
		eloop_event_add(eloop, ifp->fd, handle_arp, ifp);
	}
	if (pifp == NULL && !have_pents) {
		syslog(LOG_ERR, "%s: no valid entries", cffile);
		goto out;
	}

	if (!fflag) {
		if (daemon(0, 0) == -1) {
			syslog(LOG_ERR, "daemon: %m");
			goto out;
		}

		/* At least for kqueue, poll_fd gets invalidated by fork */
                if (eloop_requeue(eloop) == -1) {
                        syslog(LOG_ERR, "eloop_requeue after fork: %m");
                        goto out;
                }
	}

	opt = eloop_start(eloop, &sigset);

out:
	free_pents(&pents);
	while ((ifp = RB_TREE_MIN(&ifaces)) != NULL) {
		rb_tree_remove_node(&ifaces, ifp);
		free_pents(&ifp->pents);
		free(ifp->buffer);
		free(ifp);
	}

	eloop_free(eloop);
	return opt;
}

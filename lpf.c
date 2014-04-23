/*
 * parpd - Proxy ARP Daemon
 * Copyright (c) 2008-2014 Roy Marples <roy@marples.name>
 *
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

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>

#include <asm/types.h> /* needed for 2.4 kernels for the below header */
#include <linux/filter.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#define bpf_insn sock_filter
#define BPF_SKIPTYPE
#define BPF_ETHCOOK		-ETH_HLEN
#define BPF_WHOLEPACKET	0x0fffffff /* work around buggy LPF filters */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bpf-filter.h"
#include "parpd.h"

int
open_arp(struct interface *ifp)
{
	int s, flags;
	struct sockaddr_ll sll;
	struct sock_fprog pf;

	if ((s = socket(PF_PACKET, SOCK_DGRAM, htons(ETHERTYPE_ARP))) == -1)
		return -1;

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = PF_PACKET;
	sll.sll_protocol = htons(ETHERTYPE_ARP);
	if (!(sll.sll_ifindex = if_nametoindex(ifp->ifname))) {
		errno = ENOENT;
		goto eexit;
	}
	/* Install the DHCP filter */
	memset(&pf, 0, sizeof(pf));
	pf.filter = UNCONST(arp_bpf_filter);
	pf.len = arp_bpf_filter_len;
	if (setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &pf, sizeof(pf)) != 0)
		goto eexit;
	if ((flags = fcntl(s, F_GETFL, 0)) == -1
	    || fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1)
		goto eexit;
	if (bind(s, (struct sockaddr *)&sll, sizeof(sll)) == -1)
		goto eexit;
	return s;

eexit:
	close(s);
	return -1;
}

ssize_t
send_raw_packet(const struct interface *ifp,
    const uint8_t *hwaddr, size_t hwlen,
    const void *data, size_t len)
{
	struct sockaddr_ll sll;

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETHERTYPE_ARP);
	if (!(sll.sll_ifindex = if_nametoindex(ifp->ifname))) {
		errno = ENOENT;
		return -1;
	}
	sll.sll_hatype = htons(ifp->family);
	sll.sll_halen = hwlen;
	memcpy(sll.sll_addr, hwaddr, hwlen);

	return sendto(ifp->fd, data, len, 0,
	    (struct sockaddr *)&sll, sizeof(sll));
}

ssize_t
get_raw_packet(struct interface *ifp, void *data, size_t len)
{
	ssize_t bytes;

	bytes = read(ifp->fd, data, len);
	if (bytes == -1)
		return errno == EAGAIN ? 0 : -1;
	return bytes;
}

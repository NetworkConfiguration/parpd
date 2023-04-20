/*
 * parpd: Linux Packet Filter
 * Copyright (c) 2008-2023 Roy Marples <roy@marples.name>
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
#include <sys/uio.h>

#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>

#include <asm/types.h> /* needed for 2.4 kernels for the below header */
#include <linux/filter.h>
#include <net/ethernet.h>
#include <netpacket/packet.h>
#define bpf_insn sock_filter
#define BPF_WHOLEPACKET	0x7fffffff /* work around buggy LPF filters */

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bpf-filter.h"
#include "parpd.h"

int
bpf_open_arp(struct interface *ifp)
{
	int s, flags;
	union sockunion {
		struct sockaddr sa;
		struct sockaddr_ll sll;
		struct sockaddr_storage ss;
	} su;
	struct sock_fprog pf;

	if ((s = socket(PF_PACKET, SOCK_RAW, htons(ETHERTYPE_ARP))) == -1)
		return -1;

	/* Install the ARP filter */
	memset(&pf, 0, sizeof(pf));
	pf.filter = UNCONST(bpf_arp_filter);
	pf.len = bpf_arp_filter_len;
	if (setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &pf, sizeof(pf)) != 0)
		goto eexit;
	if ((flags = fcntl(s, F_GETFL, 0)) == -1
	    || fcntl(s, F_SETFL, flags | O_NONBLOCK) == -1)
		goto eexit;

	/* Allocate a suitably large buffer for a single packet. */
	if (ifp->buffer_size < ETH_DATA_LEN) {
		void *nb;

		if ((nb = realloc(ifp->buffer, ETH_DATA_LEN)) == NULL)
			goto eexit;
		ifp->buffer = nb;
		ifp->buffer_size = ETH_DATA_LEN;
		ifp->buffer_len = ifp->buffer_pos = 0;
	}

	memset(&su, 0, sizeof(su));
	su.sll.sll_family = PF_PACKET;
	su.sll.sll_protocol = htons(ETH_P_ALL);
	su.sll.sll_ifindex = (int)if_nametoindex(ifp->ifname);
	if (bind(s, &su.sa, sizeof(su.sll)) == -1)
		goto eexit;

	return s;

eexit:
	close(s);
	return -1;
}

ssize_t
bpf_write(const struct interface *ifp,
    const uint8_t *hwaddr, size_t hwlen,
    const void *data, size_t len)
{
	struct iovec iov[2];
	struct ether_header eh;

	if (ifp->hwlen != hwlen || hwlen != sizeof(eh.ether_dhost)) {
		errno = EINVAL;
		return -1;
	}

	memset(&eh, 0, sizeof(eh));
	memcpy(&eh.ether_dhost, hwaddr, sizeof(eh.ether_dhost));
	memcpy(&eh.ether_shost, ifp->hwaddr, sizeof(eh.ether_shost));
	eh.ether_type = htons(ETHERTYPE_ARP);
	iov[0].iov_base = &eh;
	iov[0].iov_len = sizeof(eh);
	iov[1].iov_base = UNCONST(data);
	iov[1].iov_len = len;
	return writev(ifp->fd, iov, 2);
}

ssize_t
bpf_read(struct interface *ifp, void *data, size_t len)
{
	ssize_t bytes;

	bytes = read(ifp->fd, ifp->buffer, ifp->buffer_size);
	if (bytes == -1)
		return errno == EAGAIN ? 0 : -1;
	if (bytes < ETHER_HDR_LEN) {
		errno = EINVAL;
		return -1;
	}
	bytes -= ETHER_HDR_LEN;
	if ((size_t)bytes > len)
		bytes = (ssize_t)len;
	memcpy(data, ifp->buffer + ETHER_HDR_LEN, (size_t)bytes);
	return bytes;
}

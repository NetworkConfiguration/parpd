/*
 * parpd - Proxy ARP Daemon
 * Copyright (c) 2008-2016 Roy Marples <roy@marples.name>
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
#include <net/bpf.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <paths.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "parpd.h"
#include "bpf-filter.h"

int
open_arp(struct interface *ifp)
{
	int fd = -1;
	struct ifreq ifr;
	unsigned char *buf;
	int ibuf_len = 0;
	size_t buf_len;
	struct bpf_version pv;
	struct bpf_program pf;
#ifdef BIOCIMMEDIATE
	int flags;
#endif
#ifdef _PATH_BPF
	fd = open(_PATH_BPF, O_RDWR | O_NONBLOCK);
#else
	char device[PATH_MAX];
	int n = 0;

	do {
		snprintf(device, sizeof(device), "/dev/bpf%d", n++);
		fd = open(device, O_RDWR | O_NONBLOCK);
	} while (fd == -1 && errno == EBUSY);
#endif

	if (fd == -1)
		return -1;

	if (ioctl(fd, BIOCVERSION, &pv) == -1)
		goto eexit;
	if (pv.bv_major != BPF_MAJOR_VERSION ||
	    pv.bv_minor < BPF_MINOR_VERSION)
	{
		errno = EINVAL;
		goto eexit;
	}

	memset(&ifr, 0, sizeof(ifr));
	strlcpy(ifr.ifr_name, ifp->ifname, sizeof(ifr.ifr_name));
	if (ioctl(fd, BIOCSETIF, &ifr) == -1)
		goto eexit;

	/* Get the required BPF buffer length from the kernel. */
	if (ioctl(fd, BIOCGBLEN, &ibuf_len) == -1)
		goto eexit;
	buf_len = (size_t)ibuf_len;
	if (ifp->buffer_size != buf_len) {
		buf = realloc(ifp->buffer, buf_len);
		if (buf == NULL)
			goto eexit;
		ifp->buffer = buf;
		ifp->buffer_size = buf_len;
		ifp->buffer_len = ifp->buffer_pos = 0;
	}

#ifdef BIOCIMMEDIATE
	flags = 1;
	if (ioctl(fd, BIOCIMMEDIATE, &flags) == -1)
		goto eexit;
#endif

	pf.bf_insns = UNCONST(arp_bpf_filter);
	pf.bf_len = arp_bpf_filter_len;
	if (ioctl(fd, BIOCSETF, &pf) == -1)
		goto eexit;
	return fd;

eexit:
	free(ifp->buffer);
	ifp->buffer = NULL;
	close(fd);
	return -1;
}

ssize_t
send_raw_packet(const struct interface *ifp,
    const uint8_t *hwaddr, size_t hwlen,
    const void *data, size_t len)
{
	struct iovec iov[2];
	struct ether_header hw;

	memset(&hw, 0, ETHER_HDR_LEN);
	memcpy(&hw.ether_dhost, hwaddr, hwlen);
	hw.ether_type = htons(ETHERTYPE_ARP);
	iov[0].iov_base = &hw;
	iov[0].iov_len = ETHER_HDR_LEN;
	iov[1].iov_base = UNCONST(data);
	iov[1].iov_len = len;
	return writev(ifp->fd, iov, 2);
}

/* BPF requires that we read the entire buffer.
 * So we pass the buffer in the API so we can loop on >1 packet. */
ssize_t
get_raw_packet(struct interface *ifp, void *data, size_t len)
{
	struct bpf_hdr packet;
	ssize_t bytes;
	const unsigned char *payload;

	for (;;) {
		if (ifp->buffer_len == 0) {
			bytes = read(ifp->fd,
			    ifp->buffer, ifp->buffer_size);
			if (bytes == -1)
				return errno == EAGAIN ? 0 : -1;
			else if ((size_t)bytes < sizeof(packet))
				return -1;
			ifp->buffer_len = (size_t)bytes;
			ifp->buffer_pos = 0;
		}
		bytes = -1;
		memcpy(&packet, ifp->buffer + ifp->buffer_pos, sizeof(packet));
		if (packet.bh_caplen != packet.bh_datalen)
			goto next; /* Incomplete packet, drop. */
		if (ifp->buffer_pos + packet.bh_caplen + packet.bh_hdrlen >
		    ifp->buffer_len)
			goto next; /* Packet beyond buffer, drop. */
		payload = ifp->buffer + ifp->buffer_pos + \
		    packet.bh_hdrlen + ETHER_HDR_LEN;
		bytes = (ssize_t)packet.bh_caplen - ETHER_HDR_LEN;
		if ((size_t)bytes > len)
			bytes = (ssize_t)len;
		memcpy(data, payload, (size_t)bytes);
next:
		ifp->buffer_pos += BPF_WORDALIGN(packet.bh_hdrlen +
		    packet.bh_caplen);
		if (ifp->buffer_pos >= ifp->buffer_len)
			ifp->buffer_len = ifp->buffer_pos = 0;
		if (bytes != -1)
			return bytes;
	}
}

/*
 * parpd - Proxy ARP Daemon
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

#ifndef PARPD_H
#define PARPD_H

#include <net/if.h>

#include "config.h"

#define VERSION			"1.99"
#define PARPD_CONF		SYSCONFDIR "/parpd.conf"

#define HWADDR_LEN		20

#define PARPD_IGNORE		0
#define PARPD_PROXY		1
#define PARPD_HALFPROXY		2

struct pent {
	struct pent *next;
	char action;
	in_addr_t ip;
	in_addr_t net;
	uint8_t hwaddr[HWADDR_LEN];
	size_t hwlen;
};

struct interface
{
	struct interface *next;
	char ifname[IF_NAMESIZE];
	int family;
	unsigned char hwaddr[HWADDR_LEN];
	size_t hwlen;
	int fd;
	size_t buffer_size, buffer_len, buffer_pos;
	unsigned char *buffer;
	struct pent *pents;
};

int bpf_open_arp(struct interface *);
ssize_t bpf_write(const struct interface *,
    const uint8_t *, size_t, const void *, size_t);
ssize_t bpf_read(struct interface *, void *, size_t);

#define UNCONST(a)		((void *)(unsigned long)(const void *)(a))

#endif
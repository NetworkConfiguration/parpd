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

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include <net/ethernet.h>
#include <net/if_arp.h>

#include <arpa/inet.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "parpd.h"

/* Set of macros used to convert a numeric constant into a string constant */
#define STR(s) XSTR(s)
#define XSTR(s) #s

#define IF_NAMESIZE_S STR(IF_NAMESIZE)

struct interface *
discover_interfaces(int argc, char * const *argv)
{
	FILE *f;
	size_t n;
	int i, s;
	struct interface *ifs = NULL, *iface;
	struct ifreq ifr;

	f = fopen("/proc/net/dev", "r");
	if (!f)
		return NULL;
	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s == -1)
		return NULL;

	fscanf(f, "%*[^\n] %*[^\n] ");
	while (!feof(f)) {
		memset(&ifr, 0, sizeof(ifr));
		fscanf(f, "%" IF_NAMESIZE_S "[^:]:%*[^\n] ", ifr.ifr_name);
		if (argc > 0) {
			for (i = 0; i < argc; i++)
				if (strcmp(argv[i], ifr.ifr_name) == 0)
					break;
			if (i == argc)
				continue;
		}
		if (ioctl(s, SIOCGIFFLAGS, &ifr) == -1)
			continue;
		if (ifr.ifr_flags & IFF_LOOPBACK ||
		    ifr.ifr_flags & IFF_POINTOPOINT ||
		    ifr.ifr_flags & IFF_NOARP)
			continue;
		if (ioctl(s, SIOCGIFHWADDR, &ifr) == -1)
			continue;
		switch (ifr.ifr_hwaddr.sa_family) {
			case ARPHRD_ETHER:
			case ARPHRD_IEEE802:
				n = ETHER_ADDR_LEN;
				break;
			default:
				syslog(argc ? LOG_ERR : LOG_DEBUG,
				       "%s: unsupported media family",
				       ifr.ifr_name);
				continue;
		}
		iface = malloc(sizeof(*iface));
		if (!iface) {
			syslog(LOG_ERR, "memory exhausted");
			exit(EXIT_FAILURE);
		}
		strlcpy(iface->name, ifr.ifr_name, sizeof(iface->name));
		iface->hwlen = n;
		memcpy(iface->hwaddr, ifr.ifr_hwaddr.sa_data, iface->hwlen);
		iface->family = ifr.ifr_hwaddr.sa_family;
		iface->fd = open_arp(iface);
		if (iface->fd == -1) {
			syslog(LOG_ERR, "open_arp %s: %m", ifr.ifr_name);
			free(iface);
		} else {
			iface->next = ifs;
			ifs = iface;
		}
	}
	fclose(f);

	return ifs;
}

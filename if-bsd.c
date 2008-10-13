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

#include <sys/socket.h>
#include <sys/sysctl.h>
#include <sys/types.h>

#include <arpa/inet.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>

#include <ifaddrs.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include "parpd.h"

struct interface *
discover_interfaces(int argc, char * const *argv)
{
	struct interface *ifl = NULL, *iface;
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_dl *sdl;
	int i;

	if (getifaddrs(&ifap) != 0) {
		syslog(LOG_ERR, "getifaddrs: %m");
		return NULL;
	}

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		sdl = (struct sockaddr_dl *)ifa->ifa_addr;
		if (sdl->sdl_family != AF_LINK ||
		    ifa->ifa_flags & IFF_LOOPBACK ||
		    ifa->ifa_flags & IFF_POINTOPOINT ||
		    ifa->ifa_flags & IFF_NOARP ||
		    ifa->ifa_data == 0)
			continue;
		if (argc > 0) {
			for (i = 0; i < argc; i++)
				if (strcmp(ifa->ifa_name, argv[i]) == 0)
					break;
			if (i == argc)
				continue;
		}
 		if (sdl->sdl_type != IFT_ETHER || sdl->sdl_alen != 6) {
			syslog(argc ? LOG_ERR : LOG_DEBUG,
			       "%s: unsupported media family", ifa->ifa_name);
			continue;
		}
		iface = malloc(sizeof(*iface));
		if (!iface) {
			syslog(LOG_ERR, "memory exhausted");
			exit(EXIT_FAILURE);
		}
		strlcpy(iface->name, ifa->ifa_name, sizeof(iface->name));
		iface->family = ARPHRD_ETHER;
		iface->hwlen = sdl->sdl_alen;
		memcpy(iface->hwaddr, LLADDR(sdl), sdl->sdl_alen);
		iface->fd = open_arp(iface);
		if (iface->fd == -1) {
			syslog(LOG_ERR, "open_arp %s: %m", iface->name);
			free(iface);
		} else {
			iface->next = ifl;
			ifl = iface;
		}
	}
	return ifl;
}

/*
 * inet.c: Shared networking functions
 *
 * Copyright (C) 2023 Calvin Owens <jcalvinowens@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include "common.h"
#include "inet.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>

unsigned sa_any_len(const struct sockaddr_any *s)
{
	switch (s->sa.sa_family) {
	case AF_INET6:
		return sizeof(s->in6);

	case AF_INET:
		return sizeof(s->in);

	case AF_PACKET:
		return sizeof(s->ll);

	}

	fatal("Bad sockaddr family: %u\n", s->sa.sa_family);
}

int get_stream_listen(const struct sockaddr_any *sa)
{
	int listen_fd;
	int v;

	listen_fd = socket(sa->sa.sa_family, SOCK_STREAM, 0);
	if (listen_fd == -1) {
		err("Can't get listen socket: %m\n");
		return -1;
	}

	v = 0;
	if (sa->sa.sa_family == AF_INET6)
		setsockopt(listen_fd, IPPROTO_IPV6, IPV6_V6ONLY, &v, sizeof(v));

	v = 1;
	if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v))) {
		err("Can't set SO_REUSEADDR on socket: %m\n");
		goto err;
	}

	if (bind(listen_fd, (const struct sockaddr *)sa, sa_any_len(sa))) {
		err("Bad bind: %m\n");
		goto err;
	}

	if (listen(listen_fd, 32)) {
		err("Bad listen: %m\n");
		goto err;
	}

	return listen_fd;

err:
	close(listen_fd);
	return -1;
}

int get_stream_listen_one(const struct sockaddr_any *sa)
{
	int fd, nfd;

	fd = get_stream_listen(sa);
	if (fd == -1)
		return -1;

	nfd = accept(fd, NULL, NULL);
	if (nfd == -1)
		err("Bad accept: %m\n");

	close(fd);
	return nfd;
}

int get_stream_connect(const struct sockaddr_any *sa)
{
	int v = 1;
	int fd;

	fd = socket(sa->sa.sa_family, SOCK_STREAM, 0);
	if (fd == -1)
		fatal("Can't get connect socket: %m\n");

	if (connect(fd, (const struct sockaddr *)sa, sa_any_len(sa)))
		fatal("Can't connect: %m\n");

	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &v, sizeof(v)))
		fatal("Couldn't set TCP_NODELAY on socket: %m\n");

	return fd;
}

int get_dgram_connect(const struct sockaddr_any *sa)
{
	int fd;

	fd = socket(sa->sa.sa_family, SOCK_DGRAM, 0);
	if (fd == -1)
		fatal("Can't get dgram socket: %m\n");

	if (connect(fd, (const struct sockaddr *)sa, sa_any_len(sa)))
		fatal("Can't connect: %m\n");

	return fd;
}


int get_dgram_bind(const struct sockaddr_any *sa)
{
	int v = 1;
	int fd;

	fd = socket(sa->sa.sa_family, SOCK_DGRAM, 0);
	if (fd == -1)
		fatal("Can't get listen socket: %m\n");

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &v, sizeof(v)))
		fatal("Can't set SO_REUSEPORT on socket: %m\n");

	if (bind(fd, (const struct sockaddr *)sa, sa_any_len(sa)))
		fatal("Can't bind: %m\n");

	return fd;
}

void get_sock_macaddr(int sockfd, uint8_t *macaddr)
{
	const struct sockaddr_ll *ll = NULL;
	struct ifaddrs *c, *ifaddrs;
	const char *ifname = NULL;
	struct sockaddr_any addr;
	socklen_t addrlen;

	addrlen = sizeof(addr);
	if (getsockname(sockfd, (struct sockaddr *)&addr, &addrlen))
		fatal("Bad getsockname: %m\n");

	if (addrlen > sizeof(addr))
		fatal("Address too big\n");

	BUG_ON(addr.sa.sa_family != AF_INET && addr.sa.sa_family != AF_INET6);

	if (getifaddrs(&ifaddrs))
		fatal("Bad getifaddrs: %m\n");

	for (c = ifaddrs; c; c = c->ifa_next) {
		const struct sockaddr_any *p = (void *)c->ifa_addr;
		struct in6_addr cmpaddr;

		if (!p)
			continue;

		switch (p->sa.sa_family) {
		case AF_INET6:

			if (addr.sa.sa_family == AF_INET)
				break;

			if (memcmp(&p->in6.sin6_addr, &addr.in6.sin6_addr, 16) == 0) {
				ifname = c->ifa_name;
				goto found;
			}

			break;

		case AF_INET:

			// Handle v4-mapped-on-v6
			if (addr.sa.sa_family == AF_INET6) {
				memset(&cmpaddr, 0, sizeof(cmpaddr));
				cmpaddr.s6_addr[10] = 0xff;
				cmpaddr.s6_addr[11] = 0xff;
				memcpy(&cmpaddr.s6_addr[12], &p->in.sin_addr.s_addr, 4);
				if (memcmp(&cmpaddr, &addr.in6.sin6_addr, 16) == 0) {
					ifname = c->ifa_name;
					goto found;
				}

				break;
			}

			if (memcmp(&p->in.sin_addr, &addr.in.sin_addr, 4) == 0) {
				ifname = c->ifa_name;
				goto found;
			}

			break;
		}
	}

	fatal("Can't find our interface!\n");

found:
	for (c = ifaddrs; c; c = c->ifa_next) {
		const struct sockaddr *p = (void *)c->ifa_addr;

		if (!p || p->sa_family != AF_PACKET)
			continue;

		if (strcmp(ifname, c->ifa_name))
			continue;

		ll = (void *)p;
		break;
	}

	if (!ll)
		fatal("Can't find our MAC!\n");

	memcpy(macaddr, ll->sll_addr, 8);
	freeifaddrs(ifaddrs);
}

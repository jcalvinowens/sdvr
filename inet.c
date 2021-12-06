/*
 * inet.c: Shared networking functions
 *
 * Copyright (C) 2021 Calvin Owens <jcalvinowens@gmail.com>
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

	case AF_UNIX:
		return sizeof(s->un);

	}

	fatal("Bad sockaddr family: %u\n", s->sa.sa_family);
}

int get_stream_listen(const struct sockaddr_any *sa)
{
	int listen_fd;
	int v = 1;

	listen_fd = socket(sa->sa.sa_family, SOCK_STREAM, 0);
	if (listen_fd == -1) {
		err("Can't get listen socket: %m\n");
		return -1;
	}

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
	//int v = 1;
	int fd;

	fd = socket(sa->sa.sa_family, SOCK_STREAM, 0);
	if (fd == -1)
		fatal("Can't get connect socket: %m\n");

	if (connect(fd, (const struct sockaddr *)sa, sa_any_len(sa)))
		fatal("Can't connect: %m\n");

	//if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &v, sizeof(v)))
	//	fatal("Couldn't set TCP_NODELAY on socket: %m\n");

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
	struct sockaddr_in6 addr;
	socklen_t addrlen;

	addrlen = sizeof(addr);
	if (getsockname(sockfd, &addr, &addrlen))
		fatal("Bad getsockname: %m\n");

	if (addrlen > sizeof(addr))
		fatal("Address too big\n");

	if (getifaddrs(&ifaddrs))
		fatal("Bad getifaddrs: %m\n");

	for (c = ifaddrs; c; c = c->ifa_next) {
		const struct sockaddr_in6 *p = (void *)c->ifa_addr;

		if (!p || p->sin6_family != AF_INET6)
			continue;

		if (memcmp(&p->sin6_addr, &addr.sin6_addr, 16))
			continue;

		ifname = c->ifa_name;
		break;
	}

	if (!ifname)
		fatal("Can't find our interface!\n");

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

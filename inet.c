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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <net/if.h>
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

int get_dgram_bind(const struct sockaddr_any *sa)
{
	int v = 1;
	int fd;

	fd = socket(sa->sa.sa_family, SOCK_DGRAM,
		    sa->sa.sa_family == AF_PACKET ? sa->ll.sll_protocol : 0);
	if (fd == -1)
		fatal("Can't get listen socket: %m\n");

	if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &v, sizeof(v)))
		fatal("Can't set SO_REUSEPORT on socket: %m\n");

	if (bind(fd, (const struct sockaddr *)sa, sa_any_len(sa)))
		fatal("Can't bind: %m\n");

	return fd;
}

int find_ifindex(const char *name)
{
	int fd, i, nr = -1;

	fd = socket(AF_PACKET, SOCK_DGRAM, htons(1337));
	if (fd == -1)
		return -1;

	for (i = 1; i < 32; i++) {
		struct ifreq ifreq;

		ifreq.ifr_ifindex = i;
		if (ioctl(fd, SIOCGIFNAME, &ifreq))
			continue;

		if (!strcmp(ifreq.ifr_name, name)) {
			nr = i;
			break;
		}
	}

	close(fd);
	return nr;
}

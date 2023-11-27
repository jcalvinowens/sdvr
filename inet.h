#pragma once

#include <netinet/in.h>
#include <linux/if_packet.h>

struct sockaddr_any {
	union {
		struct sockaddr sa;
		struct sockaddr_in6 in6;	// AF_INET6
		struct sockaddr_in in;		// AF_INET
		struct sockaddr_ll ll;		// AF_PACKET
	};
};

unsigned sa_any_len(const struct sockaddr_any *s);

int get_dgram_bind(const struct sockaddr_any *sa);

int get_stream_listen(const struct sockaddr_any *sa);
int get_stream_listen_one(const struct sockaddr_any *sa);
int get_stream_connect(const struct sockaddr_any *sa);

void get_sock_macaddr(int sockfd, uint8_t *macaddr);
int find_ifindex(const char *name);

/*
 * sdvrd.c: The SDVR server
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

#include "proto.h"
#include "ring.h"

#include "common.h"
#include "crypto.h"
#include "inet.h"
#include "rc5.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <limits.h>
#include <stdbool.h>
#include <inttypes.h>
#include <time.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <fcntl.h>
#include <unistd.h>
#include <poll.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <sys/random.h>
#include <arpa/inet.h>

#include <linux/futex.h>
#include <linux/videodev2.h>

#include <urcu/urcu-qsbr.h>
#include <urcu/rculfhash.h>
#include <urcu/uatomic.h>

#define futex(...) syscall(SYS_futex, __VA_ARGS__)

static inline void sleep_us(int64_t us)
{
	const struct timespec t = {
		.tv_sec = us / 1000000,
		.tv_nsec = us % 1000000 * 1000,
	};

	if (clock_nanosleep(CLOCK_MONOTONIC, 0, &t, NULL))
		warn("Bad nanosleep: %m\n");
}

/*
 * For stream sockets, which store cookies in epoll_event data, cookie zero
 * indicates the listen() file descriptor.
 */
#define ACCEPT_COOKIE_MAGIC	((uint32_t)0)

struct rxpiece {
	struct sockaddr_any src;
	struct iovec iovec;

	unsigned record_len;
	unsigned record_off;

	uint8_t buf[];
};

struct client {
	int ring_fd;
	void *ring_mmap;
	uint64_t ring_size;
	uint64_t ring_cur_offset;
	uint32_t ring_cur_frame;
	pthread_mutex_t atom_lock;
};

struct connection {
	struct cds_lfht_node lfht_node;
	struct rcu_head rcu;
	uint32_t cookie;

	int stream_sockfd;
	struct sockaddr_any stream_srcaddr;
	struct frame_desc stream_cur_desc;
	struct rxpiece *stream_next;
	unsigned stream_cur_off;

	struct kx_msg_3 kxmsg;
	struct server_setup_dgram ssmsg;
	struct server_setup_desc sdesc;
	struct client_setup_desc cdesc;
	struct enckey *key;
	bool rx_cdesc;
	bool rx_vdata;

	struct client *client;
};

struct server {
	char server_name[SDVR_NAMELEN];
	struct sockaddr_any bindaddr;
	int stream_listen_fd;
	int stream_epoll_fd;
	int ifindex;
	int stop;

	struct cds_lfht *connection_lfht;
	const struct rc5_ctx *cookie_ctx;
	uint32_t next_cookie;

	pthread_t *stream_rx_threads;
	int nr_stream_rx_threads;
	pthread_t *udp_rx_threads;
	int nr_udp_rx_threads;
	pthread_t *ethernet_rx_threads;
	int nr_ethernet_rx_threads;

	const struct authkeypair *authkey;
	unsigned max_record_len;
	unsigned max_dgram_payload;
	int dgram_mmsg_batch;
	int epoll_event_batch;
	int listen_backlog;

	pthread_mutex_t ring_dir_lock;
	void *ring_dir_mmap;
	int ring_dir_fd;
};

static int lfht_match_cookie(struct cds_lfht_node *node, const void *key)
{
	const struct connection *conn = container_of(node, struct connection,
						     lfht_node);
	const uint32_t *cookie = key;

	return conn->cookie == *cookie;
}

static struct connection *lookup_client(struct server *s, uint32_t cookie)
{
	struct cds_lfht_node *node;
	struct cds_lfht_iter iter;

	cds_lfht_lookup(s->connection_lfht, cookie, lfht_match_cookie,
			&cookie, &iter);
	node = cds_lfht_iter_get_node(&iter);

	if (node == NULL)
		return NULL;

	return container_of(node, struct connection, lfht_node);
}

static void destroy_client(struct rcu_head *head)
{
	struct connection *conn = container_of(head, struct connection, rcu);

	if (conn->stream_sockfd != -1)
		close(conn->stream_sockfd);

	munmap(conn->client->ring_mmap, conn->client->ring_size);
	ftruncate(conn->client->ring_fd, 0);
	close(conn->client->ring_fd);
	free(conn->client);
	free(conn->key);
	free(conn);
}

static void stop_client(struct server *s, struct connection *conn)
{
	if (!cds_lfht_del(s->connection_lfht, &conn->lfht_node)) {
		if (conn->stream_sockfd != -1)
			shutdown(conn->stream_sockfd, SHUT_RDWR);

		urcu_qsbr_call_rcu(&conn->rcu, destroy_client);
	}
}

static void ring_init(struct server *s, struct connection *conn)
{
	struct shm_ring_dir_ent *ent;
	struct shm_ring_desc *desc;
	struct shm_ring_dir *dir;
	struct shm_ring *ring;
	struct client *c;

	BUG_ON(!conn->rx_cdesc);
	conn->client = calloc(1, sizeof(*c));
	if (!conn->client)
		fatal("FIXME\n");

	c = conn->client;
	c->ring_size = 1 << 24; // FIXME
	c->ring_fd = shm_open(conn->cdesc.name, O_RDWR | O_CREAT, 0644);
	if (c->ring_fd == -1)
		fatal("FIXME\n");

	if (ftruncate(c->ring_fd, 0))
		fatal("FIXME\n");

	if (ftruncate(c->ring_fd, c->ring_size))
		fatal("FIXME\n");

	c->ring_mmap = mmap(NULL, c->ring_size, PROT_READ | PROT_WRITE,
			    MAP_SHARED | MAP_POPULATE, c->ring_fd, 0);

	if (c->ring_mmap == MAP_FAILED)
		fatal("FIXME\n");

	ring = c->ring_mmap;
	desc = &ring->desc;
	c->ring_cur_offset = (uint64_t)0-1;
	c->ring_cur_frame = (uint32_t)0-1;
	pthread_mutex_init(&c->atom_lock, NULL);
	memcpy(desc->name, conn->cdesc.name, SDVR_NAMELEN);
	desc->pixelformat = conn->cdesc.pixelformat;
	desc->fps_numerator = conn->cdesc.fps_numerator;
	desc->fps_denominator = conn->cdesc.fps_denominator;
	desc->width = conn->cdesc.width;
	desc->height = conn->cdesc.height;
	desc->ring_size = c->ring_size - 4096;
	desc->tail_offset = 0;
	desc->ctr = 0;

	pthread_mutex_lock(&s->ring_dir_lock);
	dir = s->ring_dir_mmap;

	ent = &dir->ents[dir->desc.len++];
	memcpy(ent->shm_path, conn->cdesc.name, sizeof(ent->shm_path));
	ent->is_active = 1;
	asm volatile ("" ::: "memory"); // smp_wmb()
	dir->desc.gen++;
	futex(&dir->desc.gen, FUTEX_WAKE, INT_MAX, 0, 0, 0);
	pthread_mutex_unlock(&s->ring_dir_lock);
}

static struct connection *create_connection(struct server *s, bool is_stream)
{
	struct cds_lfht_node *ret;
	struct connection *conn;

	conn = calloc(1, sizeof(*conn));
	if (!conn)
		return NULL;

	// FIXME stupid
	if (is_stream)
		conn->stream_next = calloc(1, sizeof(struct rxpiece) +
					s->max_record_len);

	strcpy(conn->sdesc.name, s->server_name);
	conn->sdesc.max_record_len = s->max_record_len;
	conn->sdesc.max_dgram_payload = s->max_dgram_payload;
	conn->stream_sockfd = -1;

	/*
	 * The cookies aren't secret: an attacker can't compromise any data by
	 * working out a valid cookie, or even the cookie for a specific client.
	 * But, knowing a valid cookie allows the attacker to force us to waste
	 * cpu evaluating spoofed signatures, so it would be nice if they were
	 * hard to guess (statistically random). They still need to be unique.
	 *
	 * We can obtain both properties by applying an encryption algorithm to
	 * a simple counter. RC5 was choosen because it is relatively fast,
	 * patent free, and trivial to implement for a 32-bit block size.
	 *
	 * Hashing doesn't work, because we would have to deal with potential
	 * collisions. An encrypted counter guarantees collisions are impossible
	 * until the counter has wrapped, which at 100 connections/sec takes 1.5
	 * years.
	 */

again:
	conn->cookie = uatomic_add_return(&s->next_cookie, 1);
	conn->cookie = rc5_scramble(s->cookie_ctx, conn->cookie);

	/*
	 * There exists *exactly* one next_cookie value which yields 0x00000000,
	 * and *exactly* one which yields 0xffffffff. Those values are reserved
	 * for the initial key exchange, so just skip them.
	 */

	if (conn->cookie == SDVR_COOKIE_ZEROS ||
	    conn->cookie == SDVR_COOKIE_ONES)
		goto again;

	ret = cds_lfht_add_unique(s->connection_lfht, conn->cookie,
				  lfht_match_cookie, &conn->cookie,
				  &conn->lfht_node);

	if (ret != &conn->lfht_node) {
		warn("Skipping in-use cookie value %08x\n", conn->cookie);
		goto again;
	}

	return conn;
}

static void ring_zero(struct shm_ring *ring, uint64_t off, uint64_t len)
{
	uint64_t i;

	for (i = 0; i < len; off++, i++)
		ring->ring[off % ring->desc.ring_size] = 0;

	asm volatile ("" ::: "memory"); // smp_wmb()
}

static void ring_write(struct shm_ring *ring, const uint8_t *in,
		       uint64_t off, uint64_t len)
{
	uint64_t i;

	for (i = 0; i < len; off++, i++)
		ring->ring[off % ring->desc.ring_size] = in[i];

	asm volatile ("" ::: "memory"); // smp_wmb()
}

static void ring_read(uint8_t *out, const struct shm_ring *ring,
		      uint64_t off, uint64_t len)
{
	uint64_t i;

	asm volatile ("" ::: "memory"); // barrier()

	for (i = 0; i < len; off++, i++)
		out[i] = ring->ring[off % ring->desc.ring_size];
}

static void ring_append(struct connection *conn, uint32_t f_seq, uint32_t f_len,
			uint32_t f_off, const uint8_t *buf, int buf_len)
{
	struct shm_ring *ring = conn->client->ring_mmap;
	struct shm_ring_desc *d = &ring->desc;
	struct client *c = conn->client;
	struct shm_ring_head head;
	uint64_t frame_begin_off;

	pthread_mutex_lock(&c->atom_lock);

	BUG_ON(f_off + buf_len > f_len);
	BUG_ON(f_len > ring->desc.ring_size - sizeof(head));

	if (f_seq > c->ring_cur_frame || c->ring_cur_frame == UINT32_MAX) {
		uint64_t prev, new_head;

		prev = c->ring_cur_offset;
		if (c->ring_cur_offset == (uint64_t)0-1) {
			c->ring_cur_offset = 0;
		} else {
			ring_read((uint8_t *)&head, ring, c->ring_cur_offset,
				  sizeof(head));
			c->ring_cur_offset += sizeof(head) + head.frame_len;
		}

		new_head = c->ring_cur_offset;
		frame_begin_off = new_head + sizeof(head);
		c->ring_cur_frame = f_seq;

		while (frame_begin_off + f_len - d->tail_offset >= d->ring_size) {
			ring_read((uint8_t *)&head, ring, d->tail_offset,
				  sizeof(head));

			d->tail_offset += sizeof(head) + head.frame_len;
			asm volatile ("" ::: "memory"); // smp_wmb()
			BUG_ON(d->tail_offset > new_head);
		}

		memset(&head, 0, sizeof(head));
		head.offset_prev = prev;
		head.pts_mono_us = 0;
		head.frame_len = f_len;
		head.frame_seq = f_seq;
		head.ring_ctr = d->ctr + 1;
		head.written_len = buf ? buf_len : 0;
		ring_write(ring, (uint8_t *)&head, new_head, sizeof(head));
		ring_zero(ring, frame_begin_off, f_len);

		if (buf)
			ring_write(ring, buf, frame_begin_off + f_off, buf_len);

		d->ctr++;
		futex(&d->ctr, FUTEX_WAKE, INT_MAX, 0, 0, 0);

	} else {
		uint64_t n_off, off;

		BUG_ON(c->ring_cur_offset == (uint64_t)0-1);
		BUG_ON(buf == NULL);

		if (f_seq == c->ring_cur_frame) {
			ring_read((uint8_t *)&head, ring, c->ring_cur_offset,
				  sizeof(head));

			ring_write(ring, buf,
				   c->ring_cur_offset + sizeof(head) + f_off,
				   buf_len);

			head.written_len += buf_len;
			ring_write(ring, (uint8_t *)&head, c->ring_cur_offset,
				   sizeof(head));

			d->gen++;
			futex(&d->gen, FUTEX_WAKE, INT_MAX, 0, 0, 0);
			goto out;
		}

		n_off = c->ring_cur_offset;
		do {
			off = n_off;
			ring_read((uint8_t *)&head, ring, off, sizeof(head));
			n_off = head.offset_prev;

			if (n_off == (uint64_t)0-1)
				break;

		} while (f_seq != head.frame_seq && n_off >= d->tail_offset);

		if (f_seq != head.frame_seq)
			goto out;

		ring_write(ring, buf, off + sizeof(head) + f_off, buf_len);

		head.written_len += buf_len;
		ring_write(ring, (uint8_t *)&head, off, sizeof(head));

		d->gen++;
		futex(&d->gen, FUTEX_WAKE, INT_MAX, 0, 0, 0);
	}

out:
	pthread_mutex_unlock(&c->atom_lock);
}

static int send_server_desc(struct connection *c)
{
	uint8_t tmp[sizeof(c->sdesc) + SDVR_MACLEN];
	struct iovec iovec = {
		.iov_base = tmp,
		.iov_len = sizeof(tmp),
	};
	struct msghdr msghdr = {
		.msg_iov = &iovec,
		.msg_iovlen = 1,
	};

	BUG_ON(!c->key);

	encrypt_one(tmp, &c->sdesc, sizeof(c->sdesc), c->key);
	return sendmsg(c->stream_sockfd, &msghdr, MSG_DONTWAIT) != sizeof(tmp);
}

static int save_clientpk(const struct enckey *k, const char *name)
{
	char path[4096];

	snprintf(path, sizeof(path), "%s/.sdvr/%s.cpk", getenv("HOME"), name);
	return crypto_save_pk(k, path);
}

static const struct authpubkey *get_clientpk(const char *name)
{
	char path[4096];

	snprintf(path, sizeof(path), "%s/.sdvr/%s.cpk", getenv("HOME"), name);
	if (!access(path, R_OK))
		return crypto_open_pk(path);

	return NULL;
}

static int rxp_process_stream(struct server *s, struct connection *c,
			      struct rxpiece *rxp)
{
	int len = rxp->iovec.iov_len;
	uint8_t *buf;

	BUG_ON(len <= SDVR_MACLEN);

	buf = alloca(len - SDVR_MACLEN);
	if (decrypt_one(buf, rxp->buf, len - SDVR_MACLEN, c->key))
		return -1;

	if (!c->rx_cdesc) {
		const struct authpubkey *savedkey;

		BUG_ON(len != sizeof(c->cdesc) + SDVR_MACLEN);
		memcpy(&c->cdesc, buf, sizeof(c->cdesc));

		c->rx_cdesc = true;

		if (send_server_desc(c)) {
			warn("Can't send server desc: %m\n");
			return -1;
		}

		savedkey = get_clientpk(c->cdesc.name);
		if (!savedkey)
			if (save_clientpk(c->key, c->cdesc.name))
				warn("Can't save client key!\n");

		if (savedkey && pk_cmp(c->key, savedkey)) {
			warn("Client key changed!\n");
			return -1;
		}

		free((void *)savedkey);

		ring_init(s, c);
		rxp->record_len = sizeof(struct frame_desc) + SDVR_MACLEN;
		rxp->record_off = 0;
		return 0;
	}

	if (c->stream_cur_off == c->stream_cur_desc.length) {
		memcpy(&c->stream_cur_desc, buf,
		       sizeof(struct frame_desc));

		c->stream_cur_off = 0;
		ring_append(c, c->stream_cur_desc.sequence,
			    c->stream_cur_desc.length,
			    0, NULL, 0);

		rxp->record_off = 0;
		rxp->record_len = min(c->stream_cur_desc.chunk_size,
				      c->stream_cur_desc.length)
				      + SDVR_MACLEN;
		return 0;
	}

	ring_append(c, c->stream_cur_desc.sequence,
		    c->stream_cur_desc.length, c->stream_cur_off,
		    buf, len - SDVR_MACLEN);

	c->stream_cur_off += len - SDVR_MACLEN;
	rxp->record_off = 0;

	if (c->stream_cur_off == c->stream_cur_desc.length)
		rxp->record_len = sizeof(struct frame_desc) + SDVR_MACLEN;
	else
		rxp->record_len = min(c->stream_cur_desc.chunk_size,
				      c->stream_cur_desc.length -
				      c->stream_cur_off) + SDVR_MACLEN;

	return 0;
}

static int rxp_process_dgram(struct connection *c, struct rxpiece *rxp, int len)
{
	uint8_t *buf;

	int textlen = len - __builtin_offsetof(struct dgram, text);
	const struct dgram *d = (const void *)rxp->buf;
	const struct dgram_frame *r;

	BUG_ON(!c->rx_cdesc);
	BUG_ON(textlen < 4);

	buf = alloca(textlen);
	if (decrypt_one_nonce(buf, d->text_mac, textlen, c->key, d->nonce))
		return -1;

	r = (const void *)buf;
	ring_append(c, r->frame_sequence,
		    r->frame_length,
		    r->offset,
		    r->data, textlen - sizeof(struct dgram_frame));

	c->rx_vdata = true;
	return 0;
}

static int stream_kx_msg_1(struct server *s, int sockfd)
{
	struct iovec iovec = {
		.iov_base = (void *)__pk(authkeypair_apk(s->authkey)),
		.iov_len = SDVR_PKLEN,
	};
	struct msghdr msghdr = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_iov = &iovec,
		.msg_iovlen = 1,
	};

	// FIXME handle short writes
	return sendmsg(sockfd, &msghdr, MSG_DONTWAIT) != SDVR_PKLEN;
}

static int stream_kx_msg_3(int sockfd, const struct kx_msg_3 *tx)
{
	struct iovec iovec = {
		.iov_base = (void *)tx,
		.iov_len = sizeof(*tx),
	};
	struct msghdr msghdr = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_iov = &iovec,
		.msg_iovlen = 1,
	};

	// FIXME handle short writes
	return sendmsg(sockfd, &msghdr, MSG_DONTWAIT) != sizeof(*tx);
}

static int dgram_kx_msg_1(struct server *s, int sockfd, void *name, int namelen)
{
	uint32_t zeros = 0;
	struct iovec iovec[2] = {
		{
			.iov_base = &zeros,
			.iov_len = sizeof(zeros),
		},
		{
			.iov_base = (void *)__pk(authkeypair_apk(s->authkey)),
			.iov_len = SDVR_PKLEN,
		},
	};
	struct msghdr msghdr = {
		.msg_name = name,
		.msg_namelen = namelen,
		.msg_iov = iovec,
		.msg_iovlen = 2,
	};

	return sendmsg(sockfd, &msghdr, MSG_DONTWAIT) != SDVR_PKLEN + 4;
}

static int dgram_kx_msg_3(int sockfd, void *name, int namelen,
			 const struct kx_msg_3 *tx)
{
	uint32_t ones = 0-1;
	struct iovec iovec[2] = {
		{
			.iov_base = &ones,
			.iov_len = sizeof(ones),
		},
		{
			.iov_base = (void *)tx,
			.iov_len = sizeof(*tx),
		},
	};
	struct msghdr msghdr = {
		.msg_name = name,
		.msg_namelen = namelen,
		.msg_iov = iovec,
		.msg_iovlen = 2,
	};

	return sendmsg(sockfd, &msghdr, MSG_DONTWAIT) != sizeof(*tx) + 4;
}

static int dgram_ssetup(int sockfd, void *name, int namelen,
		       const struct server_setup_dgram *tx)
{
	struct iovec iovec = {
		.iov_base = (void *)tx,
		.iov_len = sizeof(*tx),
	};
	struct msghdr msghdr = {
		.msg_name = name,
		.msg_namelen = namelen,
		.msg_iov = &iovec,
		.msg_iovlen = 1,
	};

	return sendmsg(sockfd, &msghdr, MSG_DONTWAIT) != sizeof(*tx);
}

static int stream_do_kx(struct server *s, struct connection *c, int fd,
			struct rxpiece *rxp)
{
	struct kx_msg_2 *m2 = (struct kx_msg_2 *)rxp->buf;
	struct kx_msg_3 m3;
	struct enckey *k;

	k = kx_reply(m2, &m3, s->authkey, c->cookie);
	if (!k) {
		warn("Bad KX! c=%08" PRIx32 "\n", c->cookie);
		return -1;
	}

	c->key = k;
	stream_kx_msg_3(fd, &m3);

	rxp->record_off = 0;
	rxp->record_len = SDVR_MACLEN + sizeof(struct client_setup_desc);
	return 0;
}

static int do_one_recvmmsg(struct server *s, int fd, struct mmsghdr *mmsghdrs,
			   int mmsghdrs_len)
{
	int ret, i;

	urcu_qsbr_thread_offline();
	ret = recvmmsg(fd, mmsghdrs, mmsghdrs_len, MSG_WAITFORONE, NULL);
	urcu_qsbr_thread_online();

	if (ret <= 0) {
		if (errno == EINTR)
			return 0;

		return ret;
	}

	for (i = 0; i < ret; i++) {
		struct msghdr *msg_hdr = &mmsghdrs[i].msg_hdr;
		unsigned msg_len = mmsghdrs[i].msg_len;
		struct kx_msg_2 *kx_msg_2;
		struct rxpiece *rxp;
		struct connection *c;
		uint32_t cookie;

		if (msg_len < 4)
			continue;

		rxp = container_of(msg_hdr->msg_iov->iov_base,
				   struct rxpiece, buf);

		cookie = *(uint32_t *)rxp->buf;
		if (cookie == 0) {
			if (msg_len < SDVR_HELLOLEN)
				continue;

			dgram_kx_msg_1(s, fd, &rxp->src, sa_any_len(&rxp->src));
			continue;
		}

		if (cookie == UINT32_MAX) {
			struct connection *new;

			if (msg_len < sizeof(*kx_msg_2))
				continue;

			kx_msg_2 = (void *)rxp->buf + sizeof(uint32_t);

			if (kx_start_reply(kx_msg_2, s->authkey)) {
				warn("Bad KX!\n");
				continue;
			}

			// FIXME handle duplicate kx_msg_2

			new = create_connection(s, false);
			if (!new) {
				warn("No memory for new client!\n");
				continue;
			}

			new->key = kx_finish_reply(kx_msg_2, &new->kxmsg,
						   s->authkey, new->cookie);

			if (!new->key) {
				warn("No memory for new key!\n");
				stop_client(s, new);
				continue;
			}

			memcpy(&new->ssmsg.text.desc, &new->sdesc,
			       sizeof(new->sdesc));

			new->ssmsg.nonce = crypto_nonce_seq_tx(new->key);
			encrypt_one(new->ssmsg.text_mac, &new->ssmsg.text,
				    sizeof(new->ssmsg.text), new->key);

			dgram_kx_msg_3(fd, msg_hdr->msg_name,
				       msg_hdr->msg_namelen, &new->kxmsg);
			continue;
		}

		c = lookup_client(s, cookie);
		if (!c)
			continue;

		BUG_ON(!c->key);

		if (!c->rx_cdesc) {
			struct client_setup_dgram *m = (void *)rxp->buf;

			if (decrypt_one(&m->text, m->text_mac, sizeof(m->text),
					c->key)) {
				warn("Bad client desc?\n");
				continue;
			}

			// FIXME racy
			memcpy(&c->cdesc, &m->text.desc, sizeof(c->cdesc));
			c->rx_cdesc = true;
			ring_init(s, c);

			dgram_ssetup(fd, msg_hdr->msg_name,
				     msg_hdr->msg_namelen, &c->ssmsg);
			continue;
		}

		rxp_process_dgram(c, rxp, msg_len);
		urcu_qsbr_quiescent_state();

		msg_hdr->msg_iov->iov_len = s->max_dgram_payload;
		msg_hdr->msg_namelen = sizeof(struct sockaddr_any);
	}

	return 0;
}

static void *dgram_receive_thread(struct server *s, int dgram_fd)
{
	struct mmsghdr *mmsghdrs;
	int i;

	urcu_qsbr_register_thread();

	mmsghdrs = alloca(sizeof(*mmsghdrs) * s->dgram_mmsg_batch);
	for (i = 0; i < s->dgram_mmsg_batch; i++) {
		struct rxpiece *rxp;

		rxp = alloca(sizeof(*rxp) + s->max_dgram_payload);
		mmsghdrs[i] = (struct mmsghdr){
			.msg_hdr = {
				.msg_name = &rxp->src,
				.msg_namelen = sizeof(rxp->src),
				.msg_iov = &rxp->iovec,
				.msg_iovlen = 1,
			},
		};

		rxp->iovec.iov_len = s->max_dgram_payload;
		rxp->iovec.iov_base = rxp->buf;
	}

	while (!s->stop &&
	       !do_one_recvmmsg(s, dgram_fd, mmsghdrs, s->dgram_mmsg_batch));

	close(dgram_fd);
	urcu_qsbr_unregister_thread();
	return NULL;
}

static void *udp_receive_thread(void *arg)
{
	struct server *s = arg;
	return dgram_receive_thread(s, get_dgram_bind(&s->bindaddr));
}

static void *ethernet_receive_thread(void *arg)
{
	struct server *s = arg;
	struct sockaddr_any addr = {
		.ll = {
			.sll_family = AF_PACKET,
			.sll_protocol = htons(0x1337),
			.sll_pkttype = PACKET_HOST,
			.sll_ifindex = s->ifindex,
		},
	};

	return dgram_receive_thread(s, get_dgram_bind(&addr));
}

static void drain_client_stream(struct server *s, struct connection *c)
{
	while (1) {
		struct rxpiece *rxp = c->stream_next;
		int r;

		BUG_ON(rxp->record_len == 0);
		BUG_ON(rxp->record_len > s->max_record_len);
		BUG_ON(rxp->record_off >= rxp->record_len);

		r = recv(c->stream_sockfd, rxp->buf + rxp->record_off,
			 rxp->record_len - rxp->record_off, MSG_DONTWAIT);

		if (r <= 0) {
			// FIXME obvious starvation problem
			if (errno == EAGAIN)
				return;

			stop_client(s, c);
			return;
		}

		rxp->record_off += r;
		BUG_ON(rxp->record_off > rxp->record_len);

		if (rxp->record_off != rxp->record_len)
			continue;

		rxp->iovec.iov_len = rxp->record_len;

		if (!c->key) {
			if (stream_do_kx(s, c, c->stream_sockfd, rxp))
				stop_client(s, c);

			continue;
		}

		if (rxp_process_stream(s, c, rxp)) {
			stop_client(s, c);
			return;
		}
	}
}

static void accept_new_connections(struct server *s, int listen_fd)
{
	while (1) {
		struct sockaddr_any srcaddr;
		socklen_t addrlen = sizeof(srcaddr);
		struct epoll_event evt;
		struct connection *new;
		int newfd;

		newfd = accept4(listen_fd, (void *)&srcaddr,
				  &addrlen, SOCK_NONBLOCK);

		if (newfd == -1) {
			if (errno == EAGAIN)
				return;

			warn("Bad accept: %m\n");
			sleep_us(10);
			continue;
		}

		if (stream_kx_msg_1(s, newfd)) {
			warn("Can't write PK: %m\n");
			close(newfd);
			continue;
		}

		new = create_connection(s, true);
		if (!new) {
			warn("No memory for client\n");
			close(newfd);
			continue;
		}

		memcpy(&new->stream_srcaddr, &srcaddr, sa_any_len(&srcaddr));
		new->stream_sockfd = newfd;

		new->stream_next->record_len = sizeof(struct kx_msg_2);
		new->stream_next->record_off = 0;

		evt.data.u32 = new->cookie;
		evt.events = EPOLLIN | EPOLLRDHUP | EPOLLET;
		if (epoll_ctl(s->stream_epoll_fd, EPOLL_CTL_ADD, newfd, &evt)) {
			warn("Bad epoll_ctl: %m\n");
			stop_client(s, new);
		}
	}
}

static void *stream_receive_thread(void *arg)
{
	struct epoll_event *evts, evt;
	struct server *s = arg;
	int listen_fd;

	urcu_qsbr_register_thread();

	listen_fd = get_stream_listen(&s->bindaddr);
	if (listen_fd == -1)
		fatal("Can't listen: %m\n");

	if (fcntl(listen_fd, F_SETFL, O_NONBLOCK))
		fatal("Can't set NONBLOCK on listen socket: %m\n");

	evt.data.u32 = ACCEPT_COOKIE_MAGIC;
	evt.events = EPOLLIN | EPOLLET;
	if (epoll_ctl(s->stream_epoll_fd, EPOLL_CTL_ADD, listen_fd, &evt))
		fatal("Can't EPOLL_CTL_ADD listen socket: %m\n");

	evts = alloca(s->epoll_event_batch * sizeof(*evts));
	while (!s->stop) {
		int r, i;

		urcu_qsbr_thread_offline();
		r = epoll_wait(s->stream_epoll_fd, evts,
			       s->epoll_event_batch, -1);
		urcu_qsbr_thread_online();

		if (r <= 0) {
			if (errno == EINTR)
				continue;

			warn("Bad epoll: %m\n");
			break;
		}

		for (i = 0; i < r; i++) {
			uint32_t cookie = evts[i].data.u32;
			uint32_t events = evts[i].events;
			struct connection *c;

			if (cookie == ACCEPT_COOKIE_MAGIC) {
				accept_new_connections(s, listen_fd);
				continue;
			}

			if (events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
				c = lookup_client(s, cookie);
				if (!c)
					continue;

				stop_client(s, c);
				continue;
			}

			c = lookup_client(s, cookie);
			if (!c)
				continue;

			drain_client_stream(s, c);
			urcu_qsbr_quiescent_state();
		}
	}

	close(listen_fd);
	urcu_qsbr_unregister_thread();
	return NULL;
}

static const struct authkeypair *get_selfkeys(void)
{
	const struct authkeypair *new;
	char *tmp, path[4096];

	snprintf(path, sizeof(path), "%s/.sdvr/sdvrdkey", getenv("HOME"));
	if (!access(path, R_OK))
		return crypto_open_key(path);

	log("No key found, making new one...\n");

	tmp = rindex(path, '/');
	*tmp = '\0';
	if (access(path, F_OK))
		if (mkdir(path, 0700))
			fprintf(stderr, "Can't mkdir ~/.sdvr!\n");
	*tmp = '/';

	new = crypto_open_key(NULL);
	if (crypto_save_key(new, path))
		fprintf(stderr, "Unable to save key!\n");

	return new;
}

static void interrupter(int nr)
{
	(void)nr;
}

static const struct sigaction intsig = {
	.sa_handler = interrupter,
	.sa_flags = SA_NODEFER,
};

static const struct sigaction ignoresig = {
	.sa_handler = SIG_IGN,
};

static void parse_args(int argc, char **argv, struct server *s)
{
	static const struct option opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "listen-address", required_argument, NULL, 'l' },
		{ "raw-interface", required_argument, NULL, 'i' },
		{},
	};

	while (1) {
		int i = getopt_long(argc, argv, "hl:i:", opts, NULL);
		char v4[strlen("::ffff:XXX.XXX.XXX.XXX") + 1];

		switch (i) {
		case -1:
			return;
		case 'l':
			if (inet_pton(AF_INET6, optarg, &s->bindaddr.in6.sin6_addr) == 1)
				break;

			snprintf(v4, sizeof(v4), "::ffff:%s", optarg);
			if (inet_pton(AF_INET6, v4, &s->bindaddr.in6.sin6_addr) == 1)
				break;

			fatal("Bad dstaddr '%s'\n", optarg);
		case 'i':
			s->ifindex = find_ifindex(optarg);

			if (s->ifindex == -1)
				fatal("No such interface '%s'", optarg);

			break;
		case 'h':
			puts("Usage: ./sdvrd [-l listen_address] [-i listen_interface]");
			puts("");
			puts("\t-l: Specify IPv4/IPv6 listen address");
			puts("\t-i: Specify interface for raw ethernet frames");
			puts("");
			exit(0);
		default:
			exit(1);
		}
	}
}

int main(int argc, char **argv)
{
	struct server s;
	int i, nr_threads;
	sigset_t set;

	urcu_qsbr_register_thread();
	sigaction(SIGPIPE, &ignoresig, NULL);
	sigaction(SIGTERM, &intsig, NULL);
	sigaction(SIGINT, &intsig, NULL);

	memset(&s, 0, sizeof(s));
	s.bindaddr.in6.sin6_family = AF_INET6;
	s.bindaddr.in6.sin6_addr = in6addr_any;
	s.bindaddr.in6.sin6_port = htons(1337);
	s.ifindex = -1;
	parse_args(argc, argv, &s);

	s.stream_epoll_fd = epoll_create(1);
	if (s.stream_epoll_fd == -1)
		fatal("Can't make epoll instance: %m\n");

	s.connection_lfht = cds_lfht_new_flavor(64, 64, 0, CDS_LFHT_AUTO_RESIZE,
					    &urcu_qsbr_flavor, NULL);
	if (!s.connection_lfht)
		fatal("Can't make cookie rculfhash\n");

	if (gethostname(s.server_name, sizeof(s.server_name))) {
		warn("Can't get hostname... using 'sdvr'\n");
		strcpy(s.server_name, "sdvr");
	}

	s.authkey = get_selfkeys();
	s.max_record_len = 4096;
	s.max_dgram_payload = 1024;
	s.dgram_mmsg_batch = 64;
	s.epoll_event_batch = 8;
	s.listen_backlog = 1024;

	BUG_ON(!(s.cookie_ctx = rc5_init()));
	BUG_ON(getrandom(&s.next_cookie, sizeof(s.next_cookie), 0)
	       != sizeof(s.next_cookie));

	s.ring_dir_fd = shm_open(SDVR_SHM_DIR_NAME, O_RDWR | O_CREAT, 0644);
	if (s.ring_dir_fd == -1)
		fatal("Can't open shm_ring_dir: %m\n");

	if (ftruncate(s.ring_dir_fd, 0))
		fatal("Can't truncate shm_ring_dir: %m\n");

	if (ftruncate(s.ring_dir_fd, 32768))
		fatal("Can't truncate shm_ring_dir: %m\n");

	s.ring_dir_mmap = mmap(NULL, 32768, PROT_READ | PROT_WRITE, MAP_SHARED,
			       s.ring_dir_fd, 0);

	if (s.ring_dir_mmap == MAP_FAILED)
		fatal("Can't map shm_ring_dir: %m\n");

	pthread_mutex_init(&s.ring_dir_lock, NULL);

	nr_threads = 1; //sysconf(_SC_NPROCESSORS_ONLN);
	if (nr_threads == -1) {
		warn("Can't get NPROCESSORS, assuming uniprocessor\n");
		nr_threads = 1;
	}


	s.stream_rx_threads = calloc(nr_threads, sizeof(pthread_t));
	s.nr_stream_rx_threads = nr_threads;

	s.udp_rx_threads = calloc(nr_threads, sizeof(pthread_t));
	s.nr_udp_rx_threads = nr_threads;

	if (s.ifindex != -1) {
		s.ethernet_rx_threads = calloc(nr_threads, sizeof(pthread_t));
		s.nr_ethernet_rx_threads = nr_threads;
	}

	for (i = 0; i < nr_threads; i++) {
		if (pthread_create(&s.stream_rx_threads[i], NULL,
				   stream_receive_thread, &s))
			fatal("Can't make stream thread\n");

		if (pthread_create(&s.udp_rx_threads[i], NULL,
				   udp_receive_thread, &s))
			fatal("Can't make stream thread\n");

		if (s.ifindex != -1)
			if (pthread_create(&s.ethernet_rx_threads[i], NULL,
					   ethernet_receive_thread, &s))
				fatal("Can't make stream thread\n");
	}

	urcu_qsbr_thread_offline();
	sigemptyset(&set);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGINT);
	sigwait(&set, &i);
	urcu_qsbr_thread_online();

	/*
	 * If nothing is happening, the rx_threads will sit in their blocking
	 * epoll_wait/recvmmsg calls and never see the stop flag. Signaling each
	 * thread causes its blocking call to fail with -EINTR, so the stop flag
	 * is observed and the thread exits.
	 */
	log("Stopping daemon\n");
	s.stop = 1;

	for (i = 0; i < s.nr_stream_rx_threads; i++) {
		pthread_kill(s.stream_rx_threads[i], SIGTERM);
		pthread_join(s.stream_rx_threads[i], NULL);
	}
	free(s.stream_rx_threads);
	close(s.stream_epoll_fd);

	for (i = 0; i < s.nr_udp_rx_threads; i++) {
		pthread_kill(s.udp_rx_threads[i], SIGTERM);
		pthread_join(s.udp_rx_threads[i], NULL);
	}
	free(s.udp_rx_threads);

	for (i = 0; s.ifindex != -1 && i < s.nr_ethernet_rx_threads; i++) {
		pthread_kill(s.ethernet_rx_threads[i], SIGTERM);
		pthread_join(s.ethernet_rx_threads[i], NULL);
	}
	free(s.ethernet_rx_threads);
	//FIXME walk connection_lfht
	cds_lfht_destroy(s.connection_lfht, NULL);
	munmap(s.ring_dir_mmap, 32768);
	ftruncate(s.ring_dir_fd, 0);
	close(s.ring_dir_fd);
	free((void *)s.cookie_ctx);
	free((void *)s.authkey);
	urcu_qsbr_unregister_thread();
	return 0;
}

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
#include <sys/timerfd.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <arpa/inet.h>
#include <linux/futex.h>
#include <linux/videodev2.h>

#define futex(...) syscall(SYS_futex, __VA_ARGS__)

static inline void sleep_us(int64_t us)
{
	const struct timespec t = {
		.tv_sec = us / 1000000,
		.tv_nsec = us % 1000000 * 1000,
	};

	if (clock_nanosleep(CLOCK_MONOTONIC, 0, &t, NULL))
		err("Bad nanosleep: %m\n");
}

static int new_tfd(int64_t interval_us)
{
	const struct itimerspec t = {
		.it_interval = {
			.tv_sec = interval_us / 1000000,
			.tv_nsec = interval_us % 1000000 * 1000,
		},
		.it_value = {
			.tv_sec = interval_us / 1000000,
			.tv_nsec = interval_us % 1000000 * 1000,
		},
	};
	int fd;

	fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
	if (fd == -1)
		return -1;

	if (timerfd_settime(fd, 0, &t, NULL)) {
		close(fd);
		return -1;
	}

	return fd;
}

#define ACCEPT_COOKIE_MAGIC	((uint32_t)0)

struct rxpiece {
	struct sockaddr_any src;
	struct iovec iovec;

	unsigned record_len;
	unsigned record_off;

	uint8_t buf[];
};

struct client {
	uint32_t cookie;

	int stream_sockfd;
	struct sockaddr_any stream_srcaddr;
	struct frame_desc stream_cur_desc;
	struct rxpiece *stream_next;
	unsigned stream_cur_off;

	struct kx_msg_3 kxmsg;
	struct server_setup_dgram ssmsg;
	struct sockaddr_any lastsrc;
	struct server_setup_desc sdesc;
	struct client_setup_desc cdesc;
	struct enckey *key;
	bool rx_cdesc;
	bool rx_vdata;

	pthread_mutex_t atom_lock;
	struct client *list_next;

	int ring_fd;
	void *ring_mmap;
	uint64_t ring_size;
	uint64_t ring_cur_offset;
	uint32_t ring_cur_frame;
};

static uint32_t tombstone_constant_u32 = UINT32_MAX;
static void *const tombstone_constant = &tombstone_constant_u32;
static_assert(__builtin_offsetof(struct client, cookie) == 0);
static_assert(SDVR_NAMELEN > HOST_NAME_MAX + 1);

struct server {
	struct sockaddr_any bindaddr;
	int ifindex;
	char server_name[SDVR_NAMELEN];
	int stream_listen_fd;
	int stream_epoll_fd;
	int stop;

	pthread_rwlock_t cookie_lookup_rwlock;
	struct client **cookie_htable;
	int cookie_htable_size;
	int cookie_htable_load;
	uint32_t next_cookie;

	pthread_mutex_t new_list_lock;
	struct client *new_list;

	// FIXME: Implement destruction
	pthread_mutex_t destroy_list_lock;
	struct client *destroy_list;

	pthread_t *stream_rx_threads;
	int nr_stream_rx_threads;
	pthread_t *dgram_rx_threads;
	int nr_dgram_rx_threads;
	pthread_t timer_thread;

	const struct authkeypair *authkey;
	int64_t timer_interval_us;
	unsigned max_record_len;
	int dgram_mmsg_batch;
	int epoll_event_batch;
	int listen_backlog;

	pthread_mutex_t ring_dir_lock;
	void *ring_dir_mmap;
	int ring_dir_fd;
};

static struct client **__lookup_client(struct client **table, int table_size,
				       uint32_t cookie)
{
	struct client **c;
	int i;

	i = cookie % table_size;
	while ((c = &table[i]) && *c && (*c)->cookie != cookie)
		i = (i + 1) % table_size;

	return c;
}

// FIXME: Actually handle resizing
#if 0
static void resize_cookie_htable(struct server *s, int new_size)
{
	struct client **new, **old;
	int i, new_load;

	new = calloc(new_size, sizeof(*new));
	if (!new)
		fatal("No memory to expand hashtable\n");

	pthread_rwlock_wrlock(&s->cookie_lookup_rwlock);

	new_load = 0;
	for (i = 0; i < s->cookie_htable_size; i++) {
		struct client **p;

		if (!s->cookie_htable[i])
			continue;

		if (s->cookie_htable[i] == tombstone_constant)
			continue;

		new_load++;
		p = __lookup_client(new, new_size, s->cookie_htable[i]->cookie);
		BUG_ON(*p != NULL);

		*p = s->cookie_htable[i];
	}

	old = s->cookie_htable;
	s->cookie_htable = new;
	s->cookie_htable_size = new_size;
	s->cookie_htable_load = new_load;

	pthread_rwlock_unlock(&s->cookie_lookup_rwlock);

	free(old);
}
#endif

static struct client *lookup_client(struct server *s, uint32_t cookie)
{
	struct client *c;

	pthread_rwlock_rdlock(&s->cookie_lookup_rwlock);
	c = *__lookup_client(s->cookie_htable, s->cookie_htable_size, cookie);
	pthread_rwlock_unlock(&s->cookie_lookup_rwlock);

	return c;
}

static int stop_client(struct server *s, struct client *c)
{
	struct client **p;
	int ret = 0;

	pthread_rwlock_wrlock(&s->cookie_lookup_rwlock);

	p = __lookup_client(s->cookie_htable, s->cookie_htable_size, c->cookie);
	if (*p) {
		*p = tombstone_constant;
		ret = 1;
	}

	pthread_rwlock_unlock(&s->cookie_lookup_rwlock);

	return ret;
}

static void ring_init(struct server *s, struct client *c)
{
	struct shm_ring_dir_ent *ent;
	struct shm_ring_desc *desc;
	struct shm_ring_dir *dir;
	struct shm_ring *ring;

	BUG_ON(!c->rx_cdesc);

	c->ring_size = 1 << 24; // FIXME
	c->ring_fd = shm_open(c->cdesc.name, O_RDWR | O_CREAT, 0644);
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
	memcpy(desc->name, c->cdesc.name, SDVR_NAMELEN);
	desc->pixelformat = c->cdesc.pixelformat;
	desc->fps_numerator = c->cdesc.fps_numerator;
	desc->fps_denominator = c->cdesc.fps_denominator;
	desc->width = c->cdesc.width;
	desc->height = c->cdesc.height;
	desc->ring_size = c->ring_size - 4096;
	desc->tail_offset = 0;
	desc->ctr = 0;

	pthread_mutex_lock(&s->ring_dir_lock);
	dir = s->ring_dir_mmap;

	ent = &dir->ents[dir->desc.len++];
	memcpy(ent->shm_path, c->cdesc.name, sizeof(ent->shm_path));
	ent->is_active = 1;
	asm volatile ("" ::: "memory"); // smp_wmb()
	dir->desc.gen++;
	futex(&dir->desc.gen, FUTEX_WAKE, INT_MAX, 0, 0, 0);
	pthread_mutex_unlock(&s->ring_dir_lock);
}

static struct client *create_client(struct server *s, bool is_stream)
{
	struct client *c, **p;

	c = calloc(1, sizeof(*c));
	if (!c)
		return NULL;

	// FIXME stupid
	if (is_stream)
		c->stream_next = calloc(1, sizeof(struct rxpiece) +
					s->max_record_len);

	pthread_mutex_init(&c->atom_lock, NULL);
	strcpy(c->sdesc.name, s->server_name);

	pthread_rwlock_wrlock(&s->cookie_lookup_rwlock);
	s->cookie_htable_load++;
	c->cookie = s->next_cookie++;
	p = __lookup_client(s->cookie_htable, s->cookie_htable_size, c->cookie);
	BUG_ON(*p != NULL);
	*p = c;
	pthread_rwlock_unlock(&s->cookie_lookup_rwlock);

	return c;
}

static void destroy_client(struct server *s, struct client *c)
{
	(void)*s;
	(void)*c;
	// FIXME
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

static void ring_append(struct client *c, uint32_t f_seq, uint32_t f_len,
			uint32_t f_off, const uint8_t *buf, int buf_len)
{
	struct shm_ring *ring = c->ring_mmap;
	struct shm_ring_desc *d = &ring->desc;
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

static int send_server_desc(struct client *c)
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

	encrypt_one(tmp, (uint8_t *)&c->sdesc, sizeof(c->sdesc), c->key);
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

static int rxp_process_stream(struct server *s, struct client *c,
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

		if (send_server_desc(c))
			fatal("Can't send server desc: %m\n");

		savedkey = get_clientpk(c->cdesc.name);
		if (!savedkey)
			if (save_clientpk(c->key, c->cdesc.name))
				fprintf(stderr, "Can't save client key!\n");

		if (savedkey && pk_cmp(c->key, savedkey))
			fatal("Client key changed!\n");

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

static int rxp_process_dgram(struct client *c, struct rxpiece *rxp)
{
	int len = rxp->iovec.iov_len;
	uint8_t *buf;

	int textlen = len - __builtin_offsetof(struct dgram, text);
	const struct dgram *d = (const void *)rxp->buf;
	const struct dgram_frame *r;

	BUG_ON(!c->rx_cdesc);
	BUG_ON(textlen < 4);

	buf = alloca(textlen);
	if (decrypt_one_nonce(buf, (const void *)d->text_mac, textlen,
			      c->key, d->nonce))
		return -1;

	r = (const void *)buf;
	ring_append(c, r->frame_sequence,
		    r->frame_length,
		    r->offset,
		    r->data, textlen - sizeof(struct dgram_frame));

	c->rx_vdata = true;
	return 0;
}

static int send_kx_msg_1(struct server *s, int sockfd, void *name, int namelen)
{
	struct iovec iovec = {
		.iov_base = (void *)__pk(authkeypair_apk(s->authkey)),
		.iov_len = SDVR_PKLEN,
	};
	struct msghdr msghdr = {
		.msg_name = name,
		.msg_namelen = namelen,
		.msg_iov = &iovec,
		.msg_iovlen = 1,
	};

	return sendmsg(sockfd, &msghdr, MSG_DONTWAIT) != SDVR_PKLEN;
}

static int send_kx_msg_3(int sockfd, void *name, int namelen,
			 const struct kx_msg_3 *tx)
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

static void do_kx(struct server *s, struct client *c, int fd,
		  struct rxpiece *rxp)
{
	struct kx_msg_2 *m2 = (struct kx_msg_2 *)rxp->buf;
	struct kx_msg_3 m3;
	struct enckey *k;

	k = kx_reply(m2, &m3, s->authkey, c->cookie);
	if (!k)
		fatal("Bad KX!\n");

	c->key = k;

	send_kx_msg_3(fd, NULL, 0, &m3);

	rxp->record_off = 0;
	rxp->record_len = SDVR_MACLEN + sizeof(struct client_setup_desc);
}

static void *dgram_receive_thread(struct server *s, int dgram_fd)
{
	struct mmsghdr *mmsghdrs;
	int i;

	mmsghdrs = alloca(sizeof(*mmsghdrs) * s->dgram_mmsg_batch);

	for (i = 0; i < s->dgram_mmsg_batch; i++) {
		struct rxpiece *rxp = alloca(sizeof(*rxp) + s->max_record_len);

		mmsghdrs[i] = (struct mmsghdr){
			.msg_hdr = {
				.msg_name = &rxp->src,
				.msg_namelen = sizeof(rxp->src),
				.msg_iov = &rxp->iovec,
				.msg_iovlen = 1,
			},
		};

		rxp->iovec.iov_len = s->max_record_len;
		rxp->iovec.iov_base = rxp->buf;
	}

	while (!s->stop) {
		int r = recvmmsg(dgram_fd, mmsghdrs, s->dgram_mmsg_batch,
				 MSG_WAITFORONE, NULL);

		if (r <= 0) {
			err("Bad recvmmsg: %m\n");
			continue;
		}

		for (i = 0; i < r; i++) {
			uint32_t cookie;
			struct kx_msg_2 *kx_msg_2;
			struct rxpiece *rxp;
			struct client *c;

			if (mmsghdrs[i].msg_hdr.msg_iov->iov_len < 4)
				continue;

			cookie =
			  *(uint32_t *)mmsghdrs[i].msg_hdr.msg_iov->iov_base;

			rxp = container_of(mmsghdrs[i].msg_hdr.msg_iov->iov_base,
					   struct rxpiece, buf);

			if (cookie == 0) {
				if (mmsghdrs[i].msg_hdr.msg_iov->iov_len
				    < SDVR_HELLOLEN)
					continue;

				dgram_kx_msg_1(s, dgram_fd, &rxp->src,
					      sa_any_len(&rxp->src));
				continue;

			}

			if (cookie == UINT32_MAX) {
				struct client *new;

				if (mmsghdrs[i].msg_hdr.msg_iov->iov_len - 4
				    < sizeof(*kx_msg_2))
					continue;

				kx_msg_2 = mmsghdrs[i].msg_hdr.msg_iov->iov_base
					   + sizeof(uint32_t);

				if (kx_start_reply(kx_msg_2, s->authkey)) {
					err("Bad KX!\n");
					continue;
				}

				// FIXME handle duplicate kx_msg_2

				new = create_client(s, false);
				if (!new) {
					err("No memory for new client!\n");
					continue;
				}

				new->key = kx_finish_reply(kx_msg_2,
							   &new->kxmsg,
							   s->authkey,
							   new->cookie);
				if (!new->key) {
					err("No memory for new key!\n");
					destroy_client(s, new);
					continue;
				}

				memcpy(&new->ssmsg.text.desc, &new->sdesc,
				       sizeof(new->sdesc));

				new->ssmsg.nonce = crypto_nonce_seq_tx(new->key);
				encrypt_one(new->ssmsg.text_mac,
					    (void *)&new->ssmsg.text,
					    sizeof(new->ssmsg.text), new->key);

				pthread_mutex_lock(&s->new_list_lock);
				new->list_next = s->new_list;
				s->new_list = new;
				pthread_mutex_unlock(&s->new_list_lock);

				dgram_kx_msg_3(dgram_fd,
					      mmsghdrs[i].msg_hdr.msg_name,
					      mmsghdrs[i].msg_hdr.msg_namelen,
					      &new->kxmsg);

				continue;
			}

			c = lookup_client(s, cookie);
			if (!c)
				continue;

			BUG_ON(!c->key);

			if (!c->rx_cdesc) {
				struct client_setup_dgram *m =
					mmsghdrs[i].msg_hdr.msg_iov->iov_base;

				if (decrypt_one((void *)&m->text, m->text_mac, sizeof(m->text), c->key)) {
					err("Bad client desc?\n");
					continue;
				}

				pthread_mutex_lock(&c->atom_lock);

				if (!c->rx_cdesc) {
					memcpy(&c->cdesc, &m->text.desc,
					       sizeof(c->cdesc));
					c->rx_cdesc = true;
					ring_init(s, c);
				}

				pthread_mutex_unlock(&c->atom_lock);

				dgram_ssetup(dgram_fd,
					    mmsghdrs[i].msg_hdr.msg_name,
					    mmsghdrs[i].msg_hdr.msg_namelen,
					    &c->ssmsg);

				continue;
			}

			rxp->iovec.iov_len = mmsghdrs[i].msg_len;
			rxp_process_dgram(c, rxp);
		}

		for (i = 0; i < r; i++) {
			mmsghdrs[i].msg_hdr.msg_iov->iov_len = s->max_record_len;
			mmsghdrs[i].msg_hdr.msg_namelen =
				sizeof(struct sockaddr_any);
		}
	}

	close(dgram_fd);
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

static void drain_client_stream(struct server *s, struct client *c)
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
			do_kx(s, c, c->stream_sockfd, rxp);
			continue;
		}

		if (rxp_process_stream(s, c, rxp)) {
			stop_client(s, c);
			return;
		}
	}
}

static void run_timers(struct server *s)
{
	(void)*s;
	return;
}

static void accept_new_connections(struct server *s, int listen_fd)
{
	while (1) {
		struct sockaddr_any srcaddr;
		socklen_t addrlen = sizeof(srcaddr);
		struct epoll_event evt;
		struct client *new;
		int newsock;

		newsock = accept4(listen_fd, (void *)&srcaddr,
				  &addrlen, SOCK_NONBLOCK);

		if (newsock == -1) {
			if (errno == EAGAIN)
				return;

			err("Bad accept: %m\n");
			sleep_us(10);
			continue;
		}

		if (send_kx_msg_1(s, newsock, NULL, 0)) {
			err("Can't write PK: %m\n");
			close(newsock);
			continue;
		}

		new = create_client(s, true);
		if (!new) {
			err("No memory for client\n");
			close(newsock);
			continue;
		}

		memcpy(&new->stream_srcaddr, &srcaddr, sa_any_len(&srcaddr));
		new->stream_sockfd = newsock;

		new->stream_next->record_len = sizeof(struct kx_msg_2);
		new->stream_next->record_off = 0;

		evt.data.u32 = new->cookie;
		evt.events = EPOLLIN | EPOLLRDHUP | EPOLLET;
		if (epoll_ctl(s->stream_epoll_fd, EPOLL_CTL_ADD, newsock, &evt))
			fatal("Bad epoll_ctl: %m\n");
	}
}

static void *stream_receive_thread(void *arg)
{
	struct epoll_event *evts, evt;
	struct server *s = arg;
	int listen_fd;

	listen_fd = get_stream_listen(&s->bindaddr);
	if (listen_fd == -1)
		fatal("Can't listen: %m\n");

	if (fcntl(listen_fd, F_SETFL, O_NONBLOCK))
		fatal("Can't set NONBLOCK on listen socket: %m\n");

	evt.data.u32 = ACCEPT_COOKIE_MAGIC;
	evt.events = EPOLLIN | EPOLLET;
	if (epoll_ctl(s->stream_epoll_fd, EPOLL_CTL_ADD, listen_fd, &evt))
		fatal("Bad epoll_ctl: %m\n");

	evts = alloca(s->epoll_event_batch * sizeof(*evts));
	while (!s->stop) {
		int r, i;

		r = epoll_wait(s->stream_epoll_fd, evts,
			       s->epoll_event_batch, -1);

		if (r <= 0) {
			err("Bad epoll: %m\n");
			continue;
		}

		for (i = 0; i < r; i++) {
			uint32_t cookie = evts[i].data.u32;
			uint32_t events = evts[i].events;
			struct client *c;

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
		}
	}

	close(listen_fd);
	return NULL;
}

static void *timer_thread(void *arg)
{
	struct server *s = arg;
	struct pollfd p;
	int timer_fd;

	timer_fd = new_tfd(s->timer_interval_us);
	if (timer_fd == -1)
		fatal("Can't make timerfd: %m\n");

	while (!s->stop) {
		uint64_t ticks;

		p.events = POLLIN;
		p.fd = timer_fd;

		if (poll(&p, 1, -1) != 1)
			fatal("Bad poll in timer thread: %m\n");

		run_timers(s);

		if (read(timer_fd, &ticks, 8) != 8)
			fatal("Unable to read ticks: %m\n");

		if (ticks != 1)
			err("Lost %" PRIu64 " ticks!\n", ticks - 1);
	}

	close(timer_fd);
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

static void stopper(int nr)
{
	fatal("Stopping: %d\n", nr);
}

static const struct sigaction stopsig = {
	.sa_flags = SA_RESETHAND,
	.sa_handler = stopper,
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

	sigaction(SIGPIPE, &ignoresig, NULL);
	sigaction(SIGTERM, &stopsig, NULL);
	sigaction(SIGINT, &stopsig, NULL);

	memset(&s, 0, sizeof(s));
	s.bindaddr.in6.sin6_family = AF_INET6;
	s.bindaddr.in6.sin6_addr = in6addr_any;
	s.bindaddr.in6.sin6_port = htons(1337);
	s.ifindex = -1;
	parse_args(argc, argv, &s);

	s.stream_epoll_fd = epoll_create(1);
	if (s.stream_epoll_fd == -1)
		fatal("Can't make epoll instance: %m\n");

	s.cookie_htable_size = 1024;
	s.cookie_htable = calloc(sizeof(struct client *), 1024);
	if (!s.cookie_htable)
		fatal("Can't allocate cookie htable\n");

	if (gethostname(s.server_name, sizeof(s.server_name))) {
		err("Can't get hostname... using 'sdvr'\n");
		strcpy(s.server_name, "sdvr");
	}

	s.authkey = get_selfkeys();
	s.timer_interval_us = 60000000L;
	s.max_record_len = 4096;
	s.dgram_mmsg_batch = 64;
	s.epoll_event_batch = 8;
	s.listen_backlog = 1024;
	s.next_cookie = 1;

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

	if (pthread_create(&s.timer_thread, NULL, timer_thread, &s))
		fatal("Can't create dgram thread\n");

	s.stream_rx_threads = calloc(1, sizeof(pthread_t));
	s.nr_stream_rx_threads = 1;

	if (pthread_create(&s.stream_rx_threads[0], NULL,
			   stream_receive_thread, &s))
		fatal("Can't create stream thread\n");

	s.dgram_rx_threads = calloc(2, sizeof(pthread_t));
	s.nr_dgram_rx_threads = 2;

	if (pthread_create(&s.dgram_rx_threads[0], NULL,
			   udp_receive_thread, &s))
		fatal("Can't create udp thread\n");

	if (s.ifindex != -1)
		if (pthread_create(&s.dgram_rx_threads[1], NULL,
				   ethernet_receive_thread, &s))
			fatal("Can't create ethernet thread\n");

	while (1)
		sleep(INT_MAX);
}

#if 0
static inline int64_t mono_us(void)
{
	struct timespec t;

	while (clock_gettime(CLOCK_MONOTONIC, &t))
		log("Bad clock_gettime: %m\n");

	return (int64_t)t.tv_nsec / 1000 + (int64_t)t.tv_sec * 1000000;
}

#endif

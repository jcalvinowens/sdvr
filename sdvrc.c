/*
 * sdvrc.c: V4L2 client for sdvrd
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
#include "proto.h"
#include "crypto.h"
#include "v4l2.h"
#include "inet.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include <signal.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <linux/videodev2.h>

static int fps;
static int width;
static int height;
static char fmt[5] = "    ";
static unsigned frame_step = 1;
static const char *device_path = "/dev/video0";
static const char *key_dir;
static sig_atomic_t stop;
static int use_udp;

static struct sockaddr_any dstaddr = {
	.in6 = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_LOOPBACK_INIT,
		.sin6_port = __builtin_bswap16(1337),
	},
};

static inline int64_t realoff_us(void)
{
	return 0; // FIXME
}

static inline int64_t mono_us(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (int64_t)t.tv_nsec / 1000L + (int64_t)t.tv_sec * 1000000L;
}

static void run_dgram_tx(struct v4l2_dev *dev, struct enckey *k, int fd,
			 uint32_t cookie)
{
	const struct v4l2_buffer *buf;
	const uint32_t chunk = 1024;
	uint64_t ctr = 0;
	uint8_t *tmp;

	tmp = alloca(chunk + __builtin_offsetof(struct dgram, text.data) + 4);

	while (!stop && (buf = v4l2_get_buffer(dev))) {
		struct dgram *d = (struct dgram *)tmp;
		uint32_t off;

		if (ctr++ % frame_step) {
			v4l2_put_buffer(dev, buf);
			continue;
		}

		for (off = 0; off < buf->bytesused; off += chunk) {
			uint32_t clen = min(chunk, buf->bytesused - off);

			d->text.frame_pts_mono_us =
				v4l2_timeval_to_ns(&buf->timestamp) / 1000L;
			d->text.frame_sequence = buf->sequence;
			d->text.frame_length = buf->bytesused;
			d->text.offset = off;

			memcpy(d->text.data,
			       v4l2_buf_mmap(dev, buf->index) + off, clen);

			clen += __builtin_offsetof(struct dgram, text.data);

			d->nonce = crypto_nonce_seq_tx(k);
			encrypt_one(d->text_mac, (const uint8_t *)&d->text,
				    sizeof(d->text) + chunk, k);

			d->cookie = cookie;

			if (write(fd, tmp, clen) != clen)
				fatal("Bad write: %m\n");
		}

		v4l2_put_buffer(dev, buf);
	}
}

static void run_stream_tx(struct v4l2_dev *dev, struct enckey *k, FILE *tx)
{
	const uint32_t chunk = 4096 - SDVR_MACLEN;
	const struct v4l2_buffer *buf;
	uint64_t ctr = 0;
	uint8_t *tmp;

	tmp = alloca(chunk + SDVR_MACLEN);

	while (!stop && (buf = v4l2_get_buffer(dev))) {
		struct frame_desc desc = {
			.pts_mono_us =
				v4l2_timeval_to_ns(&buf->timestamp) / 1000L,
			.tx_mono_us = mono_us(),
			.tx_realoff_us = realoff_us(),
			.sequence = buf->sequence,
			.length = buf->bytesused,
			.chunk_size = chunk,
		};
		uint32_t off;

		if (ctr++ % frame_step) {
			v4l2_put_buffer(dev, buf);
			continue;
		}

		encrypt_one(tmp, (const void *)&desc, sizeof(desc), k);
		if (!fwrite(tmp, 1, SDVR_MACLEN + sizeof(desc), tx))
			fatal("Bad write: %m\n");

		for (off = 0; off < buf->bytesused; off += chunk) {
			uint32_t clen = min(chunk, buf->bytesused - off);

			encrypt_one(tmp, v4l2_buf_mmap(dev, buf->index) + off,
				    clen, k);

			if (!fwrite(tmp, 1, SDVR_MACLEN + clen, tx))
				fatal("Bad write: %m\n");
		}

		v4l2_put_buffer(dev, buf);
	}
}

static int save_serverpk(const struct enckey *k, const char *name)
{
	char path[4096];

	snprintf(path, sizeof(path), "%s/.sdvr/%s.spk", getenv("HOME"), name);
	return crypto_save_pk(k, path);
}

static const struct authpubkey *get_serverpk(const char *name)
{
	char path[4096];

	snprintf(path, sizeof(path), "%s/.sdvr/%s.spk", getenv("HOME"), name);
	if (!access(path, R_OK))
		return crypto_open_pk(path);

	return NULL;
}

static const struct authkeypair *get_selfkeys(const char *name)
{
	const struct authkeypair *new;
	char *tmp, path[4096];

	snprintf(path, sizeof(path), "%s/.sdvr/%s.key", getenv("HOME"), name);
	if (!access(path, R_OK))
		return crypto_open_key(path);

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

static int enc_main(void)
{
	const struct authpubkey *remotekey;
	const struct authkeypair *authkeys;
	const struct authpubkey *savedkey;
	struct server_setup_desc ssetup;
	struct client_setup_desc setup;
	struct enckey *enckey;
	struct v4l2_dev *dev;
	uint8_t macaddr[8];
	struct kx_msg_2 m2;
	struct kx_msg_3 m3;
	uint8_t tmp[4096];
	uint32_t cookie;
	FILE *tx, *rx;
	int fd;

	fd = get_stream_connect(&dstaddr);
	if (fd == -1)
		fatal("Can't connect: %m\n");

	rx = fdopen(dup(fd), "rb");
	tx = fdopen(fd, "wb");
	setvbuf(tx, NULL, _IONBF, 0);
	setvbuf(rx, NULL, _IONBF, 0);

	dev = v4l2_open(device_path, *(uint32_t *)fmt, fps, width, height);

	v4l2_get_setup(dev, &setup);
	get_sock_macaddr(fileno(tx), macaddr);
	snprintf(setup.name, sizeof(setup.name),
		 "%s@%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
		 get_dev_businfo(dev), macaddr[0], macaddr[1], macaddr[2],
		 macaddr[3], macaddr[4], macaddr[5], macaddr[6], macaddr[7]);

	if (fread(tmp, 1, SDVR_PKLEN, rx) != SDVR_PKLEN)
		fatal("No PK?\n");

	remotekey = new_apk(tmp);
	if (!remotekey)
		fatal("No memory for PK!\n");

	authkeys = get_selfkeys(setup.name);
	enckey = kx_begin(&m2, authkeys, remotekey);
	if (!enckey)
		fatal("Bad KEX\n");

	if (!fwrite(&m2, 1, sizeof(m2), tx))
		fatal("Bad KEX\n");

	if (!fread(&m3, 1, sizeof(m3), rx))
		fatal("No KEX response\n");

	if (kx_complete(enckey, authkeys, &m3))
		fatal("Bad KEX Response\n");

	cookie = m3.text.cookie;

	encrypt_one(tmp, (const void *)&setup, sizeof(setup), enckey);
	if (!fwrite(tmp, 1, SDVR_MACLEN + sizeof(setup), tx))
		fatal("Bad write: %m\n");

	if (!fread(tmp, 1, SDVR_MACLEN + sizeof(ssetup), rx))
		fatal("Bad read: %m\n");

	if (decrypt_one((void *)&ssetup, tmp, sizeof(ssetup), enckey))
		fatal("Bad server setup desc\n");

	fclose(rx);

	fprintf(stderr, "Server name: %s\n", ssetup.name);
	fprintf(stderr, "Cookie: %" PRIu32 "\n", cookie);
	savedkey = get_serverpk(ssetup.name);

	if (!savedkey)
		if (save_serverpk(enckey, ssetup.name))
			fprintf(stderr, "Can't save server key!\n");

	if (savedkey && pk_cmp(enckey, savedkey))
		fatal("Server key changed!\n");

	if (use_udp) {
		int fd;

		fd = get_dgram_connect(&dstaddr);
		run_dgram_tx(dev, enckey, fd, cookie);
		close(fd);

	} else
		run_stream_tx(dev, enckey, tx);

	fclose(tx);
	free(enckey);
	v4l2_close(dev);
	free((void *)authkeys);
	free((void *)savedkey);
	free((void *)remotekey);
	return 0;
}

static void stopper(int nr)
{
	stop = nr;
}

static const struct sigaction stopsig = {
	.sa_flags = SA_RESETHAND,
	.sa_handler = stopper,
};

static void parse_args(int argc, char **argv)
{
	static const struct option opts[] = {
		{ "help", no_argument, NULL, 'h' },
		{ "daddr", required_argument, NULL, 'd' },
		{ "dport", required_argument, NULL, 'p' },
		{ "fps", required_argument, NULL, 'r' },
		{ "size", required_argument, NULL, 's' },
		{ "fmt", required_argument, NULL, 'f' },
		{ "drop", required_argument, NULL, 'x' },
		{ "dev", required_argument, NULL, 'i' },
		{ "key", required_argument, NULL, 'k' },
		{ "udp", no_argument, NULL, 'u' },
		{},
	};

	while (1) {
		int i = getopt_long(argc, argv, "hd:p:r:s:f:x:i:k:u", opts, NULL);
		char v4[strlen("::ffff:XXX.XXX.XXX.XXX") + 1];
		char tmp[16];
		char *w, *h;

		switch (i) {
		case 'd':
			if (inet_pton(AF_INET6, optarg, &dstaddr.in6.sin6_addr) == 1)
				break;

			snprintf(v4, sizeof(v4), "::ffff:%s", optarg);
			if (inet_pton(AF_INET6, v4, &dstaddr.in6.sin6_addr) == 1)
				break;

			fatal("Bad dstaddr '%s'\n", optarg);
		case 'p':
			// The port field is at the same offset for both v4/v6
			dstaddr.in6.sin6_port = htons(atoi(optarg));
			break;
		case 'r':
			fps = atoi(optarg);
			break;
		case 'i':
			device_path = strdup(optarg);
			break;
		case 's':
			if (!index(optarg, 'x')) {
				fprintf(stderr, "Bad size '%s'\n", optarg);
				break;
			}

			strncpy(tmp, optarg, sizeof(tmp) - 1);
			tmp[sizeof(tmp) - 1] = '\0';
			w = tmp;
			h = index(tmp, 'x');
			*h++ = '\0';

			height = atoi(h);
			width = atoi(w);
			break;
		case 'f':
			strncpy(fmt, optarg, 4);
			break;
		case 'x':
			frame_step = max(1, atoi(optarg));
			break;
		case 'k':
			key_dir = strdup(optarg);
			break;
		case 'u':
			use_udp = 1;
			break;
		case -1:
			return;
		case 'h':
			printf("Usage: %s [-f CCCC -s WxH] [-r fps] [-d drop] "
			       "[-d dstaddr] [-p dstport] [-u] [-i dev]\n", argv[0]);
			exit(0);
		default:
			exit(1);
		}
	}
}

int main(int argc, char **argv)
{
	sigaction(SIGINT, &stopsig, NULL);
	parse_args(argc, argv);
	return enc_main();
}

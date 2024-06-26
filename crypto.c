/*
 * crypto.c: Cryptography based on NaCl
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

#include "crypto.h"
#include "internal.h"
#include "proto.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/random.h>

#include <nacl/crypto_scalarmult_curve25519.h>
#include <nacl/crypto_secretbox.h>
#include <nacl/crypto_box.h>
#include <nacl/crypto_hash.h>

#define crypto_secretbox_MACBYTES (16)
#define crypto_secretbox_PADBYTES (16)
#define crypto_box_MACBYTES crypto_secretbox_MACBYTES
#define crypto_box_PADBYTES crypto_secretbox_PADBYTES

static_assert(crypto_hash_BYTES == crypto_secretbox_KEYBYTES * 2);
static_assert(crypto_secretbox_NONCEBYTES == crypto_box_NONCEBYTES);
static_assert(crypto_secretbox_ZEROBYTES == crypto_box_ZEROBYTES);
static_assert(crypto_secretbox_ZEROBYTES == 32);

static_assert(SDVR_PKLEN == crypto_box_PUBLICKEYBYTES);
static_assert(SDVR_NONCELEN == crypto_box_NONCEBYTES);
static_assert(SDVR_MACLEN == crypto_box_MACBYTES);
static_assert(SDVR_PLEN == crypto_scalarmult_curve25519_BYTES);

static_assert(__builtin_offsetof(struct kx_msg_2, text) > crypto_box_ZEROBYTES);
static_assert(__builtin_offsetof(struct kx_msg_3, text) > crypto_box_ZEROBYTES);

struct authpubkey {
	uint8_t pk[crypto_box_PUBLICKEYBYTES];
};

struct authkeypair {
	struct authpubkey apk;
	uint8_t sk[crypto_box_SECRETKEYBYTES];
};

struct hashinput {
	union {
		struct {
			uint8_t q[crypto_scalarmult_curve25519_BYTES];
			uint8_t p_a[crypto_scalarmult_curve25519_BYTES];
			uint8_t p_b[crypto_scalarmult_curve25519_BYTES];
		};

		uint8_t d[crypto_scalarmult_curve25519_BYTES * 3];
	};
};

struct hashresult {
	union {
		struct {
			uint8_t key_a[crypto_secretbox_KEYBYTES];
			uint8_t key_b[crypto_secretbox_KEYBYTES];
		};

		uint8_t d[crypto_hash_BYTES];
	};
};

struct enckey {
	struct authpubkey remote;

	struct {
		uint8_t our_n[crypto_scalarmult_curve25519_SCALARBYTES];
		uint8_t our_p[crypto_scalarmult_curve25519_BYTES];
		bool complete;
	} kx;

	struct {
		uint8_t nonce[crypto_secretbox_NONCEBYTES];
		uint8_t key[crypto_secretbox_KEYBYTES];
		uint64_t nonce_seq;
	} tx;

	struct {
		uint8_t nonce[crypto_secretbox_NONCEBYTES];
		uint8_t key[crypto_secretbox_KEYBYTES];
		uint64_t nonce_seq;
	} rx;
};

const struct authpubkey *authkeypair_apk(const struct authkeypair *ak)
{
	return &ak->apk;
}

static void __randombytes(void *x, ssize_t xlen, int flags)
{
	BUG_ON(xlen > 256);
	BUG_ON(getrandom(x, xlen, flags) != xlen);
}

uint64_t crypto_nonce_seq_tx(const struct enckey *k)
{
	return k->tx.nonce_seq;
}

uint64_t crypto_nonce_seq_rx(const struct enckey *k)
{
	return k->rx.nonce_seq;
}

int pk_cmp(const struct enckey *k, const struct authpubkey *p)
{
	return memcmp(k->remote.pk, p->pk, crypto_box_PUBLICKEYBYTES);
}

static const char hexkey_fmt[] = "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
				 "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
				 "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
				 "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx";

static int __import_hexkey(const char *hexkey, uint8_t *out)
{
	return sscanf(hexkey, hexkey_fmt,
		     out +  0, out +  1, out +  2, out + 3,
		     out +  4, out +  5, out +  6, out + 7,
		     out +  8, out +  9, out + 10, out + 11,
		     out + 12, out + 13, out + 14, out + 15,
		     out + 16, out + 17, out + 18, out + 19,
		     out + 20, out + 21, out + 22, out + 23,
		     out + 24, out + 25, out + 26, out + 27,
		     out + 28, out + 29, out + 30, out + SDVR_PKLEN - 1);
}

static void __export_hexkey(const uint8_t *in, char *out)
{
	snprintf(out, SDVR_PKLEN * 2 + 1, hexkey_fmt,
		 in[ 0], in[ 1], in[ 2], in[ 3],
		 in[ 4], in[ 5], in[ 6], in[ 7],
		 in[ 8], in[ 9], in[10], in[11],
		 in[12], in[13], in[14], in[15],
		 in[16], in[17], in[18], in[19],
		 in[20], in[21], in[22], in[23],
		 in[24], in[25], in[26], in[27],
		 in[28], in[29], in[30], in[SDVR_PKLEN - 1]);
}

const struct authpubkey *new_apk(const uint8_t *pk)
{
	struct authpubkey *r = calloc(1, sizeof(struct authpubkey));

	if (!r)
		return NULL;

	memcpy(r->pk, pk, sizeof(r->pk));
	return r;
}

const uint8_t *__pk(const struct authpubkey *p)
{
	return (const uint8_t *)p->pk;
}

const struct authkeypair *crypto_import_key(const char *hexkey)
{
	struct authkeypair *ret = malloc(sizeof(*ret));

	if (!ret)
		return NULL;

	if (hexkey) {
		if (__import_hexkey(hexkey, ret->sk) != sizeof(ret->sk)) {
			free(ret);
			return NULL;
		}

	} else {
		__randombytes(ret->sk, sizeof(ret->sk), GRND_RANDOM);
	}

	crypto_scalarmult_curve25519_base(ret->apk.pk, ret->sk);
	return ret;
}

const char *crypto_export_key(const struct authkeypair *k)
{
	char *ret = malloc(sizeof(k->sk) * 2 + 1);

	if (!ret)
		return NULL;

	__export_hexkey(k->sk, ret);
	return ret;
}

const struct authpubkey *crypto_import_pk(const char *hex_pubkey)
{
	struct authpubkey *ret = malloc(sizeof(*ret));

	if (!ret)
		return NULL;

	if (__import_hexkey(hex_pubkey, ret->pk) != sizeof(ret->pk)) {
		free(ret);
		return NULL;
	}

	return ret;
}

const char *crypto_export_pk(const struct enckey *k)
{
	char *ret = malloc(sizeof(k->remote.pk) * 2 + 1);

	if (!ret)
		return NULL;

	__export_hexkey(k->remote.pk, ret);
	return ret;
}

static struct enckey *__kx_initial(const uint8_t *remote_pk,
				   struct kx_material *kxm)
{
	struct enckey *ret;

	ret = calloc(1, sizeof(*ret));
	if (!ret)
		return NULL;

	memcpy(ret->remote.pk, remote_pk, sizeof(ret->remote.pk));
	__randombytes(ret->tx.nonce, sizeof(ret->tx.nonce), 0);
	__randombytes(ret->kx.our_n, sizeof(ret->kx.our_n), GRND_RANDOM);
	crypto_scalarmult_curve25519_base(ret->kx.our_p, ret->kx.our_n);
	memcpy(&kxm->kx_p, ret->kx.our_p, sizeof(kxm->kx_p));
	memcpy(&kxm->s_nonce, ret->tx.nonce, sizeof(kxm->s_nonce));
	return ret;
}

struct enckey *kx_begin(struct kx_msg_2 *m, const struct authkeypair *a,
			const struct authpubkey *remote)
{
	uint8_t our_kx_nonce[crypto_box_NONCEBYTES];
	struct enckey *ret;
	uint8_t *encp;

	ret = __kx_initial(remote->pk, &m->text.kxm);
	if (!ret)
		return NULL;

	__randombytes(our_kx_nonce, sizeof(our_kx_nonce), 0);
	encp = (uint8_t *)&m->text - crypto_box_ZEROBYTES;
	memset(encp, 0, crypto_box_ZEROBYTES);
	crypto_box(encp, encp, crypto_box_ZEROBYTES + sizeof(m->text),
		   our_kx_nonce, ret->remote.pk, a->sk);

	memcpy(m->kx_nonce, our_kx_nonce, sizeof(m->kx_nonce));
	memcpy(m->pk, a->apk.pk, sizeof(m->pk));

	ret->kx.complete = false;
	return ret;
}

static void __kx_complete(struct enckey *key, const uint8_t *their_p, bool x)
{
	struct hashresult h_r;
	struct hashinput h_i;

	crypto_scalarmult_curve25519(h_i.q, key->kx.our_n, their_p);
	memcpy(h_i.p_a, x ? key->kx.our_p : their_p, sizeof(h_i.p_a));
	memcpy(h_i.p_b, x ? their_p : key->kx.our_p, sizeof(h_i.p_b));

	crypto_hash(h_r.d, h_i.d, sizeof(h_i.d));
	memcpy(key->tx.key, x ? h_r.key_a : h_r.key_b, sizeof(key->tx.key));
	memcpy(key->rx.key, x ? h_r.key_b : h_r.key_a, sizeof(key->rx.key));
}

int kx_complete(struct enckey *key, const struct authkeypair *a,
		struct kx_msg_3 *m)
{
	uint8_t their_p[crypto_scalarmult_curve25519_BYTES];
	uint8_t their_kx_nonce[crypto_box_NONCEBYTES];
	uint8_t *encp;

	BUG_ON(key->kx.complete);
	memcpy(their_kx_nonce, m->kx_nonce, sizeof(their_kx_nonce));

	encp = (uint8_t *)&m->text - crypto_box_ZEROBYTES;
	memset(encp, 0, crypto_box_PADBYTES);
	if (crypto_box_open(encp, encp, crypto_box_ZEROBYTES + sizeof(m->text),
			    their_kx_nonce, key->remote.pk, a->sk))
		goto err;

	memcpy(key->rx.nonce, m->text.kxm.s_nonce, sizeof(key->rx.nonce));
	memcpy(their_p, m->text.kxm.kx_p, sizeof(their_p));
	__kx_complete(key, their_p, false);
	key->kx.complete = true;
	return 0;

err:
	return -1;
}

bool kx_start_reply(struct kx_msg_2 *m2, const struct authkeypair *a)
{
	uint8_t their_kx_nonce[crypto_box_NONCEBYTES];
	uint8_t *encp_rx;

	encp_rx = (uint8_t *)&m2->text - crypto_box_ZEROBYTES;
	memcpy(their_kx_nonce, m2->kx_nonce, sizeof(their_kx_nonce));
	memset(encp_rx, 0, crypto_box_PADBYTES);
	if (crypto_box_open(encp_rx, encp_rx,
			    crypto_box_ZEROBYTES + sizeof(m2->text),
			    their_kx_nonce, m2->pk, a->sk))
		return true;

	return false;
}

struct enckey *kx_finish_reply(const struct kx_msg_2 *m2, struct kx_msg_3 *m3,
			       const struct authkeypair *a, uint32_t cookie)
{
	uint8_t their_p[crypto_scalarmult_curve25519_BYTES];
	uint8_t our_kx_nonce[crypto_box_NONCEBYTES];
	struct enckey *ret;
	uint8_t *encp_tx;

	ret = __kx_initial(m2->pk, &m3->text.kxm);
	if (!ret)
		return NULL;

	memcpy(their_p, m2->text.kxm.kx_p, sizeof(their_p));
	memcpy(ret->rx.nonce, m2->text.kxm.s_nonce, sizeof(ret->rx.nonce));

	__randombytes(our_kx_nonce, sizeof(our_kx_nonce), 0);

	encp_tx = (uint8_t *)&m3->text - crypto_box_ZEROBYTES;
	memset(encp_tx, 0, crypto_box_ZEROBYTES);
	m3->text.cookie = cookie;
	crypto_box(encp_tx, encp_tx, crypto_box_ZEROBYTES + sizeof(m3->text),
		   our_kx_nonce, ret->remote.pk, a->sk);
	memcpy(m3->kx_nonce, our_kx_nonce, sizeof(m3->kx_nonce));

	__kx_complete(ret, their_p, true);
	ret->kx.complete = true;
	return ret;
}

struct enckey *kx_reply(struct kx_msg_2 *m2, struct kx_msg_3 *m3,
			const struct authkeypair *a, uint32_t cookie)
{
	if (kx_start_reply(m2, a))
		return NULL;

	return kx_finish_reply(m2, m3, a, cookie);
}

static void __encrypt_one(uint8_t *b, int l, const uint8_t *n, const uint8_t *k)
{
	crypto_secretbox(b, b, crypto_secretbox_ZEROBYTES + l, n, k);
}

void encrypt_one_nonce(void *out, const void *in, int len,
		       struct enckey *k, uint64_t nonce)
{
	uint8_t tmp_nonce[sizeof(k->tx.nonce)];
	uint64_t *nonce_p = (void *)tmp_nonce;
	uint8_t *buf, *plntxt, *ciptxt;

	BUG_ON(!k->kx.complete);

	memcpy(tmp_nonce, k->tx.nonce, sizeof(k->tx.nonce));
	*nonce_p += nonce;

	buf = alloca(crypto_secretbox_ZEROBYTES + len);
	memset(buf, 0, crypto_secretbox_ZEROBYTES);
	plntxt = buf + crypto_secretbox_ZEROBYTES;
	ciptxt = plntxt - crypto_secretbox_MACBYTES;

	memcpy(plntxt, in, len);
	__encrypt_one(buf, len, tmp_nonce, k->tx.key);
	memcpy(out, ciptxt, crypto_secretbox_MACBYTES + len);
}

void encrypt_one(void *out, const void *in, int len, struct enckey *k)
{
	encrypt_one_nonce(out, in, len, k, k->tx.nonce_seq++);
}

static int __decrypt_one(uint8_t *b, int l, const uint8_t *n, const uint8_t *k)
{
	if (crypto_secretbox_open(b, b, crypto_secretbox_ZEROBYTES + l, n, k))
		return -1;

	return 0;
}

int decrypt_one_nonce(void *out, const void *in, int declen,
		      struct enckey *k, uint64_t nonce)
{
	uint8_t tmp_nonce[sizeof(k->rx.nonce)];
	uint64_t *p = (void *)tmp_nonce;
	uint8_t *buf, *plntxt, *ciptxt;

	BUG_ON(!k->kx.complete);

	memcpy(tmp_nonce, k->rx.nonce, sizeof(k->rx.nonce));
	*p += nonce;

	buf = alloca(crypto_secretbox_ZEROBYTES + declen);
	memset(buf, 0, crypto_secretbox_PADBYTES);
	plntxt = buf + crypto_secretbox_ZEROBYTES;
	ciptxt = plntxt - crypto_secretbox_MACBYTES;

	memcpy(ciptxt, in, crypto_secretbox_MACBYTES + declen);
	if (__decrypt_one(buf, declen, tmp_nonce, k->rx.key))
		return -1;

	memcpy(out, plntxt, declen);
	return 0;
}

int decrypt_one(void *out, const void *in, int declen, struct enckey *k)
{
	return decrypt_one_nonce(out, in, declen, k, k->rx.nonce_seq++);
}

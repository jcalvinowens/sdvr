#pragma once

#include "proto.h"

#include <stdint.h>
#include <stdbool.h>

struct authkeypair;
struct authpubkey;
struct enckey;

const struct authkeypair *crypto_open_key(const char *path);
const struct authpubkey *crypto_open_pk(const char *path);

int crypto_save_key(const struct authkeypair *k, const char *path);
int crypto_save_pk(const struct enckey *k, const char *path);

int pk_cmp(const struct enckey *k, const struct authpubkey *p);
const struct authpubkey *authkeypair_apk(const struct authkeypair *ak);
const struct authpubkey *new_apk(const uint8_t *pk);
const uint8_t *__pk(const struct authpubkey *p);

struct enckey *kx_begin(struct kx_msg_2 *m, const struct authkeypair *a,
			const struct authpubkey *remote);

struct enckey *kx_reply(struct kx_msg_2 *m2, struct kx_msg_3 *m3,
			const struct authkeypair *a, uint32_t cookie);

int kx_complete(struct enckey *key, const struct authkeypair *a,
		struct kx_msg_3 *m);

bool kx_start_reply(struct kx_msg_2 *m2, const struct authkeypair *a);
struct enckey *kx_finish_reply(const struct kx_msg_2 *m2, struct kx_msg_3 *m3,
			       const struct authkeypair *a, uint32_t cookie);

uint64_t crypto_nonce_seq_tx(const struct enckey *k);
uint64_t crypto_nonce_seq_rx(const struct enckey *k);

void encrypt_one(void *out, const void *in, int len, struct enckey *k);
void encrypt_one_nonce(void *out, const void *in, int len,
		       struct enckey *k, uint64_t nonce);

int decrypt_one(void *out, const void *in, int declen, struct enckey *k);
int decrypt_one_nonce(void *out, const void *in, int declen,
		      struct enckey *k, uint64_t nonce);

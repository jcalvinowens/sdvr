/*
 * A simple RC5 implementation, not intended for cryptographic use, based
 * on the one provided in the appendix to Rivest's original paper.
 *
 *	http://people.csail.mit.edu/rivest/pubs/Riv94.pdf
 *	https://patents.google.com/patent/US5724428
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

#include "rc5.h"

#include <stdint.h>
#include <stdlib.h>
#include <sys/random.h>

/*
 * FIXME: We can certainly get away with less...
 */
#define RC5_ROUNDS 7

struct rc5_ctx {
	uint16_t S[2 * (RC5_ROUNDS + 1)];
};

const struct rc5_ctx *rc5_init(void)
{
	struct rc5_ctx *ctx = malloc(sizeof(*ctx));

	if (!ctx)
		return NULL;

	/*
	 * Key expansion!? Where we're going we don't need no key expansion...
	 */
	if (getrandom(ctx->S, sizeof(ctx->S), 0) != sizeof(ctx->S)) {
		free(ctx);
		return NULL;
	}

	return ctx;
}

static inline uint16_t rotl(uint16_t x, uint16_t y)
{
	return y & 15 ? ((x) << (y & (15))) | ((x) >> (16 - (y & (15)))) : x;
}

static inline uint16_t rotr(uint16_t x, uint16_t y)
{
	return y & 15 ? ((x) >> (y & (15))) | ((x) << (16 - (y & (15)))) : x;
}

uint32_t rc5_scramble(const struct rc5_ctx *ctx, uint32_t plaintext)
{
	uint16_t a = plaintext & UINT16_MAX;
	uint16_t b = plaintext >> 16;

	a += ctx->S[0];
	b += ctx->S[1];
	a = rotl(a ^ b, b) + ctx->S[2 * 1];
	b = rotl(b ^ a, a) + ctx->S[2 * 1 + 1];
	a = rotl(a ^ b, b) + ctx->S[2 * 2];
	b = rotl(b ^ a, a) + ctx->S[2 * 2 + 1];
	a = rotl(a ^ b, b) + ctx->S[2 * 3];
	b = rotl(b ^ a, a) + ctx->S[2 * 3 + 1];
	a = rotl(a ^ b, b) + ctx->S[2 * 4];
	b = rotl(b ^ a, a) + ctx->S[2 * 4 + 1];
	a = rotl(a ^ b, b) + ctx->S[2 * 5];
	b = rotl(b ^ a, a) + ctx->S[2 * 5 + 1];
	a = rotl(a ^ b, b) + ctx->S[2 * 6];
	b = rotl(b ^ a, a) + ctx->S[2 * 6 + 1];
	a = rotl(a ^ b, b) + ctx->S[2 * RC5_ROUNDS];
	b = rotl(b ^ a, a) + ctx->S[2 * RC5_ROUNDS + 1];

	return (uint32_t)b << 16 | a;
}

uint32_t rc5_unscramble(const struct rc5_ctx *ctx, uint32_t ciphertext)
{
	uint16_t a = ciphertext & UINT16_MAX;
	uint16_t b = ciphertext >> 16;

	b = rotr(b - ctx->S[2 * RC5_ROUNDS + 1], a) ^ a;
	a = rotr(a - ctx->S[2 * RC5_ROUNDS], b) ^ b;
	b = rotr(b - ctx->S[2 * 6 + 1], a) ^ a;
	a = rotr(a - ctx->S[2 * 6], b) ^ b;
	b = rotr(b - ctx->S[2 * 5 + 1], a) ^ a;
	a = rotr(a - ctx->S[2 * 5], b) ^ b;
	b = rotr(b - ctx->S[2 * 4 + 1], a) ^ a;
	a = rotr(a - ctx->S[2 * 4], b) ^ b;
	b = rotr(b - ctx->S[2 * 3 + 1], a) ^ a;
	a = rotr(a - ctx->S[2 * 3], b) ^ b;
	b = rotr(b - ctx->S[2 * 2 + 1], a) ^ a;
	a = rotr(a - ctx->S[2 * 2], b) ^ b;
	b = rotr(b - ctx->S[2 * 1 + 1], a) ^ a;
	a = rotr(a - ctx->S[2 * 1], b) ^ b;
	b -= ctx->S[1];
	a -= ctx->S[0];

	return (uint32_t)b << 16 | a;
}

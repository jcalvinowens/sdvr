/*
 * tests.c: Tests for SDVR
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
#include "crypto.h"
#include "proto.h"

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

static void test_kx(void)
{
	uint8_t str[16] = {0};
	uint8_t cip[SDVR_MACLEN + 16];
	const struct authkeypair *a_1, *a_2;
	struct enckey *k1, *k2;
	struct kx_msg_2 m2;
	struct kx_msg_3 m3;

	a_1 = crypto_open_key(NULL);
	a_2 = crypto_open_key(NULL);

	k1 = kx_begin(&m2, a_1, authkeypair_apk(a_2));
	if (!k1)
		fatal("kx_begin\n");

	k2 = kx_reply(&m2, &m3, a_2, 123456);
	if (!k2)
		fatal("kx_reply\n");

	if (kx_complete(k1, a_1, &m3))
		fatal("kx_complete\n");

	strcpy((char *)str, "Attack at dawn!");

	encrypt_one(cip, str, 16, k1);
	if (decrypt_one(str, cip, 16, k2))
		fatal("decrypt_one C/S\n");

	encrypt_one_nonce(cip, str, 16, k1, 7777);
	if (decrypt_one_nonce(str, cip, 16, k2, 7777))
		fatal("decrypt_one_nonce C/S\n");

	encrypt_one(cip, str, 16, k2);
	if (decrypt_one(str, cip, 16, k1))
		fatal("decrypt_one S/C\n");

	encrypt_one_nonce(cip, str, 16, k2, 8888);
	if (decrypt_one_nonce(str, cip, 16, k1, 8888))
		fatal("decrypt_one_nonce S/C\n");

	free((void *)a_1);
	free((void *)a_2);
	free((void *)k1);
	free((void *)k2);
}

int main(void)
{
	test_kx();

	return 0;
}

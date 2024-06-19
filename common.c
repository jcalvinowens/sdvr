/*
 * common.c: Shared client/server functionality.
 *
 * Copyright (C) 2024 Calvin Owens <calvin@wbinvd.org>
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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

#include "internal.h"
#include "crypto.h"

int save_clientpk(const struct enckey *k, const char *name)
{
	const char *tmp;
	char path[4096];
	FILE *f;
	int ret;

	snprintf(path, sizeof(path), "%s/.sdvr/%s.cpk", getenv("HOME"), name);
	f = fopen(path, "w+");
	if (!f)
		return 1;

	tmp = crypto_export_pk(k);
	ret = fwrite(tmp, 1, SDVR_PKLEN * 2, f);
	free((void *)tmp);
	fclose(f);

	if (ret != SDVR_PKLEN * 2)
		return 1;

	return 0;
}

const struct authpubkey *get_clientpk(const char *name)
{
	char hexkey[SDVR_PKLEN * 2 + 1];
	char path[4096];
	FILE *f;
	int ret;

	snprintf(path, sizeof(path), "%s/.sdvr/%s.cpk", getenv("HOME"), name);
	f = fopen(path, "r");
	if (!f)
		return NULL;

	ret = fread(hexkey, 1, sizeof(hexkey), f);
	fclose(f);

	if (ret != SDVR_PKLEN * 2)
		return NULL;

	return crypto_import_pk(hexkey);
}

int save_serverpk(const struct enckey *k, const char *name)
{
	const char *hexkey;
	char path[4096];
	int ret = 1;
	FILE *f;

	snprintf(path, sizeof(path), "%s/.sdvr/%s.spk", getenv("HOME"), name);
	f = fopen(path, "w+");
	if (!f)
		return ret;

	hexkey = crypto_export_pk(k);
	if (fwrite(hexkey, 1, SDVR_PKLEN * 2, f) == SDVR_PKLEN * 2)
		ret = 0;

	free((void *)hexkey);
	fclose(f);
	return ret;
}

const struct authpubkey *get_serverpk(const char *name)
{
	char hexkey[SDVR_PKLEN * 2 + 1];
	char path[4096];
	int ret;
	FILE *f;

	snprintf(path, sizeof(path), "%s/.sdvr/%s.spk", getenv("HOME"), name);
	f = fopen(path, "r");
	if (!f)
		return NULL;

	ret = fread(hexkey, 1, sizeof(hexkey) - 1, f);
	fclose(f);

	if (ret != sizeof(hexkey) - 1)
		return NULL;

	hexkey[sizeof(hexkey) - 1] = '\0';
	return crypto_import_pk(hexkey);
}

const struct authkeypair *get_selfkeys(const char *fmt, ...)
{
	const struct authkeypair *new;
	char *tmp, path[4096];
	const char *tmp2;
	va_list ap;
	FILE *f;

	va_start(ap, fmt);
	vsnprintf(path, sizeof(path), fmt, ap);
	va_end(ap);

	f = fopen(path, "r");
	if (f) {
		char hexkey[SDVR_PKLEN * 2 + 1];
		int ret;

		ret = fread(hexkey, 1, sizeof(hexkey) - 1, f);
		fclose(f);

		if (ret != sizeof(hexkey) - 1)
			return NULL;

		hexkey[sizeof(hexkey) - 1] = '\0';
		return crypto_import_key(hexkey);
	}

	tmp = rindex(path, '/');
	*tmp = '\0';
	if (access(path, F_OK))
		if (mkdir(path, 0700))
			fprintf(stderr, "Can't mkdir ~/.sdvr!\n");
	*tmp = '/';

	new = crypto_import_key(NULL);
	f = fopen(path, "w+");
	if (!f)
		fprintf(stderr, "Unable to save key!\n");

	tmp2 = crypto_export_key(new);
	fwrite(tmp2, 1, SDVR_PKLEN * 2, f);
	free((void *)tmp2);
	fclose(f);

	return new;
}

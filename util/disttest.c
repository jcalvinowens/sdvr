/*
 * disttest.c: Trivial little tool to brute force 32bit input hash space.
 * Install gnuplot if you want graphs.
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

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <time.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <err.h>
#include <sys/random.h>
#include <sys/wait.h>

#include "jhash.h"
#include "murmur.h"
#include "../rc5.h"

static uint32_t jhash_seed;
static uint32_t jhashhash(uint32_t v)
{
	return jhash_1word(v, jhash_seed);
}

static uint32_t murmur_seed;
static uint32_t murmurhash(uint32_t v)
{
	return __murmur3_32((const uint8_t *)&v, sizeof(v), murmur_seed);
}

static const struct rc5_ctx *ctx;
static uint32_t rc5scramble(uint32_t v)
{
	return rc5_scramble(ctx, v);
}

static void gnuplot_u32(const char *title, const uint32_t *arr, int len)
{
	static const char plotfmt[] = "set term x11; set title '%s'; plot '-';";
	char *plotcmd = NULL;
	int i, pipefd[2];
	pid_t pid;

	if (pipe(pipefd))
		err(1, "Can't make pipes");

	if (asprintf(&plotcmd, plotfmt, title) == -1)
		err(1, "Can't make plotcmd");

	pid = fork();
	if (!pid) {
		close(pipefd[1]);
		dup2(pipefd[0], STDIN_FILENO);
		execlp("gnuplot", "gnuplot", "--persist", "-e", plotcmd, NULL);

		_exit(errno);
	}

	close(pipefd[0]);
	free(plotcmd);

	for (i = 0; i < len; i++)
		dprintf(pipefd[1], "%" PRIu32 " %" PRIu32 "\n", i, arr[i]);

	close(pipefd[1]);
	waitpid(pid, NULL, 0);
}

static int hweight(uint32_t v)
{
	return __builtin_popcountl(v);
}

static int64_t now_mono_ns(void)
{
	const int64_t nsecs_per_sec = 1000L * 1000 * 1000;
	struct timespec t;

	if (clock_gettime(CLOCK_MONOTONIC, &t))
		err(1, "Bad clock_gettime");

	return (int64_t)t.tv_nsec + (int64_t)t.tv_sec * nsecs_per_sec;
}

static void make_histo(int order, const char *title,
		       uint32_t (*hashfn)(uint32_t))
{
	uint32_t output_histogram[1 << order];
	uint32_t hweight_diff_hist[33] = {0};
	uint32_t freq_hist[33] = {0};
	uint64_t before, after;
	uint32_t i = 0;
	uint8_t *map;

	printf("Testing '%s':\n", title);

	map = calloc(1, (long)UINT32_MAX + 1);
	fprintf(stderr, "[----------------------------------------------------------------]\n");
	fprintf(stderr, "[");

	before = now_mono_ns();
	do {
		uint32_t v = hashfn(i);
		hweight_diff_hist[hweight(i ^ v)]++;
		map[v]++;

		if (!(i++ & 0x03fffffful))
			fprintf(stderr, "=");
	} while (i);
	after = now_mono_ns();

	fprintf(stderr, "]\n");

	printf("Average hash wall time: %" PRId64 "ns\n", (after - before) >> 32);

	i = 0;
	do {
		uint32_t count = map[i++];
		if (count < 32)
			freq_hist[count]++;
		else
			freq_hist[32]++;
	} while (i);

	for (i = 0; i < 32; i++)
		if (freq_hist[i])
			printf("Output values produced by %02d inputs: %u\n", i,
			       freq_hist[i]);
	if (freq_hist[32])
		printf("Output values produced by more than 32 inputs: %u\n", freq_hist[32]);

	for (i = 0; i < 33; i++)
		printf("Output values which vary from input by %02d bits: %u\n", i,
		       hweight_diff_hist[i]);

	for (i = 0; i < (1u << order); i++) {
		uint32_t j;

		output_histogram[i] = 0;
		for (j = i << (32 - order); j < ((i + 1) << (32 - order)) - 1; j++)
			output_histogram[i] += map[j];
	}

	gnuplot_u32(title, output_histogram, 1 << order);
	gnuplot_u32(title, hweight_diff_hist, 33);
	puts("");
	free(map);
}

int main(void)
{
	if (getrandom(&jhash_seed, sizeof(jhash_seed), 0) != sizeof(jhash_seed))
		err(1, "Can't seed jhash");
	make_histo(16, "jhash", jhashhash);

	if (getrandom(&murmur_seed, sizeof(murmur_seed), 0) != sizeof(murmur_seed))
		err(1, "Can't seed murmur");
	make_histo(16, "murmurhash", murmurhash);

	ctx = rc5_init();
	make_histo(16, "rc5scramble", rc5scramble);
	free((void *)ctx);

	return 0;
}

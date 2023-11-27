/*
 * ring.h: Ring buffer structures
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

#pragma once

#include <stdint.h>

#define SDVR_SHM_DIR_NAME "sdvr"

struct shm_ring_dir_desc {
	uint32_t gen;
	uint32_t len;

} __attribute__((packed));

struct shm_ring_dir_ent {
	uint8_t is_active;
	char shm_path[127];

} __attribute__((packed));

struct shm_ring_dir {
	struct shm_ring_dir_desc desc;
	struct shm_ring_dir_ent ents[0];

} __attribute__((packed));

#define RING_ORDERED		((uint32_t)1 << 0)
#define RING_RELIABLE		((uint32_t)1 << 1)
#define RING_COMPRESSED		((uint32_t)1 << 2)

struct shm_ring_desc {
	uint8_t public_key[32];
	char name[128];

	uint32_t pixelformat;
	uint32_t fps_numerator;
	uint32_t fps_denominator;
	uint32_t width;
	uint32_t height;
	uint32_t flags;
	uint64_t ring_size;

	uint64_t tail_offset;
	uint32_t ctr;
	uint32_t gen;

} __attribute__((packed));

struct shm_ring {
	struct shm_ring_desc desc;
	uint8_t ring[0];

} __attribute__((packed));

#define FRAME_COMPLETE		((uint32_t)1 << 0)
#define FRAME_I_FRAME		((uint32_t)1 << 1)
#define FRAME_P_FRAME		((uint32_t)1 << 2)
#define FRAME_B_FRAME		((uint32_t)1 << 3)
#define FRAME_CORRUPTED		((uint32_t)1 << 4)

struct shm_ring_head {
	uint64_t offset_prev;
	int64_t pts_mono_us;
	uint32_t frame_seq;
	uint32_t frame_len;
	uint32_t written_len;
	uint32_t ring_ctr;

} __attribute__((packed));

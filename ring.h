/*
 * ring.h: Ring buffer structures
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

#pragma once

#include <stdint.h>

#define SDVR_SHM_DIR_NAME "sdvrddir"

struct shm_ring_dir_head {
	uint32_t seq;
	uint32_t len;

} __attribute__((packed));

struct shm_ring_dir_ent {
	uint8_t is_active;
	char client_name[127];
	char shm_path[128];

} __attribute__((packed));

struct shm_ring_dir {
	struct shm_ring_dir_head head;
	uint8_t __pad[sizeof(struct shm_ring_dir_ent)
		      - sizeof(struct shm_ring_dir_head)];

	struct shm_ring_dir_ent ents[];

} __attribute__((packed));

struct shm_ring_desc {
	char name[128];
	uint8_t public_key[32];
	uint32_t pixelformat;
	uint32_t fps_numerator;
	uint32_t fps_denominator;
	uint32_t width;
	uint32_t height;
	uint32_t flags;
	uint64_t ring_size;

	uint64_t offset_next;
	uint64_t offset_newest;
	uint64_t offset_oldest;
	int32_t frame_seq;
	int32_t chunk_seq;

} __attribute__((packed));

struct shm_ring_head {
	uint64_t prev_offset;
	int64_t pts_mono_us;
	int32_t frame_seq;
	uint32_t frame_len;
	uint32_t frame_chunk;
	uint32_t chunks_done;

} __attribute__((packed));

struct shm_ring {
	struct shm_ring_desc desc;
	uint8_t __pad[4096 - sizeof(struct shm_ring_desc)];
	uint8_t ring[0];

} __attribute__((packed));

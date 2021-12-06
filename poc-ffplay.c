/*
 * Kludgey shim that reads out of the ring and writes to ffplay via a pipe
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

#include "ring.h"
#include "common.h"

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
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/epoll.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <linux/close_range.h>
#include <linux/videodev2.h>

#define close_range(...) syscall(__NR_close_range, __VA_ARGS__)
#define futex(...) syscall(SYS_futex, __VA_ARGS__)

#define FMTCASE(a,b) case a: return b;
static const char *v4l2_to_ffmpeg(uint32_t fmt)
{
	switch (fmt) {
		FMTCASE(V4L2_PIX_FMT_YUV420, "yuv420p");
		FMTCASE(V4L2_PIX_FMT_Y41P, "yuv411p");
		FMTCASE(V4L2_PIX_FMT_YUYV, "yuyv422");
		FMTCASE(V4L2_PIX_FMT_UYVY, "uyvy422");
		FMTCASE(V4L2_PIX_FMT_YVYU, "yvyu422");
		FMTCASE(V4L2_PIX_FMT_NV12, "nv12");
		FMTCASE(V4L2_PIX_FMT_NV21, "nv21");
		FMTCASE(V4L2_PIX_FMT_NV24, "nv24");
		FMTCASE(V4L2_PIX_FMT_NV42, "nv42");
		FMTCASE(V4L2_PIX_FMT_RGB24, "rgb24");
		FMTCASE(V4L2_PIX_FMT_BGR24, "bgr24");
		FMTCASE(V4L2_PIX_FMT_GREY, "gray");
		FMTCASE(V4L2_PIX_FMT_Y10, "gray10le");
		FMTCASE(V4L2_PIX_FMT_Y16, "gray16le");
		FMTCASE(V4L2_PIX_FMT_Y16_BE, "gray16be");
	}

	return "monob";
}

static pid_t run_ffplay(uint32_t fmt, const char *sstr, int *ffplay_pipe)
{
	const char *const *argv;
	int pipefd[2];
	pid_t ret;

	const char *const mjpeg_argv[] = {
		"/usr/bin/ffplay",
		"-fflags", "nobuffer",
		"-f", "mjpeg", "-",
		NULL,
	};
	const char *const h264_argv[] = {
		"/usr/bin/ffplay",
		"-fflags", "nobuffer",
		"-f", "h264", "-",
		NULL,
	};
	const char *const raw_argv[] = {
		"/usr/bin/ffplay",
		"-fflags", "nobuffer",
		"-f", "rawvideo",
		"-s", sstr,
		"-pixel_format", v4l2_to_ffmpeg(fmt),
		"-", NULL,
	};

	if (fmt == V4L2_PIX_FMT_MJPEG || fmt == V4L2_PIX_FMT_JPEG)
		argv = mjpeg_argv;
	else if (fmt == V4L2_PIX_FMT_H264)
		argv = h264_argv;
	else
		argv = raw_argv;

	if (pipe(pipefd))
		fatal("Can't make pipes: %m\n");

	ret = fork();
	if (!ret) {
		close(pipefd[1]);
		dup2(pipefd[0], STDIN_FILENO);
		close_range(3, ~0U, CLOSE_RANGE_UNSHARE);
		execv(argv[0], (char * const *)argv);
		_exit(1);
	}

	close(pipefd[0]);
	*ffplay_pipe = pipefd[1];
	return ret;
}

static void ring_read(uint8_t *out, const struct shm_ring *ring,
		      uint64_t off, uint64_t len)
{
	uint64_t i;

	for (i = 0; i < len; off++, i++)
		out[i] = ring->ring[off % ring->desc.ring_size];
}

static sig_atomic_t stop;

static void *ffplay_feeder_thread(void *arg)
{
	struct shm_ring_dir_ent *ent = arg;
	int ring_fd, ffplay_pipe;
	int32_t last_frame_seq;
	struct shm_ring *ring;
	uint64_t last_off;
	void *ring_mmap;
	char sstr[16];
	uint8_t *buf;
	struct stat s;
	pid_t ffpid;
	FILE *fftx;

	ring_fd = shm_open(ent->shm_path, O_RDONLY, 0);
	if (ring_fd == -1)
		fatal("Can't open %s: %m\n", ent->shm_path);

	if (fstat(ring_fd, &s))
		fatal("Can't stat ring: %m\n");

	ring_mmap = mmap(NULL, s.st_size, PROT_READ, MAP_SHARED, ring_fd, 0);
	if (ring_mmap == MAP_FAILED)
		fatal("Can't map ring: %m\n");

	ring = ring_mmap;
	snprintf(sstr, sizeof(sstr), "%dx%d", ring->desc.width,
		 ring->desc.height);

	buf = malloc(ring->desc.ring_size);
	if (!buf)
		fatal("No RAM for sepbuf\n");

	ffpid = run_ffplay(ring->desc.pixelformat, sstr, &ffplay_pipe);
	fftx = fdopen(ffplay_pipe, "wb");
	setvbuf(fftx, NULL, _IONBF, 0);

	last_frame_seq = ring->desc.frame_seq; // FIXME racy
	last_off = ring->desc.offset_newest;
	while (!stop) {
		int32_t f_seq = ring->desc.frame_seq;
		struct shm_ring_head head;

		if (f_seq == last_frame_seq) {
			futex(&ring->desc.frame_seq, FUTEX_WAIT, f_seq, NULL,
			      NULL, 0);

			continue;
		}

		ring_read((uint8_t *)&head, ring, last_off, sizeof(head));
		ring_read(buf, ring, last_off + sizeof(head), head.frame_len);
		if (fwrite(buf, 1, head.frame_len, fftx) == 0)
			break;

		last_off += head.frame_len + sizeof(head);
		last_frame_seq += 1;
	}

	kill(ffpid, SIGTERM);
	fclose(fftx);
	munmap(ring_mmap, s.st_size);
	close(ring_fd);
	return NULL;
}

int main(void)
{
	int dir_fd;
	void *dir_mmap;
	struct shm_ring_dir *dir;
	uint32_t i;

	dir_fd = shm_open(SDVR_SHM_DIR_NAME, O_RDONLY, 0);
	if (dir_fd == -1)
		fatal("Can't open %s: %m\n", SDVR_SHM_DIR_NAME);

	dir_mmap = mmap(NULL, 32768, PROT_READ, MAP_SHARED, dir_fd, 0);
	if (dir_mmap == MAP_FAILED)
		fatal("Can't map dir: %m\n");

	dir = dir_mmap;
	for (i = 0; i < dir->head.len; i++) {
		struct shm_ring_dir_ent *ent = dir->ents + i;
		pthread_t tmp;

		if (!ent->is_active)
			continue;

		pthread_create(&tmp, NULL, ffplay_feeder_thread, ent);
	}

	while (1)
		sleep(INT_MAX);

	return 0;
}

/*
 * v4l2.c: Minimal V4L2 library
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
#include "proto.h"
#include "v4l2.h"

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <linux/videodev2.h>

struct v4l2_dev {
	struct v4l2_capability cap;
	int v4l2_fd;

	int nr_buffers;
	unsigned buffer_lens[MAXBUFS];
	void *mmaps[MAXBUFS];
};

const char *get_dev_businfo(const struct v4l2_dev *dev)
{
	return (const char *)dev->cap.bus_info;
}

static void v4l2_enum_ivals(struct v4l2_dev *dev, const struct v4l2_fmtdesc *fmt,
			    int width, int height)
{
	int i;

	for (i = 0;; i++) {
		struct v4l2_frmivalenum ival = {
			.pixel_format = fmt->pixelformat,
			.width = width,
			.height = height,
			.index = i,
		};

		if (ioctl(dev->v4l2_fd, VIDIOC_ENUM_FRAMEINTERVALS, &ival))
			break;

		fprintf(stderr, "        @%dx%d ival %d ", width, height, i);

		switch (ival.type) {
		case V4L2_FRMIVAL_TYPE_DISCRETE:
			fprintf(stderr, "discrete %d/%d\n",
				ival.discrete.numerator,
				ival.discrete.denominator);

			break;

		case V4L2_FRMIVAL_TYPE_STEPWISE:
			fprintf(stderr, "step %d/%d ",
				ival.stepwise.step.numerator,
				ival.stepwise.step.denominator);

			/* fall through */

		case V4L2_FRMIVAL_TYPE_CONTINUOUS:
			fprintf(stderr, "min %d/%d max %d/%d\n",
				ival.stepwise.min.numerator,
				ival.stepwise.min.denominator,
				ival.stepwise.max.numerator,
				ival.stepwise.max.denominator);

			break;

		}
	}
}

static void v4l2_enum_sizes(struct v4l2_dev *dev, const struct v4l2_fmtdesc *fmt)
{
	int i;

	for (i = 0;; i++) {
		struct v4l2_frmsizeenum size = {
			.pixel_format = fmt->pixelformat,
			.index = i,
		};

		if (ioctl(dev->v4l2_fd, VIDIOC_ENUM_FRAMESIZES, &size))
			break;

		fprintf(stderr, "    Size % 2d ", i);

		switch (size.type) {
		case V4L2_FRMSIZE_TYPE_DISCRETE:
			fprintf(stderr, "discrete %dx%d\n", size.discrete.width,
				size.discrete.height);

			v4l2_enum_ivals(dev, fmt, size.discrete.width,
					size.discrete.height);

			break;

		case V4L2_FRMSIZE_TYPE_STEPWISE:
			fprintf(stderr, "step %dx%d ",
				size.stepwise.step_width,
				size.stepwise.step_height);

			/* fall through */

		case V4L2_FRMSIZE_TYPE_CONTINUOUS:
			fprintf(stderr, "min %dx%d max %dx%d\n",
				size.stepwise.min_width,
				size.stepwise.min_height,
				size.stepwise.max_width,
				size.stepwise.max_height);

			v4l2_enum_ivals(dev, fmt, size.stepwise.min_width,
					size.stepwise.min_height);
			v4l2_enum_ivals(dev, fmt, size.stepwise.max_width,
					size.stepwise.max_height);

			break;

		};
	}
}

static void v4l2_enum_formats(struct v4l2_dev *dev)
{
	int i;

	for (i = 0;; i++) {
		struct v4l2_fmtdesc fmt = {
			.type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
			.index = i,
		};
		char pixfmt[5] = {0};

		if (ioctl(dev->v4l2_fd, VIDIOC_ENUM_FMT, &fmt))
			break;

		memcpy(pixfmt, &fmt.pixelformat, 4);
		fprintf(stderr, "Format % 2d '%s' %s %s%s\n", i, pixfmt,
			fmt.description,
			fmt.flags & V4L2_FMT_FLAG_COMPRESSED ? "[COMPRESSED] " : "",
			fmt.flags & V4L2_FMT_FLAG_EMULATED ? "[EMULATED] " : ""
		);
		v4l2_enum_sizes(dev, &fmt);
	}
}

void v4l2_get_setup(struct v4l2_dev *dev, struct client_setup_desc *out)
{
	struct v4l2_format fmt = {
		.type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
	};
	struct v4l2_streamparm parm = {
		.type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
	};

	memset(out, 0, sizeof(*out));

	if (ioctl(dev->v4l2_fd, VIDIOC_G_FMT, &fmt))
		fatal("VIDIOC_G_FMT: %m\n");

	if (ioctl(dev->v4l2_fd, VIDIOC_G_PARM, &parm) == 0) {
		fprintf(stderr, "Claimed FPS: %u/%u\n",
			parm.parm.capture.timeperframe.numerator,
			parm.parm.capture.timeperframe.denominator);

		out->fps_numerator = parm.parm.capture.timeperframe.numerator;
		out->fps_denominator = parm.parm.capture.timeperframe.denominator;
	}

	out->pixelformat = fmt.fmt.pix.pixelformat;
	out->width = fmt.fmt.pix.width;
	out->height = fmt.fmt.pix.height;
}

static int v4l2_set_format(struct v4l2_dev *dev, const struct v4l2_pix_format *pix)
{
	struct v4l2_format fmt = {
		.type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
		.fmt.pix = *pix,
	};

	return ioctl(dev->v4l2_fd, VIDIOC_S_FMT, &fmt);
}

static int v4l2_set_rate(struct v4l2_dev *dev, const struct v4l2_fract *fp)
{
	struct v4l2_streamparm parm = {
		.type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
		.parm.capture = {
			//.capturemode = V4L2_MODE_HIGHQUALITY,
			.timeperframe = *fp,
		},
	};

	return ioctl(dev->v4l2_fd, VIDIOC_S_PARM, &parm);
}

static void v4l2_init_stream(struct v4l2_dev *dev)
{
	struct v4l2_buffer bufs[MAXBUFS];
	struct v4l2_requestbuffers req = {
		.type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
		.memory = V4L2_MEMORY_MMAP,
		.count = MAXBUFS,
	};
	int i;

	if (ioctl(dev->v4l2_fd, VIDIOC_QUERYCAP, &dev->cap))
		fatal("VIDIOC_QUERYCAP: %m\n");

	fprintf(stderr, "Driver: %s\n", dev->cap.driver);
	fprintf(stderr, "Card:   %s\n", dev->cap.card);
	fprintf(stderr, "Phys:   %s\n", dev->cap.bus_info);
	fprintf(stderr, "Vers:   %08x\n", dev->cap.version);
	v4l2_enum_formats(dev);

	if (!(dev->cap.device_caps & V4L2_CAP_VIDEO_CAPTURE))
		fatal("No capture support!\n");

	if (!(dev->cap.device_caps & V4L2_CAP_STREAMING))
		fatal("No streaming support!\n");

	if (ioctl(dev->v4l2_fd, VIDIOC_REQBUFS, &req))
		fatal("VIDIOC_REQBUFS: %m\n");

	if (req.count > MAXBUFS)
		fatal("Too many buffers! %d\n", req.count);

	dev->nr_buffers = req.count;
	fprintf(stderr, "Driver allocated %d buffers\n", dev->nr_buffers);
	for (i = 0; i < dev->nr_buffers; i++) {
		bufs[i] = (struct v4l2_buffer){
			.type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
			.flags = V4L2_BUF_FLAG_TIMESTAMP_MONOTONIC,
			.memory = V4L2_MEMORY_MMAP,
			.index = i,
		};

		if (ioctl(dev->v4l2_fd, VIDIOC_QUERYBUF, &bufs[i]))
			fatal("VIDIOC_QUERYBUF: %m\n");

		dev->buffer_lens[i] = bufs[i].length;
		dev->mmaps[i] = mmap(NULL, bufs[i].length, PROT_READ | PROT_WRITE,
				     MAP_SHARED | MAP_POPULATE, dev->v4l2_fd,
				     bufs[i].m.offset);

		if (dev->mmaps[i] == MAP_FAILED)
			fatal("Can't mmap buffer %d: %m\n", i);
	}

	for (i = 0; i < dev->nr_buffers; i++)
		if (ioctl(dev->v4l2_fd, VIDIOC_QBUF, &bufs[i]))
			fatal("Initial VIDIOC_QBUF: %m\n");

	i = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	if (ioctl(dev->v4l2_fd, VIDIOC_STREAMON, &i))
		fatal("VIDIOC_STREAMON: %m\n");
}

const uint8_t *v4l2_buf_mmap(struct v4l2_dev *dev, int index)
{
	return dev->mmaps[index];
}

const struct v4l2_buffer *v4l2_get_buffer(struct v4l2_dev *dev)
{
	struct v4l2_buffer *buf = malloc(sizeof(*buf));
	struct pollfd pfd = {0};

	if (!buf)
		return NULL;

	while (1) {
		*buf = (struct v4l2_buffer){
			.type = V4L2_BUF_TYPE_VIDEO_CAPTURE,
			.memory = V4L2_MEMORY_MMAP,
		};

		if (ioctl(dev->v4l2_fd, VIDIOC_DQBUF, buf) == 0) {
			if (buf->bytesused > dev->buffer_lens[buf->index])
				fatal("Bad buffer: %u > %d\n", buf->bytesused,
				      dev->buffer_lens[buf->index]);

			return buf;
		}

		if (errno != EAGAIN)
			break;

		pfd.fd = dev->v4l2_fd;
		pfd.events = POLLIN;
		if (poll(&pfd, 1, -1) == -1 && errno != EINTR)
			break;
	}

	free(buf);
	return NULL;
}

void v4l2_put_buffer(struct v4l2_dev *dev, const struct v4l2_buffer *buf)
{
	if (ioctl(dev->v4l2_fd, VIDIOC_QBUF, buf))
		fatal("VIDIOC_QBUF: %m\n");

	free((void *)buf);
}

struct v4l2_dev *v4l2_open(const char *path, uint32_t fmt, int fps, int width,
			   int height)
{
	struct v4l2_dev *dev;

	dev = calloc(1, sizeof(*dev));
	if (!dev)
		fatal("No memory for v4l2_dev struct\n");

	dev->v4l2_fd = open(path, O_RDWR | O_NONBLOCK);
	if (dev->v4l2_fd == -1)
		fatal("Can't open V4L2 dev %s: %m\n", path);

	if (fmt != 0x20202020) {
		struct v4l2_pix_format pix = {
			.pixelformat = fmt,
			.width = width,
			.height = height,
		};

		if (width == 0 || height == 0)
			fatal("You forgot '-s WWWWxHHHH'\n");

		if (v4l2_set_format(dev, &pix))
			fprintf(stderr, "VIDIOC_S_FMT: %m\n");
	}

	if (fps) {
		struct v4l2_fract fp = {
			.numerator = 1,
			.denominator = fps,
		};

		if (v4l2_set_rate(dev, &fp))
			fprintf(stderr, "VIDIOC_S_PARM: %m\n");
	}

	v4l2_init_stream(dev);
	return dev;
}

void v4l2_close(struct v4l2_dev *dev)
{
	int i;

	i = V4L2_BUF_TYPE_VIDEO_CAPTURE;
	if (ioctl(dev->v4l2_fd, VIDIOC_STREAMOFF, &i))
		fatal("VIDIOC_STREAMOFF: %m\n");

	for (i = 0; i < dev->nr_buffers; i++)
		munmap(dev->mmaps[i], dev->buffer_lens[i]);

	close(dev->v4l2_fd);
	free(dev);
}

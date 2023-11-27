#pragma once

#include <stdint.h>
#include <linux/videodev2.h>

#define MAXBUFS 256

struct v4l2_dev;

struct v4l2_dev *v4l2_open(const char *path, uint32_t pixfmt, int fps,
			   int width, int height);

void v4l2_get_setup(struct v4l2_dev *dev, struct client_setup_desc *setup);
const char *get_dev_businfo(const struct v4l2_dev *dev);

const struct v4l2_buffer *v4l2_get_buffer(struct v4l2_dev *dev);
void v4l2_put_buffer(struct v4l2_dev *dev, const struct v4l2_buffer *buf);
const uint8_t *v4l2_buf_mmap(struct v4l2_dev *dev, int index);

void v4l2_close(struct v4l2_dev *dev);

/*
 * Example consumer that records raw video (decoded, if necessary)
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

#include "output.h"

#include <cerrno>
#include <climits>
#include <csignal>
#include <unordered_map>
#include <iostream>

extern "C" {
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include "libavcodec/avcodec.h"
}

class SDVRClientRawFileRecorder final : public DecodingSDVRClient {
public:

	explicit SDVRClientRawFileRecorder(const SDVRClientRawFileRecorder&) = delete;
	explicit SDVRClientRawFileRecorder(std::string shm_path) :
		DecodingSDVRClient(shm_path) {}

	void init() final
	{
		fd_ = open(desc()->name, O_WRONLY | O_TRUNC | O_CREAT);
		if (fd_ == -1)
			throw std::system_error(errno, std::generic_category());
	}

	void process_decoded(AVFrame *f) final
	{
		switch (f->format) {
		case AV_PIX_FMT_YUVJ422P:
			write(fd_, f->data[0], f->height * f->width);
			write(fd_, f->data[1], f->height * f->width / 2);
			write(fd_, f->data[2], f->height * f->width / 2);
			break;

		case AV_PIX_FMT_YUVJ420P:
		case AV_PIX_FMT_YUV420P:
			write(fd_, f->data[0], f->height * f->width);
			write(fd_, f->data[1], f->height * f->width / 4);
			write(fd_, f->data[2], f->height * f->width / 4);
			break;

		case AV_PIX_FMT_GRAY8:
			write(fd_, f->data[0], f->height * f->width);
			break;

		default:
			throw std::runtime_error("Unknown pixel format!");
		}
	}

	void deinit() final
	{
		if (close(fd_))
			throw std::system_error(errno, std::generic_category());
	}

private:

	int fd_;
};

int main(void)
{
	sigset_t set;
	int num;

	sigemptyset(&set);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGINT);
	sigprocmask(SIG_BLOCK, &set, nullptr);

	SDVRFactory<SDVRClientRawFileRecorder> factory(false);
	factory.start();
	sigwait(&set, &num);
	factory.stop();
	return 0;
}

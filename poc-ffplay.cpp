/*
 * Example code to play all cameras using ffplay.
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

#include "output.h"

#include <cerrno>
#include <climits>
#include <csignal>
#include <unordered_map>

extern "C" {
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/close_range.h>
#include <linux/videodev2.h>
}

#define close_range(...) syscall(__NR_close_range, __VA_ARGS__)

static const std::unordered_map<uint32_t, const char *> v4l2_to_ff = {
	{V4L2_PIX_FMT_YUV420,	"yuv420p"},
	{V4L2_PIX_FMT_Y41P,	"yuv411p"},
	{V4L2_PIX_FMT_YUYV,	"yuyv422"},
	{V4L2_PIX_FMT_UYVY,	"uyvy422"},
	{V4L2_PIX_FMT_YVYU,	"yvyu422"},
	{V4L2_PIX_FMT_NV12,	"nv12"},
	{V4L2_PIX_FMT_NV21,	"nv21"},
	{V4L2_PIX_FMT_NV24,	"nv24"},
	{V4L2_PIX_FMT_NV42,	"nv42"},
	{V4L2_PIX_FMT_RGB24,	"rgb24"},
	{V4L2_PIX_FMT_BGR24,	"bgr24"},
	{V4L2_PIX_FMT_GREY,	"gray"},
	{V4L2_PIX_FMT_Y10,	"gray10le"},
	{V4L2_PIX_FMT_Y16,	"gray16le"},
	{V4L2_PIX_FMT_Y16_BE,	"gray16be"},
};

static const char *const mjpeg_argv[] = {
	"/usr/bin/ffplay",
	"-fflags", "nobuffer",
	"-f", "mjpeg", "-",
	nullptr,
};

static const char *const h264_argv[] = {
	"/usr/bin/ffplay",
	"-fflags", "nobuffer",
	"-f", "h264", "-",
	nullptr,
};

class SDVRClientFF final : public SDVRClient {
public:

	explicit SDVRClientFF(std::string shm_path) : SDVRClient(shm_path) {}
	explicit SDVRClientFF(const SDVRClientFF&) = delete;

	void init() override {
		uint32_t fmt = desc().pixelformat;
		const char *const *argv;
		int pipefd[2];
		char sstr[16];
		pid_t ret;

		snprintf(sstr, sizeof(sstr), "%dx%d", desc().width, desc().height);

		std::string ff_fmt;
		auto it = v4l2_to_ff.find(desc().pixelformat);
		if (it == v4l2_to_ff.end())
			ff_fmt = "monob";
		else
			ff_fmt = it->second;

		const char *const raw_argv[] = {
			"/usr/bin/ffplay",
			"-fflags", "nobuffer",
			"-f", "rawvideo",
			"-s", sstr,
			"-pixel_format", ff_fmt.c_str(),
			"-", nullptr,
		};

		if (fmt == V4L2_PIX_FMT_MJPEG || fmt == V4L2_PIX_FMT_JPEG)
			argv = mjpeg_argv;
		else if (fmt == V4L2_PIX_FMT_H264)
			argv = h264_argv;
		else
			argv = raw_argv;

		if (pipe(pipefd))
			throw std::system_error(errno, std::generic_category());

		ret = fork();
		if (!ret) {
			close(pipefd[1]);
			dup2(pipefd[0], STDIN_FILENO);
			close_range(3, ~0U, CLOSE_RANGE_UNSHARE);
			execv(argv[0], (char * const *)argv);
			_exit(1);
		}

		close(pipefd[0]);
		ffplay_pipe_ = pipefd[1];
		ffplay_pid_ = ret;

		if (ffplay_pid_ == -1)
			throw std::runtime_error("Can't start ffplay?");

		fftx_ = fdopen(ffplay_pipe_, "wb");
	}

	void call(SDVRFrame& frame) override {
		fwrite(frame.data_, 1, frame.head_->frame_len, fftx_);
	}

	void deinit() override {
		kill(ffplay_pid_, SIGTERM);
		fclose(fftx_);
	}

private:

	pid_t ffplay_pid_;
	int ffplay_pipe_;
	FILE *fftx_;
};

int main(void)
{
	sigset_t set;
	int num;

	sigemptyset(&set);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGINT);
	sigprocmask(SIG_BLOCK, &set, nullptr);

	SDVRFactory<SDVRClientFF> factory;
	factory.start();
	sigwait(&set, &num);

	factory.stop();
	return 0;
}

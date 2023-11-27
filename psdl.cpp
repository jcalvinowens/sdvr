/*
 * Example consumer that displays video at native resolution using libsdl2
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
#include <SDL2/SDL.h>
#include <SDL2/SDL_video.h>
#include "libavcodec/avcodec.h"
}

static const std::unordered_map<enum AVPixelFormat, uint32_t> lavc_to_sdl = {
	// Natively supported LAVC formats in SDL
	{AV_PIX_FMT_YUV420P,	SDL_PIXELFORMAT_IYUV},
	{AV_PIX_FMT_YUVJ420P,	SDL_PIXELFORMAT_IYUV},
	{AV_PIX_FMT_NV12,	SDL_PIXELFORMAT_NV12},
	{AV_PIX_FMT_NV21,	SDL_PIXELFORMAT_NV21},
	{AV_PIX_FMT_YUYV422,	SDL_PIXELFORMAT_YUY2},
	{AV_PIX_FMT_UYVY422,	SDL_PIXELFORMAT_UYVY},
	{AV_PIX_FMT_YVYU422,	SDL_PIXELFORMAT_YVYU},
	{AV_PIX_FMT_RGB24,	SDL_PIXELFORMAT_RGB888},
	{AV_PIX_FMT_BGR24,	SDL_PIXELFORMAT_BGR888},

	// Planar 16bpp YUV needs to be converted to packed YUYV
	{AV_PIX_FMT_YUVJ422P,	SDL_PIXELFORMAT_YUY2},

	// Y8 grayscale, easiest to just fill in Y with neutral U/V
	{AV_PIX_FMT_GRAY8,	SDL_PIXELFORMAT_IYUV},
};

class SDVRClientSDL final : public DecodingSDVRClient {
public:

	explicit SDVRClientSDL(const SDVRClientSDL&) = delete;
	explicit SDVRClientSDL(std::string shm_path) :
		DecodingSDVRClient(shm_path),
		window_(nullptr) {}

	static uint32_t lavc_pixfmt_to_sdl(int format)
	{
		auto v = static_cast<enum AVPixelFormat>(format);
		auto it = lavc_to_sdl.find(v);
		if (it == lavc_to_sdl.end())
			throw std::runtime_error("Unsupported lavc pix_fmt!");

		return it->second;
	}

	/*
	 * Convert 16bpp planar YUV to packed YUYV or YVYU (depending on input).
	 */
	static void yuv16_planar_to_packed(void *rawdata, int width, int height)
	{
		int y_index = 0, u_index = 0, v_index = 0;
		uint8_t tmp_v[width * height / 2];
		uint8_t tmp_u[width * height / 2];
		uint8_t tmp_y[width * height];
		uint8_t *data;
		int i;

		data = reinterpret_cast<uint8_t *>(rawdata);
		memcpy(tmp_y, data, width * height);
		memcpy(tmp_u, data + width * height, width * height / 2);
		memcpy(tmp_v, data + width * height + width * height / 2,
		       width * height / 2);

		for (i = 0; i < width * height * 2; i += 4) {
			data[i + 0] = tmp_y[y_index++];
			data[i + 1] = tmp_u[u_index++];
			data[i + 2] = tmp_y[y_index++];
			data[i + 3] = tmp_v[v_index++];
		}
	}

	static void draw_frame(SDL_Renderer *r, SDL_Texture *t, AVFrame *f)
	{
		uint8_t *tmp;
		void *ptr;
		int pitch;

		if (SDL_LockTexture(t, nullptr, (void **)&ptr, &pitch))
			return;

		tmp = reinterpret_cast<uint8_t *>(ptr);
		switch (f->format) {
		case AV_PIX_FMT_YUVJ422P:
			memcpy(tmp, f->data[0], f->height * f->width);
			tmp += f->height * f->width;
			memcpy(tmp, f->data[1], f->height * f->width / 2);
			tmp += f->height * f->width / 2;
			memcpy(tmp, f->data[2], f->height * f->width / 2);
			yuv16_planar_to_packed(ptr, f->width, f->height);
			break;

		case AV_PIX_FMT_YUVJ420P:
		case AV_PIX_FMT_YUV420P:
			memcpy(tmp, f->data[0], f->height * f->width);
			tmp += f->height * f->width;
			memcpy(tmp, f->data[1], f->height * f->width / 4);
			tmp += f->height * f->width / 4;
			memcpy(tmp, f->data[2], f->height * f->width / 4);
			break;

		case AV_PIX_FMT_GRAY8:
			memcpy(tmp, f->data[0], f->height * f->width);
			tmp += f->height * f->width;
			memset(tmp, 127, f->height * f->width / 4);
			tmp += f->height * f->width / 4;
			memset(tmp, 127, f->height * f->width / 4);
			break;

		case AV_PIX_FMT_YUYV422:
		case AV_PIX_FMT_UYVY422:
		case AV_PIX_FMT_YVYU422:
			memcpy(tmp, f->data[0], f->height * f->width +
						f->height * f->width / 2 * 2);
			break;

		default:
			memcpy(ptr, f->data[0], f->height * f->width);
			break;
		}

		SDL_UnlockTexture(t);
		SDL_RenderCopy(r, t, nullptr, nullptr);
		SDL_RenderPresent(r);
	}

	static void create_window(SDL_Window **w, SDL_Renderer **r,
				  SDL_Texture **t, const char *name, int y,
				  int x, uint32_t f)
	{
		*w = SDL_CreateWindow(name, 10, 10, y, x, SDL_WINDOW_SHOWN);
		*r = SDL_CreateRenderer(*w, -1, 0);
		*t = SDL_CreateTexture(*r, f, SDL_TEXTUREACCESS_STREAMING, y, x);
	}

	void poll() override
	{
		SDL_Event evt;

		if (!window_)
			return;

		while (SDL_PollEvent(&evt)) {
			switch (evt.type) {
			case SDL_APP_TERMINATING:
			case SDL_QUIT:
				// FIXME
				kill(getppid(), SIGKILL);
				raise(SIGKILL);
			}
		}
	}

	void process_decoded(AVFrame *frame) final
	{
		if (!window_) {
			sdl_fmt_ = lavc_pixfmt_to_sdl(frame->format);
			create_window(&window_, &renderer_, &texture_,
				      desc()->name, desc()->width,
				      desc()->height, sdl_fmt_);
		}

		draw_frame(renderer_, texture_, frame);
	}

private:

	uint32_t sdl_fmt_;
	SDL_Window *window_;
	SDL_Renderer *renderer_;
	SDL_Texture *texture_;
};

int main(void)
{
	sigset_t set;
	int num;

	sigemptyset(&set);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGINT);
	sigprocmask(SIG_BLOCK, &set, nullptr);

	SDVRFactory<SDVRClientSDL> factory(true);
	factory.start();
	sigwait(&set, &num);
	factory.stop();
	return 0;
}

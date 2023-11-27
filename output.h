/*
 * C++ library for consuming data from SDVR
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

#include "ring.h"

#include <cerrno>
#include <csignal>
#include <cstring>
#include <functional>
#include <stdexcept>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <utility>

extern "C" {
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <linux/videodev2.h>
#include "libavcodec/avcodec.h"
};

#define futex(...) syscall(SYS_futex, __VA_ARGS__)

class SDVRClientBase {
public:

	virtual void init() {};
	virtual void poll() {};
	virtual void process(struct shm_ring_head *head, uint8_t *data) = 0;
	virtual void deinit() {};

	SDVRClientBase(const SDVRClientBase&) = delete;
	explicit SDVRClientBase(std::string shm_path)
	{
		struct stat s;

		ring_fd_ = shm_open(shm_path.c_str(), O_RDONLY, 0);

		if (ring_fd_ == -1)
			throw std::system_error(errno, std::generic_category());

		if (fstat(ring_fd_, &s))
			throw std::system_error(errno, std::generic_category());

		ring_mmap_ = mmap(nullptr, s.st_size, PROT_READ, MAP_SHARED,
				  ring_fd_, 0);

		if (ring_mmap_ == MAP_FAILED)
			throw std::system_error(errno, std::generic_category());

		ring_ = reinterpret_cast<struct shm_ring *>(ring_mmap_);
		cp_buf_ = (uint8_t *)malloc(desc()->ring_size);

		if (!cp_buf_)
			throw std::bad_alloc();

		ctr_frames_ = 0;
		last_ctr_ = 0;
		last_off_ = 0;
		stop_ = false;
	}

	~SDVRClientBase()
	{
		if (cb_thread_.joinable())
			std::terminate();

		munmap(ring_mmap_, desc()->ring_size);
		close(ring_fd_);
		free(cp_buf_);
	}

	void start()
	{
		if (cb_thread_.joinable())
			throw std::runtime_error("Double start!");

		init();

		auto run = [this] { while (!stop_) work(); };
		cb_thread_ = std::thread(run);
	}

	void stop()
	{
		if (!cb_thread_.joinable())
			throw std::runtime_error("Not started!");

		stop_ = true;
		tgkill(getpid(), cb_thread_.native_handle(), SIGUSR1);
		cb_thread_.join();

		deinit();
	}

	struct shm_ring_desc *desc() noexcept
	{
		asm volatile ("" ::: "memory"); // barrier()
		return &ring_->desc;
	}

private:

	uint64_t tail_offset() noexcept
	{
		uint64_t ret = desc()->tail_offset;
		asm volatile ("" ::: "memory"); // smp_rmb()
		return ret;
	}

	void ring_read(uint8_t *out, uint64_t off, uint64_t len)
	{
		asm volatile ("" ::: "memory"); // smp_rmb()

		for (uint64_t i = 0; i < len; off++, i++)
			out[i] = ring_->ring[off % desc()->ring_size];
	}

	void work()
	{
		uint32_t f_gen, f_ctr = desc()->ctr;
		struct timespec t1 = {
			.tv_sec = 1,
			.tv_nsec = 0,
		};

		while (last_ctr_ == f_ctr) {
			poll();
			futex(&desc()->ctr, FUTEX_WAIT, f_ctr, &t1, NULL, 0);
			f_ctr = desc()->ctr;
		}

		if (tail_offset() > last_off_)
			last_off_ = tail_offset();

		while (1) {
			struct timespec t2 = {
				.tv_sec = 0,
				.tv_nsec = 50L * 1000 * 1000,
			};
			int r;

			do {
				f_gen = desc()->gen;
				ring_read(reinterpret_cast<uint8_t *>(&cp_head_),
					  last_off_, sizeof(cp_head_));

				if (tail_offset() > last_off_)
					return;

			} while (desc()->gen != f_gen);

			if (cp_head_.written_len == cp_head_.frame_len
			    || desc()->ctr != cp_head_.ring_ctr)
				break;

			poll();
			r = futex(&desc()->gen, FUTEX_WAIT, f_gen, &t2, NULL, 0);
			if (r == -1 && errno == ETIMEDOUT)
				break;
		}

		if (tail_offset() > last_off_)
			return;

		ring_read(cp_buf_, last_off_ + sizeof(cp_head_),
			  cp_head_.frame_len);

		if (tail_offset() > last_off_)
			return;

		poll();
		process(&cp_head_, cp_buf_);

		last_off_ += cp_head_.frame_len + sizeof(cp_head_);
		last_ctr_ = cp_head_.ring_ctr;
		ctr_frames_++;
	}

	int ring_fd_;
	void *ring_mmap_;

	struct shm_ring *ring_;
	struct shm_ring_head cp_head_;
	uint32_t last_ctr_;
	uint64_t last_off_;
	uint8_t *cp_buf_;

	uint64_t ctr_frames_;

	bool stop_;
	std::thread cb_thread_;
};

static const std::unordered_map<uint32_t, enum AVCodecID> codec_lookup = {
	{V4L2_PIX_FMT_MJPEG,	AV_CODEC_ID_MJPEG},
	{V4L2_PIX_FMT_H264,	AV_CODEC_ID_H264},
};

static const std::unordered_map<uint32_t, enum AVPixelFormat> pixfmt_lookup = {
	{V4L2_PIX_FMT_YUV420,	AV_PIX_FMT_YUV420P},
	{V4L2_PIX_FMT_NV12,	AV_PIX_FMT_NV12},
	{V4L2_PIX_FMT_NV21,	AV_PIX_FMT_NV21},
	{V4L2_PIX_FMT_YUYV,	AV_PIX_FMT_YUYV422},
	{V4L2_PIX_FMT_UYVY,	AV_PIX_FMT_UYVY422},
	{V4L2_PIX_FMT_YVYU,	AV_PIX_FMT_YVYU422},
	{V4L2_PIX_FMT_RGB24,	AV_PIX_FMT_RGB24},
	{V4L2_PIX_FMT_BGR24,	AV_PIX_FMT_BGR24},
	{V4L2_PIX_FMT_GREY,	AV_PIX_FMT_GRAY8},
};

class DecodingSDVRClient : public SDVRClientBase {
public:

	virtual void process_decoded(AVFrame *frame) = 0;

	explicit DecodingSDVRClient(const DecodingSDVRClient&) = delete;
	explicit DecodingSDVRClient(std::string shm_path) : SDVRClientBase(shm_path)
	{
		lavc_codec_ = v4l2_pixfmt_to_lavc_codec(desc()->pixelformat);

		// Fow RAWVIDEO formats, no need to involve libavcodec at all.
		if (lavc_codec_ == AV_CODEC_ID_RAWVIDEO) {
			codec_ = nullptr;
			return;
		}

		codec_ = avcodec_find_decoder(lavc_codec_);
		if (!codec_)
			throw std::runtime_error("No codec!");

		pctx_ = av_parser_init(lavc_codec_);
		ctx_ = avcodec_alloc_context3(codec_);
		ctx_->get_format = this->get_format;

		if (codec_->capabilities & AV_CODEC_CAP_TRUNCATED)
			ctx_->flags |= AV_CODEC_FLAG_TRUNCATED;

		if (avcodec_open2(ctx_, codec_, nullptr) < 0)
			throw std::runtime_error("Can't open codec!");

		fframe_ = av_frame_alloc();
		pkt_ = av_packet_alloc();
	}

	~DecodingSDVRClient()
	{
		av_packet_free(&pkt_);
		av_frame_free(&fframe_);
		av_parser_close(pctx_);
		avcodec_free_context(&ctx_);
	}

	static enum AVPixelFormat v4l2_pixfmt_to_lavc_pixfmt(uint32_t format)
	{
		auto it = pixfmt_lookup.find(format);
		if (it == pixfmt_lookup.end())
			throw std::runtime_error("Unknown V4L2 format!");

		return it->second;
	}

	static enum AVCodecID v4l2_pixfmt_to_lavc_codec(uint32_t format)
	{
		auto it = codec_lookup.find(format);
		if (it == codec_lookup.end())
			return AV_CODEC_ID_RAWVIDEO;

		return it->second;
	}

	/*
	 * This callback called by libavcodec, with an array of supported
	 * output pixel formats (terminated by a '-1'). We prefer formats that
	 * libsdl2 supports natively.
	 */
	static enum AVPixelFormat get_format(struct AVCodecContext *c,
					     const enum AVPixelFormat *fmt)
	{
		const enum AVPixelFormat *cur = fmt;
		(void) c;

		do {
			switch (*cur) {
			case AV_PIX_FMT_YUV420P:
			case AV_PIX_FMT_YUVJ420P:
			case AV_PIX_FMT_NV12:
			case AV_PIX_FMT_NV21:
			case AV_PIX_FMT_YUYV422:
			case AV_PIX_FMT_UYVY422:
			case AV_PIX_FMT_YVYU422:
			case AV_PIX_FMT_RGB24:
			case AV_PIX_FMT_BGR24:
				return *cur;

			default:
				continue;
			}

		} while (*cur++ != -1);

		cur = fmt;
		do {
			switch (*cur) {
			case AV_PIX_FMT_YUVJ422P:
				return *cur;

			default:
				continue;
			}

		} while (*cur++ != -1);

		throw std::runtime_error("No supported pixel formats!");
	}

	void process(struct shm_ring_head *head, uint8_t *in_data) final
	{
		int in_len = head->frame_len;

		if (!codec_) {
			process_decoded(fframe_); // FIXME
			return;
		}

		while (in_len >= 0) {
			int len, r;

			len = av_parser_parse2(pctx_, ctx_, &pkt_->data,
					       &pkt_->size, in_data, in_len,
					       AV_NOPTS_VALUE, AV_NOPTS_VALUE, 0);

			in_len -= len;
			in_data += len;

			if (!pkt_->size) {
				if (!len && !in_len)
					break;

				continue;
			}

resend_packet:
			r = avcodec_send_packet(ctx_, pkt_);

			while (!avcodec_receive_frame(ctx_, fframe_))
				process_decoded(fframe_);

			if (r == AVERROR(EAGAIN))
				goto resend_packet;
		}
	}

private:

	enum AVCodecID lavc_codec_;
	AVCodecParserContext *pctx_;
	const AVCodec *codec_;
	AVCodecContext *ctx_;
	AVFrame *fframe_;
	AVPacket *pkt_;
};

/*
 * Makes a T for every camera that connects
 */

template<class T>
class SDVRFactory final {
public:

	SDVRFactory(const SDVRFactory&) = delete;
	explicit SDVRFactory(bool forking = false) : forking_(forking)
	{
		dir_fd_ = shm_open(SDVR_SHM_DIR_NAME, O_RDONLY, 0);
		if (dir_fd_ == -1)
			throw std::system_error(errno, std::generic_category());

		dir_mmap_ = mmap(nullptr, 4096, PROT_READ, MAP_SHARED, dir_fd_, 0);
		if (dir_mmap_ == MAP_FAILED)
			throw std::system_error(errno, std::generic_category());

		cp_dir_ = (struct shm_ring_dir *)malloc(32768); // FIXME
		if (cp_dir_ == nullptr)
			throw std::bad_alloc();

		dir_ = reinterpret_cast<struct shm_ring_dir *>(dir_mmap_);
		last_gen_ = 0;
		stop_ = false;
	}

	~SDVRFactory()
	{
		if (watch_thread_.joinable())
			abort();

		munmap(dir_mmap_, 4096);
		close(dir_fd_);
		free(cp_dir_);
	}

	void start()
	{
		if (watch_thread_.joinable())
			throw std::runtime_error("Double start!");

		auto run = [this] { while (!stop_) work(); };
		watch_thread_ = std::thread(run);
	}

	void stop()
	{
		if (!watch_thread_.joinable())
			throw std::runtime_error("Not started!");

		stop_ = true;
		tgkill(getpid(), watch_thread_.native_handle(), SIGUSR1);
		watch_thread_.join();

		if (forking_) {
			for (const auto& i: fork_map_) {
				kill(i.second, SIGTERM);
				waitpid(i.second, NULL, WEXITED);
			}

		} else {
			for (auto& i : thread_map_)
				i.second.stop();
		}

		fork_map_.clear();
		thread_map_.clear();
	}

private:

	void work()
	{
		uint32_t i, f_gen = dir_->desc.gen;

		if (f_gen == last_gen_)
			futex(&dir_->desc.gen, FUTEX_WAIT, f_gen, nullptr, nullptr, 0);

		do {
			memcpy(cp_dir_, dir_, sizeof(*dir_) +
			       dir_->desc.len * sizeof(struct shm_ring_dir_ent));

			asm volatile ("" ::: "memory"); // smp_rmb()
		} while (cp_dir_->desc.gen != dir_->desc.gen);

		for (i = 0; i < cp_dir_->desc.len; i++) {
			struct shm_ring_dir_ent *ent = cp_dir_->ents + i;
			std::string path = std::string(ent->shm_path);

			if (forking_) {
				auto it = fork_map_.find(path);

				if (!ent->is_active) {
					if (it == fork_map_.end())
						continue;

					kill(it->second, SIGTERM);
					fork_map_.erase(it->first);
					continue;
				}

				if (it == fork_map_.end()) {
					pid_t pid = fork();
					sigset_t set;
					int num;

					if (pid == -1)
						continue;

					if (pid != 0) {
						fork_map_.emplace(path, pid);
						continue;
					}

					sigemptyset(&set);
					sigaddset(&set, SIGTERM);
					sigprocmask(SIG_BLOCK, &set, nullptr);

					try {
						T newobj(path);
						newobj.start();
						sigwait(&set, &num);
						newobj.stop();

					} catch (const std::exception& e) {
						_exit(1);

					} catch (...) {
						_exit(2);
					}

					_exit(0);
				}

			} else {
				auto it = thread_map_.find(path);

				if (!ent->is_active) {
					if (it == thread_map_.end())
						continue;

					it->second.stop();
					thread_map_.erase(it->first);
					continue;
				}

				if (it == thread_map_.end()) {
					auto r = thread_map_.emplace(path, path);
					r.first->second.start();
				}
			}
		}

		last_gen_ = f_gen;
	}

	const bool forking_;
	std::unordered_map<std::string, T> thread_map_;
	std::unordered_map<std::string, pid_t> fork_map_;
	struct shm_ring_dir *cp_dir_;
	struct shm_ring_dir *dir_;
	uint32_t last_gen_;
	void *dir_mmap_;
	int dir_fd_;

	bool stop_;
	std::thread watch_thread_;
};

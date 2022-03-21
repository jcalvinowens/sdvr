#include "ring.h"

#include <cerrno>
#include <csignal>
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
#include <sys/syscall.h>
#include <linux/futex.h>
};

//
// I am lazy
//

#define futex(...) syscall(SYS_futex, __VA_ARGS__)

//
// Convenience wrapper for frame data
//

struct SDVRFrame final {

	SDVRFrame(struct shm_ring_head *head, uint8_t *data)
		: head_(head), data_(data) {};

	struct shm_ring_head* head_;
	uint8_t* data_;
};

//
// Derive this to do things with frame data
//

class SDVRClient {
public:

	explicit SDVRClient(std::string shm_path) {
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
		cp_buf_ = (uint8_t *)malloc(desc().ring_size);

		if (cp_buf_ == nullptr)
			throw std::bad_alloc();

		last_frame_seq_ = 0;
		last_off_ = 0;
		stop_ = false;
	}

	SDVRClient(const SDVRClient&) = delete;

	void start() {

		if (cb_thread_.joinable())
			throw std::runtime_error("Double start!");

		init();

		auto run = [this] { while (!stop_) work(); };
		cb_thread_ = std::thread(run);
	}

	virtual void init() {};
	virtual void call(SDVRFrame&) = 0;
	virtual void deinit() {};

	void stop() {

		if (!cb_thread_.joinable())
			throw std::runtime_error("Not started!");

		stop_ = true;
		tgkill(getpid(), cb_thread_.native_handle(), SIGUSR1);
		cb_thread_.join();

		deinit();
	}

	struct shm_ring_desc& desc() noexcept {
		return ring_->desc;
	}

	~SDVRClient() {

		if (cb_thread_.joinable())
			std::terminate();

		munmap(ring_mmap_, desc().ring_size);
		close(ring_fd_);
		free(cp_buf_);
	}

private:

	void ring_read(uint8_t *out, uint64_t off, uint64_t len) {

		for (uint64_t i = 0; i < len; off++, i++)
			out[i] = ring_->ring[off % desc().ring_size];
	}

	void work() {
		uint32_t f_ctr = desc().ctr;

		if (f_ctr == last_frame_seq_ + 1)
			futex(&desc().ctr, FUTEX_WAIT, f_ctr, nullptr, nullptr, 0);

		ctr_frames_++;

		ring_read(reinterpret_cast<uint8_t *>(&cp_head_),
			  last_off_, sizeof(cp_head_));

		if (desc().tail_offset > last_off_) {
			last_off_ = desc().tail_offset;
			ctr_drops_++;
			return;
		}

		ring_read(cp_buf_, last_off_ + sizeof(cp_head_),
			  cp_head_.frame_len);

		if (desc().tail_offset > last_off_) {
			last_off_ = desc().tail_offset;
			ctr_drops_++;
			return;
		}

		auto frame = SDVRFrame(&cp_head_, cp_buf_);
		call(frame);

		last_off_ += cp_head_.frame_len + sizeof(cp_head_);
		last_frame_seq_ = cp_head_.frame_seq + 1;
	}

	int ring_fd_;
	void *ring_mmap_;

	struct shm_ring *ring_;
	struct shm_ring_head cp_head_;
	uint32_t last_frame_seq_;
	uint64_t last_off_;
	uint8_t *cp_buf_;

	uint64_t ctr_frames_;
	uint64_t ctr_drops_;

	bool stop_;
	std::thread cb_thread_;
};

//
// Makes a T for every camera that connects
//

template<class T>
class SDVRFactory final {
public:
	SDVRFactory() {

		dir_fd_ = shm_open(SDVR_SHM_DIR_NAME, O_RDONLY, 0);
		if (dir_fd_ == -1)
			throw std::system_error(errno, std::generic_category());

		dir_mmap_ = mmap(nullptr, 4096, PROT_READ, MAP_SHARED, dir_fd_, 0);
		if (dir_mmap_ == MAP_FAILED)
			throw std::system_error(errno, std::generic_category());

		dir_ = reinterpret_cast<struct shm_ring_dir *>(dir_mmap_);
		last_gen_ = UINT32_MAX;
		stop_ = false;
	}

	SDVRFactory(const SDVRFactory&) = delete;

	void start() {

		if (watch_thread_.joinable())
			throw std::runtime_error("Double start!");

		auto run = [this] { while (!stop_) work(); };
		watch_thread_ = std::thread(run);
	}

	void stop() {

		if (!watch_thread_.joinable())
			throw std::runtime_error("Not started!");

		stop_ = true;
		tgkill(getpid(), watch_thread_.native_handle(), SIGUSR1);
		watch_thread_.join();
	}

	~SDVRFactory() {
		if (watch_thread_.joinable())
			std::terminate();

		munmap(dir_mmap_, 4096);
		close(dir_fd_);
	}

private:

	void work() {
		uint32_t f_gen, i;

		do { f_gen = dir_->desc.gen; } while (f_gen & 1);

		if (f_gen == last_gen_)
			futex(&dir_->desc.gen, FUTEX_WAIT, f_gen, nullptr, nullptr, 0);

		for (i = 0; i < dir_->desc.len; i++) {
			struct shm_ring_dir_ent *ent = dir_->ents + i;
			std::string path = std::string(ent->shm_path);
			auto it = map_.find(path);

			if (!ent->is_active) {
				if (it == map_.end())
					continue;

				it->second.stop();
				map_.erase(it->first);
				continue;
			}

			if (it == map_.end()) {
				auto r = map_.emplace(path, path);
				r.first->second.start();
			}
		}

		last_gen_ = f_gen;
	}

	std::unordered_map<std::string, T> map_;
	struct shm_ring_dir *dir_;
	uint32_t last_gen_;
	void *dir_mmap_;
	int dir_fd_;

	bool stop_;
	std::thread watch_thread_;
};

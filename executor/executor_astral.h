// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <astral/syscall.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <fcntl.h>

static void os_init(int argc, char** argv, void* data, size_t data_size)
{
	int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
	int flags = MAP_ANON | MAP_PRIVATE | MAP_FIXED_NOREPLACE;

	void* got = mmap(data, data_size, prot, flags, -1, 0);
	if (data != got)
		failmsg("failed to map executor data", "want %p, got %p", data, got);

	is_kernel_64_bit = true;
}

static intptr_t execute_syscall(const call_t* c, intptr_t a[kMaxArgs])
{
	if (c->call)
		return c->call(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);

	long ret;
	long error = syscall(c->sys_nr, &ret, a[0], a[1], a[2], a[3], a[4], a[5]);
	// The executor expects the libc convention: -1 and errno on failure.
	if (error) {
		errno = error;
		return -1;
	}
	return ret;
}
#define KCOV_REQUEST_START 0xF1177000
#define KCOV_REQUEST_STOP 0xF1177100
#define KCOV_REQUEST_SET_SIZE 0xF1177200

static void cover_open(cover_t* cov, bool extra)
{
	int fd = open("/dev/kcov", O_RDWR);
	if (fd == -1)
		fail("open of /dev/kcov failed");

	if (dup2(fd, cov->fd) < 0)
		failmsg("failed to dup cover fd", "from=%d, to=%d", fd, cov->fd);
	close(fd);

	int size = kCoverSize;
	if (ioctl(cov->fd, KCOV_REQUEST_SET_SIZE, &size))
		fail("ioctl init trace write failed");

	cov->data_size = (kCoverSize + 1) * 8;
}

static void cover_mmap(cover_t* cov)
{
	if (cov->mmap_alloc_ptr != NULL)
		fail("cover_mmap invoked on an already mmapped cover_t object");

	cov->mmap_alloc_size = cov->data_size;
	void* mmap_ptr = mmap(NULL, cov->mmap_alloc_size, PROT_READ | PROT_WRITE,
			      MAP_SHARED, cov->fd, 0);

	if (mmap_ptr == MAP_FAILED)
		fail("cover mmap failed");

	cov->mmap_alloc_ptr = (char*)mmap_ptr;
	cov->data = (char*)mmap_ptr;
	cov->data_end = cov->data + cov->mmap_alloc_size;
	cov->data_offset = sizeof(uint64_t);
	cov->pc_offset = 0;
}

static void cover_protect(cover_t* cov)
{
	if (cov->mmap_alloc_ptr == NULL)
		fail("cover_protect invoked on an unmapped cover_t object");

	size_t mmap_alloc_size = (kCoverSize + 1) * 8;
	long page_size = sysconf(_SC_PAGESIZE);
	if (page_size > 0)
		mprotect(cov->mmap_alloc_ptr + page_size, mmap_alloc_size - page_size,
			 PROT_READ);
}

static void cover_unprotect(cover_t* cov)
{
	if (cov == nullptr)
		fail("cover_unprotect invoked without cover_t");

	if (cov->mmap_alloc_ptr == NULL)
		fail("cover_unprotect invoked on an unmapped cover_t object");

	size_t mmap_alloc_size = (kCoverSize + 1) * 8;
	mprotect(cov->mmap_alloc_ptr, mmap_alloc_size, PROT_READ | PROT_WRITE);
}

#define KCOV_MODE_PC 1
#define KCOV_MODE_CMP 2
static void cover_enable(cover_t* cov, bool collect_comps, bool extra)
{
	int kcov_mode = collect_comps ? KCOV_MODE_CMP : KCOV_MODE_PC;
	if (ioctl(cov->fd, KCOV_REQUEST_START, &kcov_mode))
		failmsg("cover enable write trace failed", "fd=%d, mode=%d", cov->fd, kcov_mode);
}

static void cover_reset(cover_t* cov)
{
	*(uint64*)cov->data = 0;
}

static void cover_collect(cover_t* cov)
{
	cov->size = *(uint64*)cov->data;
}

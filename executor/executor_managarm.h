#include <errno.h>
#include <hel-syscalls.h>
#include <hel.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

static void os_init(int argc, char** argv, void* data, size_t data_size)
{
	int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
	int flags = MAP_ANON | MAP_PRIVATE | MAP_FIXED_NOREPLACE;
	void* got = mmap(data, data_size, prot, flags, -1, 0);
	if (data != got)
		failmsg("mmap of data segment failed", "want %p, got %p", data, got);
	is_kernel_64_bit = true;
}

#define SYZ_HAVE_FEATURES 1

static const char* setup_unsupported()
{
	return "not supported on managarm";
}

static feature_t features[] = {
    {rpc::Feature::ExtraCoverage, setup_unsupported},
    {rpc::Feature::KcovResetIoctl, setup_unsupported},
    {rpc::Feature::Fault, setup_unsupported},
    {rpc::Feature::Leak, setup_unsupported},
    {rpc::Feature::NetInjection, setup_unsupported},
    {rpc::Feature::NetDevices, setup_unsupported},
    {rpc::Feature::KCSAN, setup_unsupported},
    {rpc::Feature::DevlinkPCI, setup_unsupported},
    {rpc::Feature::NicVF, setup_unsupported},
    {rpc::Feature::USBEmulation, setup_unsupported},
    {rpc::Feature::VhciInjection, setup_unsupported},
    {rpc::Feature::WifiEmulation, setup_unsupported},
    {rpc::Feature::LRWPANEmulation, setup_unsupported},
    {rpc::Feature::BinFmtMisc, setup_unsupported},
    {rpc::Feature::Swap, setup_unsupported},
    {rpc::Feature::MemoryDump, setup_unsupported},
};

static void setup_sysctl()
{
}

static void setup_cgroups()
{
}

static intptr_t execute_syscall(const call_t* c, intptr_t a[kMaxArgs])
{
	if (c->call == nullptr)
		failmsg("managarm call has no entry point", "call=%s", c->name);
	intptr_t res = c->call(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
	if (strncmp(c->name, "syz_", 4) == 0)
		return res;

	HelError error = (HelError)res;
	if (error != kHelErrNone) {
		errno = error;
		return -1;
	}
	return 0;
}

#define KCOV_REQUEST_START 0xF1177000
#define KCOV_REQUEST_STOP 0xF1177100
#define KCOV_REQUEST_SET_SIZE 0xF1177200

#define KCOV_MODE_PC 1
#define KCOV_MODE_CMP 2

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
		fail("cover set size failed");
	cov->data_size = (kCoverSize + 1) * sizeof(uint64);
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
	cov->data_offset = sizeof(uint64);
	cov->pc_offset = 0;
}

static void cover_protect(cover_t* cov)
{
	if (cov->mmap_alloc_ptr == NULL)
		fail("cover_protect invoked on an unmapped cover_t object");
	long page_size = sysconf(_SC_PAGESIZE);
	if (page_size > 0)
		mprotect(cov->mmap_alloc_ptr + page_size, cov->mmap_alloc_size - page_size,
			 PROT_READ);
}

static void cover_unprotect(cover_t* cov)
{
	if (cov->mmap_alloc_ptr == NULL)
		fail("cover_unprotect invoked on an unmapped cover_t object");
	mprotect(cov->mmap_alloc_ptr, cov->mmap_alloc_size, PROT_READ | PROT_WRITE);
}

static void cover_enable(cover_t* cov, bool collect_comps, bool extra)
{
	int mode = collect_comps ? KCOV_MODE_CMP : KCOV_MODE_PC;
	if (ioctl(cov->fd, KCOV_REQUEST_START, &mode))
		failmsg("cover enable failed", "fd=%d, mode=%d", cov->fd, mode);
}

static void cover_reset(cover_t* cov)
{
	*(uint64*)cov->data = 0;
}

static void cover_collect(cover_t* cov)
{
	cov->size = *(uint64*)cov->data;
}

#include <errno.h>
#include <hel-syscalls.h>
#include <hel.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

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

static void cover_open(cover_t* cov, bool extra)
{
	(void)kCoverSize;
	fail("coverage is not supported on managarm");
}

static void cover_enable(cover_t* cov, bool collect_comps, bool extra)
{
}

static void cover_reset(cover_t* cov)
{
}

static void cover_collect(cover_t* cov)
{
}

static void cover_protect(cover_t* cov)
{
}

static void cover_mmap(cover_t* cov)
{
}

static void cover_unprotect(cover_t* cov)
{
}

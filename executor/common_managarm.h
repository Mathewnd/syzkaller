#include <hel-syscalls.h>
#include <hel.h>
#include <unistd.h>

// Ugly way to work around gcc's "error: function called through a non-compatible type".
// The macro is used in generated C code.
#define CAST(f) ({void* p = (void*)f; p; })

#if SYZ_EXECUTOR || __NR_syz_mmap
#include <sys/mman.h>

// syz_mmap(addr vma, len len[addr])
static long syz_mmap(volatile long a0, volatile long a1)
{
	return (long)mmap((void*)a0, a1, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0);
}
#endif

#if SYZ_EXECUTOR || __NR_syz_hel_get_process_hierarchy
#include <errno.h>

// Mirrors posix::ManagarmProcessData from managarm's protocols/posix/data.hpp
// (a C++ header, while this file is also compiled as C for reproducers).
struct syz_managarm_process_data {
	HelHandle posix_lane;
	HelHandle mbus_lane;
	void* thread_page;
	HelHandle* file_table;
	void* clock_tracker_page;
	HelHandle hierarchy_handle;
};

// posix::superGetProcessData.
#define SYZ_MANAGARM_SUPER_GET_PROCESS_DATA 1

// syz_hel_get_process_hierarchy() hel_hierarchy
static long syz_hel_get_process_hierarchy(void)
{
	struct syz_managarm_process_data pd;
	HelError error = helSyscall2(kHelCallSuper + SYZ_MANAGARM_SUPER_GET_PROCESS_DATA,
				     (HelWord)&pd, sizeof(pd));
	if (error) {
		errno = error;
		return -1;
	}
	return pd.hierarchy_handle;
}
#endif

#if SYZ_EXECUTOR || SYZ_SANDBOX_NONE
static void loop();
static int do_sandbox_none(void)
{
	loop();
	return 0;
}
#endif

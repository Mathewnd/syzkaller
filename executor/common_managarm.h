#include <hel-syscalls.h>
#include <hel.h>
#include <unistd.h>

// for sys/managarm/posix*.txt
#include <dirent.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/file.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/pidfd.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <termios.h>
#include <time.h>

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

#if SYZ_EXECUTOR || __NR_syz_fork
// syz_fork() pid
static long syz_fork(void)
{
	pid_t pid = fork();
	if (pid)
		return pid;
	usleep(100 * 1000);
	_exit(0);
}
#endif

#if SYZ_EXECUTOR || __NR_syz_open_pts
// syz_open_pts(fd fd_tty, flags flags[open_flags]) fd_tty
static long syz_open_pts(volatile long a0, volatile long a1)
{
	int ptyno = 0;
	if (ioctl(a0, TIOCGPTN, &ptyno))
		return -1;
	char buf[64];
	snprintf(buf, sizeof(buf), "/dev/pts/%d", ptyno);
	return open(buf, a1, 0);
}
#endif

#if SYZ_EXECUTOR || __NR_syz_sighandler
static void syz_nop_sighandler(int sig)
{
	(void)sig;
}

// syz_sighandler() sighandler
static long syz_sighandler(void)
{
	return (long)syz_nop_sighandler;
}
#endif

#if SYZ_EXECUTOR || SYZ_REPEAT
#define SYZ_HAVE_SETUP_TEST 1
static void setup_test()
{
	prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
	setsid();
}
#endif

#if SYZ_EXECUTOR || SYZ_SANDBOX_NONE
#include <sys/sysmacros.h>

// As managarm does not support namespaces and there are no permission checks currently,
// we need to be more careful as to not delete important files like libc. Because of that,
// we will run the fuzzer in a chroot jail in a tmpfs.

static void sandbox_mknod(const char* path, int major, int minor)
{
	if (mknod(path, S_IFCHR | 0666, makedev(major, minor)))
		failmsg("sandbox: mknod failed", "path=%s", path);
}

static void sandbox_mount(const char* fstype, const char* path)
{
	if (mkdir(path, 0755))
		failmsg("sandbox: mkdir failed", "path=%s", path);
	if (mount("none", path, fstype, 0, NULL))
		failmsg("sandbox: mount failed", "fstype=%s path=%s", fstype, path);
}

static void sandbox_chroot(void)
{
	char root[] = "./syz-root.XXXXXX";
	if (!mkdtemp(root))
		fail("sandbox: mkdtemp failed");
	if (mount("none", root, "tmpfs", 0, NULL))
		fail("sandbox: mounting tmpfs failed");
	if (chdir(root))
		fail("sandbox: chdir failed");
	if (mkdir("dev", 0755))
		fail("sandbox: mkdir failed");

	// We won't mount the real /dev because that has disks etc.
	sandbox_mknod("dev/null", 1, 3);
	sandbox_mknod("dev/zero", 1, 5);
	sandbox_mknod("dev/full", 1, 7);
	sandbox_mknod("dev/random", 1, 8);
	sandbox_mknod("dev/urandom", 1, 9);
	sandbox_mknod("dev/tty", 5, 0);
	sandbox_mknod("dev/ptmx", 5, 2);
	sandbox_mount("devpts", "dev/pts");
	sandbox_mount("proc", "proc");
	if (chroot("."))
		fail("sandbox: chroot failed");
	if (chdir("/"))
		fail("sandbox: chdir failed");
}

static void loop();
static int do_sandbox_none(void)
{
	sandbox_chroot();
	loop();
	return 0;
}
#endif

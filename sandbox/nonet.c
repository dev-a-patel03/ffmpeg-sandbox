/* nonet.c: seccomp wrapper that denies sockets and process creation, then execs the tool. */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <dirent.h>
#include <stdlib.h>

#if defined(__x86_64__)
#define NATIVE_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define NATIVE_ARCH AUDIT_ARCH_AARCH64
#else
#error "unsupported arch (x86-64 and aarch64 only)"
#endif

#define DENY BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EACCES)
#define ALLOW BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

#ifndef __NR_close_range
#if defined(__x86_64__) || defined(__aarch64__)
#define __NR_close_range 436  /* same number on both arches */
#endif
#endif

#ifndef __NR_io_uring_setup
#error "__NR_io_uring_setup missing; update kernel headers"
#endif

#if defined(__x86_64__)
#define X32_SYSCALL_BIT 0x40000000  /* x32 ABI: bit 30 of the syscall nr */
#endif

/* Close fds above the progress pipe (fd 3) so a leaked socket can't be reused. */
static int sanitize_fds(void) {
#if defined(__NR_close_range)
    if (syscall(__NR_close_range, 4, ~0U, 0) == 0)
        return 0;
#endif
    DIR *d = opendir("/proc/self/fd");
    if (!d)
        return -1;
    int dfd = dirfd(d);
    for (struct dirent *e; (e = readdir(d)); ) {
        int fd = atoi(e->d_name);
        if (fd > 3 && fd != dfd)
            close(fd);
    }
    closedir(d);
    return 0;
}

int main(int argc, char **argv) {
    struct sock_filter f[] = {
        /* Reject foreign ABIs, e.g. i386 int 0x80 */
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, NATIVE_ARCH, 1, 0),
        DENY,

        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

#if defined(__x86_64__)
        /* Block the x32 ABI */
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, X32_SYSCALL_BIT, 0, 1),
        DENY,
#endif

        /* Block io_uring_setup: no ring, no IORING_OP_SOCKET */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_io_uring_setup, 0, 1),
        DENY,

        /* Deny socket() for every family, AF_UNIX included */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socket, 0, 1),
        DENY,

        /* socketpair() makes sockets too, so deny it as well */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_socketpair, 0, 1),
        DENY,

        /* Threads only. The filter can't read clone3's flags, so ENOSYS makes libc use clone */
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone3, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS),
#ifdef __NR_fork
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_fork, 0, 1),
        DENY,
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_vfork, 0, 1),
        DENY,
#endif
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, CLONE_THREAD, 1, 0),
        DENY,

        ALLOW,
    };

    struct sock_fprog prog = { .len = sizeof f / sizeof f[0], .filter = f };

    if (argc < 2) {
        fprintf(stderr, "usage: nonet cmd [args]\n");
        return 2;
    }

    if (sanitize_fds()) {
        perror("close inherited fds");
        return 1;
    }

    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("no_new_privs");
        return 1;
    }

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) {
        perror("seccomp");
        return 1;
    }

    execvp(argv[1], argv + 1);
    perror("exec");
    return 127;
}

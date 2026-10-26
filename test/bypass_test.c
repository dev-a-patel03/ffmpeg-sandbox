/* bypass_test.c: try socket() across families and ABIs, plus socketpair() and
 * io_uring. Under nonet every row returns "Permission denied".
 *   ./bypass_test            # baseline
 *   ./nonet ./bypass_test    # sandboxed */
#define _GNU_SOURCE   /* expose syscall() */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef __NR_io_uring_setup
#error "__NR_io_uring_setup missing; update kernel headers"
#endif

#if defined(__x86_64__)
static long i386_socket(void) {
    long ret;
    /* 32-bit int 0x80 socket() (syscall 359) from 64-bit code */
    __asm__ volatile (
        "int $0x80"
        : "=a"(ret)
        : "a"(359), "b"(AF_INET), "c"(SOCK_STREAM), "d"(0)
        : "memory"
    );
    return ret;
}
#endif

int main(void) {
    int s;

    s = socket(AF_INET, SOCK_STREAM, 0);
    printf("native socket(AF_INET):  %s\n", s >= 0 ? "OPENED" : strerror(errno));
    if (s >= 0) close(s);

    s = socket(AF_INET6, SOCK_DGRAM, 0);
    printf("native socket(AF_INET6): %s\n", s >= 0 ? "OPENED" : strerror(errno));
    if (s >= 0) close(s);

    s = socket(AF_NETLINK, SOCK_RAW, 0);
    printf("native socket(AF_NETLINK): %s\n", s >= 0 ? "OPENED" : strerror(errno));
    if (s >= 0) close(s);

    s = socket(AF_UNIX, SOCK_STREAM, 0);
    printf("native socket(AF_UNIX):  %s\n", s >= 0 ? "OPENED" : strerror(errno));
    if (s >= 0) close(s);

    int sv[2];
    s = socketpair(AF_UNIX, SOCK_DGRAM, 0, sv);
    printf("socketpair(AF_UNIX):     %s\n", s == 0 ? "OPENED" : strerror(errno));
    if (s == 0) { close(sv[0]); close(sv[1]); }

#if defined(__x86_64__)
    long r = i386_socket();
    printf("i386 int 0x80 socket:    %s\n", r >= 0 ? "OPENED" : strerror((int)-r));

    /* x32 calls set bit 30 of the syscall number */
    s = syscall(0x40000000 | __NR_socket, AF_INET, SOCK_STREAM, 0);
    printf("x32 socket:              %s\n", s >= 0 ? "OPENED" : strerror(errno));
    if (s >= 0) close(s);
#endif

    char params[120] = {0};
    long u = syscall(__NR_io_uring_setup, 4, params);
    printf("io_uring_setup:          %s\n", u >= 0 ? "OPENED" : strerror(errno));

    return 0;
}

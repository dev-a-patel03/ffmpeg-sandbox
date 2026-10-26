/* socket_probe.c: run under nonet. Exits 42 when socket(), socketpair(), fork() and
 * clone() are all denied with EACCES, 0 if any succeeds, 1 on any other error. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    int sv[2];
    if (socket(AF_INET, SOCK_STREAM, 0) >= 0)
        return 0;
    if (errno != EACCES)
        return 1;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0)
        return 0;
    if (errno != EACCES)
        return 1;
    pid_t pid = fork();
    if (pid == 0)
        _exit(0);
    if (pid > 0)
        return 0;
    if (errno != EACCES)
        return 1;
    /* musl's fork() calls SYS_fork on x86-64, so try clone itself too */
    long c = syscall(SYS_clone, SIGCHLD, 0, 0, 0, 0);
    if (c == 0)
        _exit(0);
    if (c > 0)
        return 0;
    return errno == EACCES ? 42 : 1;
}

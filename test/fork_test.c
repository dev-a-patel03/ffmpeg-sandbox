/* fork_test.c: try each way to start a process, plus a thread. Under nonet only the thread starts.
 *   ./fork_test            # baseline
 *   ./nonet ./fork_test    # sandboxed */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/sched.h>
#include <pthread.h>
#include <signal.h>
#include <spawn.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static void *thread_main(void *arg) { return arg; }

static void report(const char *what, long r) {
    if (r == 0)
        _exit(0);
    printf("%-24s %s\n", what, r > 0 ? "STARTED" : strerror(errno));
    if (r > 0)
        waitpid(r, NULL, 0);
}

int main(void) {
    report("fork():", fork());
#ifdef SYS_fork
    report("raw fork syscall:", syscall(SYS_fork));
#endif
    pid_t pid = vfork();
    if (pid == 0)
        _exit(0);  /* a vfork child may only _exit or exec */
    report("vfork():", pid);
    report("raw clone(SIGCHLD):", syscall(SYS_clone, SIGCHLD, 0, 0, 0, 0));

    struct clone_args ca = { .exit_signal = SIGCHLD };
    report("raw clone3:", syscall(SYS_clone3, &ca, sizeof ca));

    char *av[] = { "true", NULL };
    errno = posix_spawnp(&pid, "true", NULL, NULL, av, environ);
    report("posix_spawn:", errno ? -1 : pid);

    pthread_t t;
    errno = pthread_create(&t, NULL, thread_main, NULL);
    printf("%-24s %s\n", "pthread_create:", errno ? strerror(errno) : "STARTED");
    if (!errno)
        pthread_join(t, NULL);
    return 0;
}

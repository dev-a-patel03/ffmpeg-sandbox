/* fd_probe.c: report whether fds 3, 4, 5 are open. test/fd_test.sh uses it to
 * check nonet closes inherited fds above fd 3 and keeps fd 3. */
#include <fcntl.h>
#include <stdio.h>

int main(void) {
    for (int fd = 3; fd <= 5; fd++)
        printf("fd %d: %s\n", fd, fcntl(fd, F_GETFD) == -1 ? "closed" : "open");
    return 0;
}

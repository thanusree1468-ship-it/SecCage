#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>

int main(void)
{
    printf("Restricted test program started.\n");

    errno = 0;

    long result = syscall(SYS_getppid);

    if (result == -1)
    {
        printf("getppid() was BLOCKED by SecCage.\n");
        printf("Error: %s\n", strerror(errno));
        return 1;
    }

    printf("Parent PID: %ld\n", result);

    return 0;
}

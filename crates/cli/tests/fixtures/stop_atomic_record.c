#define _GNU_SOURCE
#include <dlfcn.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Only loaded into the regression's own child. Stop after the real file sync,
 * before write_atomic can rename its sibling. No product fault switch exists. */
int fsync(int fd) {
    int (*real_fsync)(int) = dlsym(RTLD_NEXT, "fsync");
    int result = real_fsync(fd);
    char link[64], path[4096];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t length = readlink(link, path, sizeof(path) - 1);
    if (result == 0 && length > 0) {
        path[length] = '\0';
        if (strstr(path, "/submissions/.d3d-tmp-") != NULL) {
            raise(SIGSTOP);
        }
    }
    return result;
}

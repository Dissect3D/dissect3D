/* Private Linux child-process fixture: fail only recovery-record fsync calls.
 * Loaded explicitly into a disposable CLI through LD_PRELOAD; no product hook.
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int fsync(int fd) {
    char descriptor[64], path[4096];
    snprintf(descriptor, sizeof(descriptor), "/proc/self/fd/%d", fd);
    ssize_t count = readlink(descriptor, path, sizeof(path) - 1);
    if (count > 0) {
        path[count] = '\0';
        if (strstr(path, "/submissions/") != NULL) {
            int fail = 1;
#ifdef RECEIPT_ONLY
            char bytes[65537];
            int reader = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
            ssize_t length = reader < 0 ? -1 : read(reader, bytes, sizeof(bytes) - 1);
            if (reader >= 0) close(reader);
            fail = 0;
            if (length > 0) {
                bytes[length] = '\0';
                fail = strstr(bytes, "\"receipt\":{") != NULL;
            }
#endif
            if (fail) {
                errno = EIO;
                return -1;
            }
        }
    }
    int (*real_sync)(int) = dlsym(RTLD_NEXT, "fsync");
    if (real_sync == NULL) {
        errno = EIO;
        return -1;
    }
    return real_sync(fd);
}

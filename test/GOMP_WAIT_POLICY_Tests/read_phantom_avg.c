#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

/* Self-contained definitions matching pvsched.h */
struct hg_message {
    uint64_t msg;
    uint64_t padding[7];
};

#define H2G_LATEST_SLOT 0

int main(void)
{
    int fd = open("/dev/guest_ivshmem", O_RDONLY);
    if (fd < 0) {
        perror("Failed to open /dev/guest_ivshmem");
        return 1;
    }

    printf("Polling /dev/guest_ivshmem for Phantom Average (Ctrl-C to stop)...\n");

    while (1) {
        struct hg_message msg = {0};
        off_t offset = (off_t)(H2G_LATEST_SLOT * sizeof(struct hg_message));

        ssize_t ret = pread(fd, &msg, sizeof(msg), offset);
        if (ret < 0) {
            perror("pread failed");
            close(fd);
            return 1;
        } else if (ret != sizeof(msg)) {
            fprintf(stderr, "Short read: got %zd bytes, expected %zu\n", ret, sizeof(msg));
        } else {
            printf("Phantom Average: %llu\n", (unsigned long long)msg.msg);
        }

        sleep(1);
    }

    close(fd);
    return 0;
}

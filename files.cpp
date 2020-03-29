#include <cerrno>
#include <cstdio>
#include <sys/sendfile.h>
#include <unistd.h>


#include "files.h"


int pread_full(int file, char *buf, size_t bytes, off_t offset) {
    int got = 0;
    while (bytes > 0) {
        got = pread(file, buf, bytes, offset);

        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("pread");
            return -1;
        }

        if (got == 0) {
            printf("pread: Unexpected end of file.");
            return -1;
        }

        buf += got;
        offset += got;
        bytes -= got;
    }

    return 0;
}


int pwrite_full(int file, char *buf, size_t bytes, off_t offset) {
    int wrote = 0;
    while (bytes > 0) {
        wrote = pwrite(file, buf, bytes, offset);

        if (wrote < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("pwrite");
            return -1;
        }

        buf += wrote;
        offset += wrote;
        bytes -= wrote;
    }

    return 0;
}


// TODO eintr
int copy_data(int output, int input, size_t size, off_t output_offset, off_t input_offset) {
    if (lseek(output, output_offset, SEEK_SET) < 0 || lseek(input, input_offset, SEEK_SET) < 0) {
        perror("lseek");
        return -1;
    }

    ssize_t sent;
    while (size != 0) {
        sent = sendfile(output, input, nullptr, size);
        if (sent < 0) {
            perror("sendfile(output, input)");
            return -1;
        }
        size -= sent;
    }

    return 0;
}

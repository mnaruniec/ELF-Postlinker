#ifndef FILES_H
#define FILES_H

#include <cstdio>

int pread_full(int file, char *buf, size_t bytes, off_t offset);

int pwrite_full(int file, char *buf, size_t bytes, off_t offset);

int copy_data(int output, int input, size_t size, off_t output_offset = 0, off_t input_offset = 0);

#endif //FILES_H

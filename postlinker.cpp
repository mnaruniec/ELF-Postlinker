#include <cstdio>
#include <elf.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <vector>

int pread_full(int file, char *buf, size_t bytes, off_t offset) {
    int got = 0;
    while (bytes > 0) {
        got = pread64(file, buf, bytes, offset);

        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("pread64");
            return -1;
        }

        if (got == 0) {
            printf("pread64: Unexpected end of file.");
            return -1;
        }

        buf += got;
        offset += got;
        bytes -= got;
    }

    return 0;
}

long get_section_count(int file, Elf64_Ehdr *elf_header) {
    long result = elf_header->e_shnum;
    if (result >= SHN_LORESERVE) {
        Elf64_Shdr first_header;

        if (pread_full(file, (char *)&first_header, sizeof(first_header), elf_header->e_shoff)) {
            return -1;
        }

        result = first_header.sh_size;
    }

    return result;
}

int get_section_headers(std::vector<Elf64_Shdr> &result, int file, Elf64_Ehdr *elf_header) {
    Elf64_Shdr new_header;
    long num_headers;
    unsigned long header_offset = elf_header->e_shoff;

    if ((num_headers = get_section_count(file, elf_header)) < 0) {
        return -1;
    }

    for (unsigned i = 0; i < num_headers; ++i) {
        if (pread_full(file, (char *)&new_header, sizeof(new_header), header_offset)) {
            return -1;
        }

        result.push_back(new_header);

        header_offset += elf_header->e_phentsize;
    }

    return 0;
}

int postlink(int exec, int rel, char *output_path) {
    // TODO - validation
    Elf64_Ehdr exec_hdr;
    Elf64_Ehdr rel_hdr;
    std::vector<Elf64_Shdr> rel_section_headers;

    if (pread_full(exec, (char *)&exec_hdr, sizeof(exec_hdr), 0)
        || pread_full(rel, (char *)&rel_hdr, sizeof(rel_hdr), 0)
        || get_section_headers(rel_section_headers, rel, &rel_hdr)) {
        return -1;
    }

    return 0;
}

int main(int argc, char **argv) {
    int exit_code = -1;
    int input_exec;
    int input_rel;

    if (argc < 4) {
        printf("usage: %s <ET_EXEC file> <ET_REL file> <output file>", argv[0]);
        goto fail_no_close;
    }

    input_exec = open(argv[1], O_RDONLY);
    if (input_exec < 0) {
        perror("open(input_exec)");
        goto fail_no_close;
    }
    input_rel = open(argv[2], O_RDONLY);
    if (input_rel < 0) {
        perror("open(input_rel)");
        goto fail_second_close;
    }

    exit_code = postlink(input_exec, input_rel, argv[3]);

    if (close(input_rel) < 0) {
        perror("close(input_rel)");
        exit_code = -1;
    };
    fail_second_close:
        if (close(input_exec) < 0) {
            perror("close(input_exec)");
            exit_code = -1;
        };
    fail_no_close:
        return exit_code;
}

#include "types.h"

#include "files.h"


int ElfFile::write_elf_header() const {
    return pwrite_full(fd, (char *) &elf_header, sizeof(elf_header), 0);
}

int ElfFile::write_section_headers() const {
    unsigned long offset = elf_header.e_shoff;
    for (auto &header: section_headers) {
        if (pwrite_full(fd, (char *) &header, sizeof(header), offset)) {
            return -1;
        }

        offset += elf_header.e_shentsize;
    }

    return 0;
}

int ElfFile::write_program_headers() const {
    unsigned long offset = elf_header.e_phoff;
    for (auto &header: program_headers) {
        if (pwrite_full(fd, (char *) &header, sizeof(header), offset)) {
            return -1;
        }

        offset += elf_header.e_phentsize;
    }

    return 0;
}

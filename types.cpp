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

unsigned long ElfFile::get_lowest_free_offset() const {
    unsigned long result = elf_header.e_ehsize;

    unsigned long section_table_end =
            elf_header.e_shoff + (section_headers.size() * elf_header.e_shentsize);
    result = std::max(result, section_table_end);

    unsigned long segment_table_end =
            elf_header.e_phoff + (program_headers.size() * elf_header.e_phentsize);
    result = std::max(result, segment_table_end);

    for (auto &header: section_headers) {
        unsigned long size = (header.sh_type == SHT_NOBITS) ? 0 : header.sh_size;
        result = std::max(result, header.sh_offset + size);
    }

    for (auto &header: program_headers) {
        result = std::max(result, header.p_offset + header.p_filesz);
    }

    return result;
}

unsigned long ElfFile::get_lowest_free_address() const {
    unsigned long result = 0;

    for (auto &header: program_headers) {
        result = std::max(result, header.p_vaddr + header.p_memsz);
    }

    return result;
}

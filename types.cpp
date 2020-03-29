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

unsigned long ElfFile::get_max_segment_alignment() const {
    unsigned long result = PAGE_SIZE;
    for (auto &header: program_headers) {
        result = std::max(result, header.p_align);
    }

    return result;
}

int ElfFile::read_elf_header() {
    return pread_full(fd, (char *)&elf_header, sizeof(elf_header), 0);
}

int ElfFile::read_section_headers() {
    section_headers.clear();

    Elf64_Shdr new_header;
    long num_headers;
    unsigned long header_offset = elf_header.e_shoff;

    if ((num_headers = get_section_count()) < 0) {
        return -1;
    }

    for (unsigned i = 0; i < num_headers; ++i) {
        if (pread_full(fd, (char *)&new_header, sizeof(new_header), header_offset)) {
            return -1;
        }

        section_headers.push_back(new_header);

        header_offset += elf_header.e_shentsize;
    }

    return 0;
}

int ElfFile::read_program_headers() {
    program_headers.clear();

    Elf64_Phdr new_header;
    long num_headers;
    unsigned long header_offset = elf_header.e_phoff;

    if ((num_headers = get_segment_count()) < 0) {
        return -1;
    }

    for (unsigned i = 0; i < num_headers; ++i) {
        if (pread_full(fd, (char *)&new_header, sizeof(new_header), header_offset)) {
            return -1;
        }

        program_headers.push_back(new_header);

        header_offset += elf_header.e_phentsize;
    }

    return 0;
}

long ElfFile::get_section_count() const {
    long result = elf_header.e_shnum;
    if (result == SHN_UNDEF) {
        if (elf_header.e_shoff == 0) {
            return 0;
        }

        Elf64_Shdr first_header;

        if (pread_full(fd, (char *)&first_header, sizeof(first_header), elf_header.e_shoff)) {
            return -1;
        }

        result = first_header.sh_size;
    }

    return result;
}

long ElfFile::get_segment_count() const {
    long result = elf_header.e_phnum;
    if (result == PN_XNUM) {
        if (elf_header.e_shoff == 0) {
            return -1;
        }

        Elf64_Shdr first_section_header;

        if (pread_full(fd, (char *)&first_section_header, sizeof(first_section_header), elf_header.e_shoff)) {
            return -1;
        }

        result = first_section_header.sh_info;
    }

    return result;
}

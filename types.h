#ifndef TYPES_H
#define TYPES_H


#include <elf.h>
#include <vector>

struct ElfFile {
    int fd = -1;
    Elf64_Ehdr elf_header;
    std::vector<Elf64_Shdr> section_headers;
    std::vector<Elf64_Phdr> program_headers;

    int write_elf_header() const;

    int write_section_headers() const;

    int write_program_headers() const;

    unsigned long get_lowest_free_offset() const;

    unsigned long get_lowest_free_address() const;
};

#endif //TYPES_H

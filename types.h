#ifndef TYPES_H
#define TYPES_H


#include <elf.h>
#include <vector>

struct ElfFile {
    int fd;
    Elf64_Ehdr elf_header;
    std::vector<Elf64_Shdr> section_headers;
    std::vector<Elf64_Phdr> program_headers;

    int write_elf_header() const;

    int write_section_headers() const;

    int write_program_headers() const;
};

#endif //TYPES_H

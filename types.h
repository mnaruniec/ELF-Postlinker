#ifndef TYPES_H
#define TYPES_H


#include <elf.h>
#include <vector>

struct ElfFile {
    int fd;
    Elf64_Ehdr elf_header;
    std::vector<Elf64_Shdr> section_headers;
    std::vector<Elf64_Phdr> program_headers;
};

#endif //TYPES_H

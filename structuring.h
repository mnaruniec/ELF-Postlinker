#ifndef STRUCTURING_H
#define STRUCTURING_H

#include <elf.h>
#include <map>
#include <unordered_map>
#include <vector>

#include "types.h"

int get_elf_header(Elf64_Ehdr &elf_header, int file);

long get_section_count(int file, const Elf64_Ehdr &elf_header);

long get_segment_count(int file, const Elf64_Ehdr &elf_header);

int get_section_headers(std::vector<Elf64_Shdr> &result, int file, const Elf64_Ehdr &elf_header);

int get_program_headers(std::vector<Elf64_Phdr> &result, int file, const Elf64_Ehdr &elf_header);

int run_structuring_phase(ElfFile &output,
                          HiddenSectionsInfo &hidden_sections_info,
                          const ElfFile &exec,
                          const ElfFile &rel
);

int write_structured_output(const ElfFile &output,
                            const ElfFile &exec,
                            const ElfFile &rel,
                            const HiddenSectionsInfo &hidden_sections_info
);

#endif //STRUCTURING_H

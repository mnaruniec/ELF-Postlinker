#ifndef TYPES_H
#define TYPES_H

#include <elf.h>
#include <unordered_map>
#include <vector>

#include "constants.h"


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

    unsigned long get_max_segment_alignment() const;

    int read_elf_header();

    int read_section_headers();

    int read_program_headers();

private:
    long get_section_count() const;

    long get_segment_count() const;
};

/**
 * Structure for keeping information about rel file sections locations in the output elf.
 */
struct HiddenSectionsInfo {
    std::vector<int> section_partition[SEGMENT_KIND_COUNT];
    std::unordered_map<int, unsigned long> section_addresses;
    std::unordered_map<int, unsigned long> loadable_section_relative_offsets;
    std::unordered_map<int, unsigned long> loadable_section_absolute_offsets;
};

#endif //TYPES_H

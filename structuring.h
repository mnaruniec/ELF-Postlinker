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

void coalesce_sections(std::vector<int> section_partition[], const ElfFile &rel_file);

unsigned long get_lowest_free_offset(const ElfFile &file);

unsigned long get_lowest_free_address(const ElfFile &file);

unsigned long get_max_segment_alignment(const ElfFile &file);

// TODO inlines
/*inline*/ unsigned long align_to(unsigned long to_be_aligned, unsigned long alignment);

// TODO remove
void DEBUG_print_section_partition(const std::vector<int> section_partition[]);

void initialize_new_program_header(Elf64_Phdr &header, unsigned flags);

void allocate_segments_no_offset(
        std::map<int, Elf64_Phdr> &new_program_headers,
        std::unordered_map<int, unsigned long> &section_addresses,
        std::unordered_map<int, unsigned long> &file_section_relative_offsets,
        unsigned long next_free_address,
        const std::vector<int> section_partition[],
        const ElfFile &rel_file
);


// TODO possibly handle all overflows
/*inline*/ unsigned long align_same_as(unsigned long to_be_aligned, const unsigned long objective, unsigned long alignment);

void allocate_segment_offsets(std::map<int, Elf64_Phdr> &program_headers, unsigned long next_free_offset);

void update_output_program_headers(ElfFile &output, const std::map<int, Elf64_Phdr> &new_program_headers);

void build_absolute_section_offsets(
        std::unordered_map<int, unsigned long> &absolute_offsets,
        const std::unordered_map<int, unsigned long> &relative_offsets,
        const std::vector<int> section_partition[],
        const std::map<int, Elf64_Phdr> &new_program_headers
);

int write_elf_header(const ElfFile &file);

int write_section_headers(int file, const Elf64_Ehdr &elf_header, const std::vector<Elf64_Shdr> &section_headers);

int write_program_headers(int file, const Elf64_Ehdr &elf_header, const std::vector<Elf64_Phdr> &program_headers);

int copy_sections(int output, int input,
                  const std::vector<Elf64_Shdr> &input_section_headers,
                  const std::unordered_map<int, unsigned long> &output_section_absolute_offsets
);

int write_output_no_relocations(const ElfFile &output,
                                const ElfFile &exec,
                                const ElfFile &rel,
                                const std::unordered_map<int, unsigned long> &output_section_absolute_offsets,
                                unsigned long exec_file_size,
                                unsigned long exec_shift_value
);

/*inline*/ unsigned long get_program_headers_size(const Elf64_Ehdr &elf_header, unsigned long program_header_count);

int get_first_load_segment(Elf64_Phdr &load, const std::vector<Elf64_Phdr> &program_headers);

int perform_shifts(ElfFile &output,
                   unsigned long output_program_headers_count,
                   unsigned long exec_shift_value
);

int update_program_header_count(ElfFile &file);


#endif //STRUCTURING_H

#ifndef RELOCATIONS_H
#define RELOCATIONS_H

#include <elf.h>
#include <map>
#include <unordered_map>
#include <vector>

int read_symbol_table(std::vector<Elf64_Sym> &symbol_table, int file, const Elf64_Shdr &header);

int read_string_table(std::vector<char> &string_table, int file, const Elf64_Shdr &header);

int read_string_table_for_symbol_table(std::vector<char> &string_table,
                                       int file,
                                       const std::vector<Elf64_Shdr> &section_headers,
                                       const Elf64_Shdr &symbol_header);

int build_global_symbol_map(std::unordered_map<std::string, Elf64_Sym> &symbol_map,
                            int file,
                            const std::vector<Elf64_Shdr> &section_headers);


int get_symbol_tables(std::map<int, std::vector<Elf64_Sym>> &symbol_tables,
                      int file,
                      const std::vector<Elf64_Shdr> &section_headers);

int update_symbol_tables(std::map<int, std::vector<Elf64_Sym>> &rel_symbol_tables,
                         Elf64_Ehdr &output_elf_header,
                         int rel_file,
                         const std::vector<Elf64_Shdr> &rel_section_headers,
                         const std::unordered_map<std::string, Elf64_Sym> &exec_symbol_map,
                         const std::unordered_map<int, unsigned long> &hidden_section_addresses
);

int read_rela_table(std::vector<Elf64_Rela> &rela_table, int file, const Elf64_Shdr &header);

int perform_relocations(
        int output_file,
        int rel_file,
        const std::map<int, std::vector<Elf64_Sym>> &symbol_tables,
        const std::vector<Elf64_Shdr> &rel_section_headers,
        const std::unordered_map<int, unsigned long> &alloc_section_offsets,
        const std::unordered_map<int, unsigned long> &section_addresses
);

#endif //RELOCATIONS_H

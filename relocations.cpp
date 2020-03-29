#include "relocations.h"

#include <cstring>

#include "constants.h"
#include "files.h"


int read_symbol_table(std::vector<Elf64_Sym> &symbol_table, int file, const Elf64_Shdr &header) {
    Elf64_Sym symbol;

    for (unsigned off = header.sh_offset; off < header.sh_offset + header.sh_size; off += header.sh_entsize) {
        if (pread_full(file, (char *) &symbol, sizeof(symbol), off)) {
            return -1;
        }

        symbol_table.push_back(symbol);
    }

    return 0;
}

int read_string_table(std::vector<char> &string_table, int file, const Elf64_Shdr &header) {
    if (header.sh_type != SHT_STRTAB) {
        printf("Non-SHT_STRTAB section used as string table.\n");
        return -1;
    }

    string_table.resize(header.sh_size);
    if (pread_full(file, string_table.data(), header.sh_size, header.sh_offset)) {
        return -1;
    }

    if (string_table[header.sh_size - 1] != 0) {
        printf("SHT_STRTAB section is not null-terminated.\n");
        return -1;
    }

    return 0;
}

int read_string_table_for_symbol_table(std::vector<char> &string_table,
        const ElfFile &file,
        const Elf64_Shdr &symbol_header
        ) {
    if (symbol_header.sh_type != SHT_SYMTAB) {
        printf("Trying to use non-SHT_SYMTAB section as symbol table..\n");
        return -1;
    }

    unsigned string_table_index = symbol_header.sh_link;
    if (string_table_index >= file.section_headers.size()) {
        printf("String table index is out-of-bounds.\n");
        return -1;
    }
    const Elf64_Shdr &string_table_header = file.section_headers[string_table_index];

    return read_string_table(string_table, file.fd, string_table_header);
}

// TODO check sizeofs for buffer overflow
int build_global_symbol_map(std::unordered_map<std::string, Elf64_Sym> &symbol_map, const ElfFile &file) {
    for (auto &header: file.section_headers) {
        if (header.sh_type != SHT_SYMTAB) {
            continue;
        }

        std::vector<char> string_table;
        std::vector<Elf64_Sym> symbol_table;

        if (read_symbol_table(symbol_table, file.fd, header)
            || read_string_table_for_symbol_table(string_table, file, header)) {
            return -1;
        }

        for (auto &symbol: symbol_table) {
            unsigned name_offset = symbol.st_name;
            if (name_offset >= string_table.size()) {
                printf("Symbol name index is out-of-bounds.\n");
                return -1;
            }

            std::string symbol_name(string_table.data() + name_offset);
            unsigned long symbol_binding = ELF64_ST_BIND(symbol.st_info);

            // TODO check COMMON
            if (symbol_binding == STB_GLOBAL && symbol.st_shndx != SHN_UNDEF && symbol.st_shndx != SHN_COMMON) {
                if (symbol_map.find(symbol_name) != symbol_map.end()) {
                    printf("Duplicate symbol name\n");
                    return -1;
                }

                symbol_map[symbol_name] = symbol;
            }
        }
    }

    // TODO remove
//    for (auto &entry: symbol_map) {
//        printf("%s\n", entry.first.c_str());
//    }

    return 0;
}

int get_symbol_tables(std::map<int, std::vector<Elf64_Sym>> &symbol_tables, const ElfFile &file) {
    for (unsigned i = 0; i < file.section_headers.size(); ++i) {
        const Elf64_Shdr &header = file.section_headers[i];

        if (header.sh_type != SHT_SYMTAB) {
            continue;
        }

        std::vector<Elf64_Sym> symbol_table;
        if (read_symbol_table(symbol_table, file.fd, header)) {
            return -1;
        }

        symbol_tables[i] = symbol_table;
    }

    return 0;
}

// TODO write new elf header down
int update_symbol_tables(std::map<int, std::vector<Elf64_Sym>> &rel_symbol_tables,
                         ElfFile &output,
                         const ElfFile &rel,
                         const std::unordered_map<std::string, Elf64_Sym> &exec_symbol_map,
                         const std::unordered_map<int, unsigned long> &hidden_section_addresses
) {
    unsigned long orig_start = output.elf_header.e_entry;

    for (auto &entry: rel_symbol_tables) {
        std::vector<char> string_table;

        if (read_string_table_for_symbol_table(
                string_table, rel, rel.section_headers[entry.first])) {
            return -1;
        }

        for (auto &symbol: entry.second) {
            if (symbol.st_name >= string_table.size()) {
                printf("String index out-of-bounds.\n");
                return -1;
            }

            std::string name(string_table.data() + symbol.st_name);

            if (symbol.st_shndx == SHN_UNDEF) {

                if (name == ORIG_START_STRING) {
                    // TODO might write down transformed sections
                    symbol.st_shndx = SHN_ABS;
                    symbol.st_value = orig_start;
                } else if (exec_symbol_map.find(name) != exec_symbol_map.end()) {
                    symbol.st_shndx = SHN_ABS;
                    symbol.st_value = exec_symbol_map.at(name).st_value;
                }

//                printf("EXT symbol: %s, address: %lx\n", name.c_str(), symbol.st_value);
            } else if (symbol.st_shndx != SHN_ABS) {
                // TODO might handle big indices
                unsigned section_index = symbol.st_shndx;

                if (hidden_section_addresses.find(section_index) == hidden_section_addresses.end()) {
                    continue;
                }

                symbol.st_value += hidden_section_addresses.at(section_index);

                if (name == _START_STRING) {
                    output.elf_header.e_entry = symbol.st_value;
                }

//                printf("INT symbol: %s, address: %lx\n", name.c_str(), symbol.st_value);
            }

//            printf("symbol: %s, address: %lx\n", name.c_str(), symbol.st_value);
        }
    }

    return 0;
}

int read_rela_table(std::vector<Elf64_Rela> &rela_table, int file, const Elf64_Shdr &header) {
    if (header.sh_type != SHT_RELA) {
        printf("Trying to use non-SHT_RELA section as relocation table.");
        return -1;
    }

    Elf64_Rela rela;

    for (unsigned off = header.sh_offset; off < header.sh_offset + header.sh_size; off += header.sh_entsize) {
        if (pread_full(file, (char *)(&rela), sizeof(rela), off)) {
            return -1;
        }
        rela_table.push_back(rela);
    }

    return 0;
}

int perform_relocations(
        const ElfFile &output,
        const ElfFile &rel,
        const std::map<int, std::vector<Elf64_Sym>> &symbol_tables,
        const std::unordered_map<int, unsigned long> &alloc_section_offsets,
        const std::unordered_map<int, unsigned long> &section_addresses
) {
    for (auto &header: rel.section_headers) {
        if (header.sh_type != SHT_RELA) {
            continue;
        }

        unsigned long symbol_section_index = header.sh_link;
        unsigned long target_section_index = header.sh_info;

        if (symbol_tables.find(symbol_section_index) == symbol_tables.end()) {
            printf("Relocation section targeting non-symbol section.");
            return -1;
        }

        if (alloc_section_offsets.find(target_section_index) == alloc_section_offsets.end()) {
            continue;
        }

        const std::vector<Elf64_Sym> &symbol_table = symbol_tables.at(symbol_section_index);

        std::vector<Elf64_Rela> rela_table;
        if (read_rela_table(rela_table, rel.fd, header)) {
            return -1;
        }

        for (auto &rela: rela_table) {
            unsigned long rel_offset = rela.r_offset;
            unsigned symbol_index = ELF64_R_SYM(rela.r_info);
            unsigned type = ELF64_R_TYPE(rela.r_info);

            if (symbol_index >= symbol_table.size()) {
                printf("Out-of-bounds symbol index.");
                return -1;
            }

            Elf64_Sym symbol = symbol_table[symbol_index];

            if (symbol.st_shndx == SHN_UNDEF) {
                printf("Relocation for undefined symbol.");
                return -1;
            }

            long addend = rela.r_addend;
            unsigned long abs_offset = alloc_section_offsets.at(target_section_index) + rel_offset;
            unsigned long address = section_addresses.at(target_section_index) + rel_offset;
            unsigned long value = symbol.st_value;
            long signed_value;
            long signed_address;
            memcpy(&signed_value, (const void *)&value, sizeof(signed_value));
            memcpy(&signed_address, (const void *)&address, sizeof(signed_address));

            switch (type) {
                case R_X86_64_64:
                    signed_value += addend;
                    if (pwrite_full(output.fd, (char *)&signed_value, 8, abs_offset)) {
                        return -1;
                    }
                    break;
                case R_X86_64_32:
                    signed_value += addend;
                    //TODO check
                    if (pwrite_full(output.fd, (char *)&signed_value, 4, abs_offset)) {
                        return -1;
                    }
                    break;
                case R_X86_64_32S:
                    signed_value += addend;
                    //TODO check
                    if (pwrite_full(output.fd, (char *)&signed_value, 4, abs_offset)) {
                        return -1;
                    }
                    break;
                case R_X86_64_PC32:
                case R_X86_64_PLT32:
                    signed_value -= signed_address;
                    signed_value += addend;
                    // TODO check
                    if (pwrite_full(output.fd, (char *)&signed_value, 4, abs_offset)) {
                        return -1;
                    }
                    break;
                default:
                    continue;
            }
        }
    }

    return output.write_elf_header();
}
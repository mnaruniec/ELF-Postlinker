#include "structuring.h"

#include <algorithm>

#include "constants.h"
#include "files.h"


int get_elf_header(Elf64_Ehdr &elf_header, int file) {
    return pread_full(file, (char *)&elf_header, sizeof(elf_header), 0);
}

long get_section_count(int file, const Elf64_Ehdr &elf_header) {
    long result = elf_header.e_shnum;
    if (result == SHN_UNDEF) {
        if (elf_header.e_shoff == 0) {
            return 0;
        }

        Elf64_Shdr first_header;

        if (pread_full(file, (char *)&first_header, sizeof(first_header), elf_header.e_shoff)) {
            return -1;
        }

        result = first_header.sh_size;
    }

    return result;
}

long get_segment_count(int file, const Elf64_Ehdr &elf_header) {
    long result = elf_header.e_phnum;
    if (result == PN_XNUM) {
        if (elf_header.e_shoff == 0) {
            return -1;
        }

        Elf64_Shdr first_section_header;

        if (pread_full(file, (char *)&first_section_header, sizeof(first_section_header), elf_header.e_shoff)) {
            return -1;
        }

        result = first_section_header.sh_info;
    }

    return result;
}

int get_section_headers(std::vector<Elf64_Shdr> &result, int file, const Elf64_Ehdr &elf_header) {
    Elf64_Shdr new_header;
    long num_headers;
    unsigned long header_offset = elf_header.e_shoff;

    if ((num_headers = get_section_count(file, elf_header)) < 0) {
        return -1;
    }

    for (unsigned i = 0; i < num_headers; ++i) {
        if (pread_full(file, (char *)&new_header, sizeof(new_header), header_offset)) {
            return -1;
        }

        result.push_back(new_header);

        header_offset += elf_header.e_shentsize;
    }

    return 0;
}

int get_program_headers(std::vector<Elf64_Phdr> &result, int file, const Elf64_Ehdr &elf_header) {
    Elf64_Phdr new_header;
    long num_headers;
    unsigned long header_offset = elf_header.e_phoff;

    if ((num_headers = get_segment_count(file, elf_header)) < 0) {
        return -1;
    }

    for (unsigned i = 0; i < num_headers; ++i) {
        if (pread_full(file, (char *)&new_header, sizeof(new_header), header_offset)) {
            return -1;
        }

        result.push_back(new_header);

        header_offset += elf_header.e_phentsize;
    }

    return 0;
}

struct SectionComparator {
    explicit SectionComparator(const std::vector<Elf64_Shdr> *section_headers) : section_headers{section_headers} {}

    bool operator() (int i, int j) {
        bool i_nobits = (*section_headers)[i].sh_type == SHT_NOBITS;
        bool j_nobits = (*section_headers)[j].sh_type == SHT_NOBITS;

        if (i_nobits && !j_nobits) {
            return false;
        }

        if (!i_nobits && j_nobits) {
            return true;
        }

        return i < j;
    }
private:
    const std::vector<Elf64_Shdr> *section_headers;
};

void coalesce_sections(std::vector<int> section_partition[], const ElfFile &rel_file) {
    unsigned char flags;
    for (unsigned i = 0; i < rel_file.section_headers.size(); ++i) {
        const Elf64_Shdr &header = rel_file.section_headers[i];
        if (header.sh_flags & SHF_ALLOC) {
            flags = 0;

            if (header.sh_flags & SHF_WRITE) {
                flags |= WRITE_SEGMENT;
            }

            if (header.sh_flags & SHF_EXECINSTR) {
                flags |= EXEC_SEGMENT;
            }

            section_partition[flags].push_back(i);
        }
    }

    for (unsigned i = 0; i < SEGMENT_KIND_COUNT; ++i) {
        std::sort(
                section_partition[i].begin(),
                section_partition[i].end(),
                SectionComparator(&rel_file.section_headers)
        );
    }
}

unsigned long get_lowest_free_offset(const ElfFile &file) {
    unsigned long result = file.elf_header.e_ehsize;

    unsigned long section_table_end =
            file.elf_header.e_shoff + (file.section_headers.size() * file.elf_header.e_shentsize);
    result = std::max(result, section_table_end);

    unsigned long segment_table_end = file.elf_header.e_phoff + (file.program_headers.size() * file.elf_header.e_phentsize);
    result = std::max(result, segment_table_end);

    for (auto &header: file.section_headers) {
        unsigned long size = (header.sh_type == SHT_NOBITS) ? 0 : header.sh_size;
        result = std::max(result, header.sh_offset + size);
    }

    for (auto &header: file.program_headers) {
        result = std::max(result, header.p_offset + header.p_filesz);
    }

    return result;
}

unsigned long get_lowest_free_address(const ElfFile &file) {
    unsigned long result = 0;

    for (auto &header: file.program_headers) {
        result = std::max(result, header.p_vaddr + header.p_memsz);
    }

    return result;
}

unsigned long get_max_segment_alignment(const ElfFile &file) {
    unsigned long result = MAX_PAGE_SIZE;
    for (auto &header: file.program_headers) {
        result = std::max(result, header.p_align);
    }

    return result;
}

/*inline*/ unsigned long align_to(unsigned long to_be_aligned, unsigned long alignment) {
    if (!alignment) {
        return to_be_aligned;
    }

    if (to_be_aligned % alignment) {
        to_be_aligned /= alignment;
        to_be_aligned *= alignment;
        to_be_aligned += alignment;
    }

    return to_be_aligned;
}

void DEBUG_print_section_partition(const std::vector<int> section_partition[]) {
    for (unsigned i = 0; i < SEGMENT_KIND_COUNT; ++i) {
        printf("Segment %u:\n", i);
        for (auto section: section_partition[i]) {
            printf("%d\n", section);
        }
    }
}

void initialize_new_program_header(Elf64_Phdr &header, unsigned flags) {
    header.p_type = PT_LOAD;
    header.p_offset = header.p_vaddr = header.p_paddr = header.p_filesz = header.p_memsz = 0;
    // TODO check flags
    header.p_align = PAGE_SIZE;

    header.p_flags = PF_R;
    if (flags & WRITE_SEGMENT) {
        header.p_flags |= PF_W;
    }
    if (flags & EXEC_SEGMENT) {
        header.p_flags |= PF_X;
    }
}

void allocate_segments_no_offset(
        std::map<int, Elf64_Phdr> &new_program_headers,
        std::unordered_map<int, unsigned long> &section_addresses,
        std::unordered_map<int, unsigned long> &file_section_relative_offsets,
        unsigned long next_free_address,
        const std::vector<int> section_partition[],
        const ElfFile &rel_file
) {
    for (unsigned i = 0; i < SEGMENT_KIND_COUNT; ++i) {
        if (section_partition[i].empty()) {
            continue;
        }

        next_free_address = align_to(next_free_address, MAX_PAGE_SIZE);
        Elf64_Phdr new_program_header;
        initialize_new_program_header(new_program_header, i);

        for (unsigned j = 0; j < section_partition[i].size(); ++j) {
            int section_index = section_partition[i][j];
            const Elf64_Shdr &section_header = rel_file.section_headers[section_index];

            unsigned long section_address = align_to(next_free_address, section_header.sh_addralign);
            unsigned long padding = section_address - next_free_address;
            unsigned long section_size = section_header.sh_size;
            bool is_nobits = section_header.sh_type == SHT_NOBITS;

            section_addresses[section_index] = section_address;

            if (j == 0) {
                new_program_header.p_vaddr = new_program_header.p_paddr = section_address;
            } else {
                if (!is_nobits) {
                    new_program_header.p_filesz += padding;
                }
                new_program_header.p_memsz += padding;
            }

            if (!is_nobits) {
                new_program_header.p_filesz += section_size;
                file_section_relative_offsets[section_index] = section_address - new_program_header.p_vaddr;
            }
            new_program_header.p_memsz += section_size;

            next_free_address = section_address + section_size;
        }

        new_program_headers[i] = new_program_header;
    }
}


// TODO possibly handle all overflows
/*inline*/ unsigned long align_same_as(unsigned long to_be_aligned, const unsigned long objective, unsigned long alignment) {
    if (!alignment) {
        return to_be_aligned;
    }

    unsigned long objective_mod = objective % alignment;

    if (to_be_aligned % alignment <= objective_mod) {
        return to_be_aligned / alignment * alignment + objective_mod;
    }

    return align_to(to_be_aligned, alignment) + objective_mod;
}

void allocate_segment_offsets(std::map<int, Elf64_Phdr> &program_headers, unsigned long next_free_offset) {
    for (auto &header_entry: program_headers) {
        next_free_offset = align_same_as(next_free_offset, header_entry.second.p_vaddr, header_entry.second.p_align);

        header_entry.second.p_offset = next_free_offset;

        next_free_offset += header_entry.second.p_filesz;
    }
}


void build_absolute_section_offsets(
        std::unordered_map<int, unsigned long> &absolute_offsets,
        const std::unordered_map<int, unsigned long> &relative_offsets,
        const std::vector<int> section_partition[],
        const std::map<int, Elf64_Phdr> &new_program_headers
) {
    for (auto &entry: new_program_headers) {
        unsigned long segment_offset = entry.second.p_offset;

        for (auto section_index: section_partition[entry.first]) {
            if (relative_offsets.find(section_index) == relative_offsets.end()) {
                continue;
            }

            absolute_offsets[section_index] = segment_offset + relative_offsets.at(section_index);
        }
    }
}

int copy_sections(int output, int input,
                  const std::vector<Elf64_Shdr> &input_section_headers,
                  const std::unordered_map<int, unsigned long> &output_section_absolute_offsets
) {
    for (auto &entry: output_section_absolute_offsets) {
        const Elf64_Shdr &header = input_section_headers[entry.first];
        if (header.sh_type == SHT_NOBITS) {
            continue;
        }

        if (copy_data(output, input, header.sh_size, entry.second, header.sh_offset)) {
            return -1;
        }
    }

    return 0;
}

int write_output_no_relocations(const ElfFile &output,
                                const ElfFile &exec,
                                const ElfFile &rel,
                                const std::unordered_map<int, unsigned long> &output_section_absolute_offsets,
                                unsigned long exec_file_size,
                                unsigned long exec_shift_value
) {

    if (copy_data(output.fd, exec.fd, exec_file_size, exec_shift_value)
        || output.write_elf_header()
        || output.write_section_headers()
        || output.write_program_headers()
        || copy_sections(output.fd, rel.fd, rel.section_headers, output_section_absolute_offsets)) {
        return -1;
    }

    return 0;
}

/*inline*/ unsigned long get_program_headers_size(const Elf64_Ehdr &elf_header, unsigned long program_header_count) {
    return elf_header.e_phentsize * program_header_count;
}

int get_first_load_segment(Elf64_Phdr &load, const std::vector<Elf64_Phdr> &program_headers) {
    for (auto &header: program_headers) {
        if (header.p_type == PT_LOAD) {
            load = header;
            if (header.p_offset != 0) {
                printf("First load segment has non-zero offset.\n");
                return -1;
            }

            return 0;
        }
    }

    printf("No load segment found.\n");
    return -1;
}

int perform_shifts(ElfFile &output,
                   unsigned long output_program_headers_count,
                   unsigned long exec_shift_value
) {
    output.elf_header.e_phoff = output.elf_header.e_ehsize;
    output.elf_header.e_shoff += exec_shift_value;

    for (auto &header: output.section_headers) {
        if (header.sh_type != SHT_NULL) {
            header.sh_offset += exec_shift_value;
        }
    }

    Elf64_Phdr first_load_segment;
    if (get_first_load_segment(first_load_segment, output.program_headers)) {
        return -1;
    }

    first_load_segment.p_filesz += exec_shift_value;
    first_load_segment.p_memsz += exec_shift_value;
    first_load_segment.p_paddr = first_load_segment.p_vaddr -= exec_shift_value;

    bool is_first_load = true;

    for (auto &header: output.program_headers) {
        if (header.p_type == PT_PHDR) {
            header.p_paddr = header.p_vaddr = first_load_segment.p_vaddr + output.elf_header.e_ehsize;
            header.p_offset = output.elf_header.e_phoff;
            header.p_memsz = header.p_filesz =
                    get_program_headers_size(output.elf_header, output_program_headers_count);
        } else if (header.p_type == PT_LOAD && is_first_load) {
            is_first_load = false;
            header = first_load_segment;
        } else if (header.p_vaddr != 0){
            header.p_offset += exec_shift_value;
        }
    }

    return 0;
}

static int update_program_header_count(ElfFile &file) {
    unsigned long count = file.program_headers.size();

    if (count >= PN_XNUM) {
        if (file.section_headers.empty()) {
            printf("No first section found in exec file.\n");
            return -1;
        }

        file.section_headers[0].sh_info = count;
    } else {
        if (!file.section_headers.empty()) {
            file.section_headers[0].sh_info = 0;
        }

        file.elf_header.e_phnum = count;
    }

    return 0;
}

int update_output_program_headers(ElfFile &output, const std::map<int, Elf64_Phdr> &new_program_headers) {
    for (auto &entry: new_program_headers) {
        output.program_headers.push_back(entry.second);
    }

    return update_program_header_count(output);
}

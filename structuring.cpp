#include "structuring.h"

#include <algorithm>
#include <map>

#include "constants.h"
#include "files.h"


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

static void coalesce_sections(HiddenSectionsInfo &hidden_sections_info, const ElfFile &rel_file) {
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

            hidden_sections_info.section_partition[flags].push_back(i);
        }
    }

    for (auto &sections: hidden_sections_info.section_partition) {
        std::sort(sections.begin(), sections.end(), SectionComparator(&rel_file.section_headers));
    }
}

static inline unsigned long align_to(unsigned long to_be_aligned, unsigned long alignment) {
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

static void initialize_new_program_header(Elf64_Phdr &header, unsigned flags) {
    header.p_type = PT_LOAD;
    header.p_offset = header.p_vaddr = header.p_paddr = header.p_filesz = header.p_memsz = 0;
    header.p_align = PAGE_SIZE;

    header.p_flags = PF_R;
    if (flags & WRITE_SEGMENT) {
        header.p_flags |= PF_W;
    }
    if (flags & EXEC_SEGMENT) {
        header.p_flags |= PF_X;
    }
}

static void allocate_segments_no_offset(
        std::map<int, Elf64_Phdr> &new_program_headers,
        HiddenSectionsInfo &hidden_sections_info,
        const ElfFile &exec,
        const ElfFile &rel
) {
    unsigned long next_free_address = exec.get_lowest_free_address();

    for (unsigned i = 0; i < SEGMENT_KIND_COUNT; ++i) {
        if (hidden_sections_info.section_partition[i].empty()) {
            continue;
        }

        next_free_address = align_to(next_free_address, PAGE_SIZE);
        Elf64_Phdr new_program_header;
        initialize_new_program_header(new_program_header, i);

        for (unsigned j = 0; j < hidden_sections_info.section_partition[i].size(); ++j) {
            int section_index = hidden_sections_info.section_partition[i][j];
            const Elf64_Shdr &section_header = rel.section_headers[section_index];

            unsigned long section_address = align_to(next_free_address, section_header.sh_addralign);
            unsigned long padding = section_address - next_free_address;
            unsigned long section_size = section_header.sh_size;
            bool is_nobits = section_header.sh_type == SHT_NOBITS;

            hidden_sections_info.section_addresses[section_index] = section_address;

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
                hidden_sections_info.loadable_section_relative_offsets[section_index] =
                        section_address - new_program_header.p_vaddr;
            }
            new_program_header.p_memsz += section_size;

            next_free_address = section_address + section_size;
        }

        new_program_headers[i] = new_program_header;
    }
}

static inline unsigned long align_same_as(unsigned long to_be_aligned, const unsigned long objective, unsigned long alignment) {
    if (!alignment) {
        return to_be_aligned;
    }

    unsigned long objective_mod = objective % alignment;

    if (to_be_aligned % alignment <= objective_mod) {
        return to_be_aligned / alignment * alignment + objective_mod;
    }

    return align_to(to_be_aligned, alignment) + objective_mod;
}

static void allocate_segment_offsets(std::map<int, Elf64_Phdr> &program_headers, unsigned long next_free_offset) {
    for (auto &header_entry: program_headers) {
        next_free_offset = align_same_as(next_free_offset, header_entry.second.p_vaddr, header_entry.second.p_align);

        header_entry.second.p_offset = next_free_offset;

        next_free_offset += header_entry.second.p_filesz;
    }
}


static void build_absolute_section_offsets(
        HiddenSectionsInfo &hidden_sections_info,
        const std::map<int, Elf64_Phdr> &new_program_headers
) {
    auto &absolute_offsets = hidden_sections_info.loadable_section_absolute_offsets;
    const auto &relative_offsets = hidden_sections_info.loadable_section_relative_offsets;

    for (auto &entry: new_program_headers) {
        unsigned long segment_offset = entry.second.p_offset;

        for (auto section_index: hidden_sections_info.section_partition[entry.first]) {
            if (relative_offsets.find(section_index) != relative_offsets.end()) {
                absolute_offsets[section_index] = segment_offset + relative_offsets.at(section_index);
            }
        }
    }
}

static int copy_rel_sections(const ElfFile &output, const ElfFile &rel, const HiddenSectionsInfo &hidden_sections_info) {
    for (auto &entry: hidden_sections_info.loadable_section_absolute_offsets) {
        const Elf64_Shdr &header = rel.section_headers[entry.first];
        if (header.sh_type == SHT_NOBITS) {
            continue;
        }

        if (copy_data(output.fd, rel.fd, header.sh_size, entry.second, header.sh_offset)) {
            return -1;
        }
    }

    return 0;
}

static inline unsigned long get_program_headers_size(const Elf64_Ehdr &elf_header, unsigned long program_header_count) {
    return elf_header.e_phentsize * program_header_count;
}

static int get_first_load_segment(Elf64_Phdr &load, const std::vector<Elf64_Phdr> &program_headers) {
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

static int perform_shifts(ElfFile &output,
                   unsigned long output_program_headers_count,
                   unsigned long exec_to_output_shift
) {
    output.elf_header.e_phoff = output.elf_header.e_ehsize;
    output.elf_header.e_shoff += exec_to_output_shift;

    for (auto &header: output.section_headers) {
        if (header.sh_type != SHT_NULL) {
            header.sh_offset += exec_to_output_shift;
        }
    }

    Elf64_Phdr first_load_segment;
    if (get_first_load_segment(first_load_segment, output.program_headers)) {
        return -1;
    }

    first_load_segment.p_filesz += exec_to_output_shift;
    first_load_segment.p_memsz += exec_to_output_shift;
    first_load_segment.p_paddr = first_load_segment.p_vaddr -= exec_to_output_shift;

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
            header.p_offset += exec_to_output_shift;
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

static int update_output_program_headers(ElfFile &output, const std::map<int, Elf64_Phdr> &new_program_headers) {
    for (auto &entry: new_program_headers) {
        output.program_headers.push_back(entry.second);
    }

    return update_program_header_count(output);
}

static unsigned long get_exec_to_output_shift(const ElfFile &exec, unsigned long output_program_headers_count) {
    unsigned long max_segment_alignment = exec.get_max_segment_alignment();
    unsigned long elf_and_program_headers_size =
            exec.elf_header.e_ehsize + get_program_headers_size(exec.elf_header, output_program_headers_count);

    return align_to(elf_and_program_headers_size, max_segment_alignment);
}

int run_structuring_phase(ElfFile &output,
                          HiddenSectionsInfo &hidden_sections_info,
                          const ElfFile &exec,
                          const ElfFile &rel
) {
    std::map<int, Elf64_Phdr> new_program_headers;

    output.elf_header = exec.elf_header;
    output.section_headers = std::vector<Elf64_Shdr>(exec.section_headers);
    output.program_headers = std::vector<Elf64_Phdr>(exec.program_headers);

    coalesce_sections(hidden_sections_info, rel);

    allocate_segments_no_offset(new_program_headers, hidden_sections_info, exec, rel);

    unsigned long output_program_headers_count = exec.program_headers.size() + new_program_headers.size();
    unsigned long exec_to_output_shift = get_exec_to_output_shift(exec, output_program_headers_count);

    if (perform_shifts(output, output_program_headers_count, exec_to_output_shift)) {
        return -1;
    }

    unsigned long lowest_free_offset = exec.get_lowest_free_offset() + exec_to_output_shift;
    allocate_segment_offsets(new_program_headers, lowest_free_offset);

    if (update_output_program_headers(output, new_program_headers)) {
        return -1;
    }

    build_absolute_section_offsets(hidden_sections_info, new_program_headers);

    return 0;
}

int write_structured_output(const ElfFile &output,
                            const ElfFile &exec,
                            const ElfFile &rel,
                            const HiddenSectionsInfo &hidden_sections_info
) {
    unsigned long exec_file_size = exec.get_lowest_free_offset();
    unsigned long exec_to_output_shift = get_exec_to_output_shift(exec, output.program_headers.size());

    if (copy_data(output.fd, exec.fd, exec_file_size, exec_to_output_shift)
        || output.write_elf_header()
        || output.write_section_headers()
        || output.write_program_headers()
        || copy_rel_sections(output, rel, hidden_sections_info)) {
        return -1;
    }

    return 0;
}

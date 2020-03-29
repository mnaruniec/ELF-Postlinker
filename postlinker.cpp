#include <algorithm>
#include <cstdio>
#include <elf.h>
#include <fcntl.h>
#include <vector>
#include <unistd.h>
#include <unordered_map>
#include <map>
#include <cstring>

#include "constants.h"
#include "files.h"
#include "relocations.h"

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

void coalesce_sections(std::vector<int> section_partition[], const std::vector<Elf64_Shdr> &section_headers) {
    unsigned char flags;
    for (unsigned i = 0; i < section_headers.size(); ++i) {
        const Elf64_Shdr &header = section_headers[i];
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
        std::sort(section_partition[i].begin(), section_partition[i].end(), SectionComparator(&section_headers));
    }
}

unsigned long get_lowest_free_offset(const Elf64_Ehdr &elf_header,
        const std::vector<Elf64_Shdr> &section_headers,
        const std::vector<Elf64_Phdr> &program_headers) {

    unsigned long result = elf_header.e_ehsize;

    unsigned long section_table_end = elf_header.e_shoff + (section_headers.size() * elf_header.e_shentsize);
    result = std::max(result, section_table_end);

    unsigned long segment_table_end = elf_header.e_phoff + (program_headers.size() * elf_header.e_phentsize);
    result = std::max(result, segment_table_end);

    for (auto &header: section_headers) {
        unsigned long size = (header.sh_type == SHT_NOBITS) ? 0 : header.sh_size;
        result = std::max(result, header.sh_offset + size);
    }

    for (auto &header: program_headers) {
        result = std::max(result, header.p_offset + header.p_filesz);
    }

    return result;
}


unsigned long get_lowest_free_address(const std::vector<Elf64_Phdr> &program_headers) {
    unsigned long result = 0;

    for (auto &header: program_headers) {
        result = std::max(result, header.p_vaddr + header.p_memsz);
    }

    return result;
}

unsigned long get_max_alignment(const std::vector<Elf64_Phdr> &program_headers) {
    unsigned long result = MAX_PAGE_SIZE;
    for (auto &header: program_headers) {
        result = std::max(result, header.p_align);
    }

    return result;
}

inline unsigned long align_to(unsigned long to_be_aligned, unsigned long alignment) {
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
        const std::vector<Elf64_Shdr> &section_headers
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
            const Elf64_Shdr &section_header = section_headers[section_index];

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
inline unsigned long align_same_as(unsigned long to_be_aligned, const unsigned long objective, unsigned long alignment) {
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

void update_output_program_headers(
        std::vector<Elf64_Phdr> &output_program_headers,
        const std::map<int, Elf64_Phdr> &new_program_headers
        ) {
    for (auto &entry: new_program_headers) {
        output_program_headers.push_back(entry.second);
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

int write_elf_header(int file, const Elf64_Ehdr &elf_header) {
    return pwrite_full(file, (char *) &elf_header, sizeof(elf_header), 0);
}

int write_section_headers(int file, const Elf64_Ehdr &elf_header, const std::vector<Elf64_Shdr> &section_headers) {
    unsigned long offset = elf_header.e_shoff;
    for (auto &header: section_headers) {
        if (pwrite_full(file, (char *) &header, sizeof(header), offset)) {
            return -1;
        }

        offset += elf_header.e_shentsize;
    }

    return 0;
}

int write_program_headers(int file, const Elf64_Ehdr &elf_header, const std::vector<Elf64_Phdr> &program_headers) {
    unsigned long offset = elf_header.e_phoff;
    for (auto &header: program_headers) {
        if (pwrite_full(file, (char *) &header, sizeof(header), offset)) {
            return -1;
        }

        offset += elf_header.e_phentsize;
    }

    return 0;
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

int write_output_no_relocations(int output, int exec, int rel,
        const Elf64_Ehdr &output_elf_header,
        const std::vector<Elf64_Shdr> &output_section_headers,
        const std::vector<Elf64_Phdr> &output_program_headers,
        const std::vector<Elf64_Shdr> &rel_section_headers,
        const std::unordered_map<int, unsigned long> &output_section_absolute_offsets,
        unsigned long exec_file_size,
        unsigned long exec_shift_value
        ) {

    if (copy_data(output, exec, exec_file_size, exec_shift_value)
        || write_elf_header(output, output_elf_header)
        || write_section_headers(output, output_elf_header, output_section_headers)
        || write_program_headers(output, output_elf_header, output_program_headers)
        || copy_sections(output, rel, rel_section_headers, output_section_absolute_offsets)) {
        return -1;
    }

    return 0;
}

inline unsigned long get_program_headers_size(const Elf64_Ehdr &elf_header, unsigned long program_header_count) {
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

int perform_shifts(Elf64_Ehdr &output_elf_header,
        std::vector<Elf64_Shdr> &output_section_headers,
        std::vector<Elf64_Phdr> &output_program_headers,
        unsigned long output_program_headers_count,
        unsigned long exec_shift_value
        ) {
    output_elf_header.e_phoff = output_elf_header.e_ehsize;
    output_elf_header.e_shoff += exec_shift_value;

    for (auto &header: output_section_headers) {
        if (header.sh_type != SHT_NULL) {
            header.sh_offset += exec_shift_value;
        }
    }

    Elf64_Phdr first_load_segment;
    if (get_first_load_segment(first_load_segment, output_program_headers)) {
        return -1;
    }

    first_load_segment.p_filesz += exec_shift_value;
    first_load_segment.p_memsz += exec_shift_value;
    first_load_segment.p_paddr = first_load_segment.p_vaddr -= exec_shift_value;

    bool is_first_load = true;

    for (auto &header: output_program_headers) {
        if (header.p_type == PT_PHDR) {
            header.p_paddr = header.p_vaddr = first_load_segment.p_vaddr + output_elf_header.e_ehsize;
            header.p_offset = output_elf_header.e_phoff;
            header.p_memsz = header.p_filesz =
                    get_program_headers_size(output_elf_header, output_program_headers_count);
        } else if (header.p_type == PT_LOAD && is_first_load) {
            is_first_load = false;
            header = first_load_segment;
        } else if (header.p_vaddr != 0){
            header.p_offset += exec_shift_value;
        }
    }

    return 0;
}

int update_program_header_count(Elf64_Ehdr &elf_header,
        std::vector<Elf64_Shdr> &section_headers,
        const std::vector<Elf64_Phdr> &program_headers
        ) {
    unsigned long count = program_headers.size();

    if (count >= PN_XNUM) {
        if (section_headers.empty()) {
            printf("No first section found in exec file.\n");
            return -1;
        }

        section_headers[0].sh_info = count;
    } else {
        if (!section_headers.empty()) {
            section_headers[0].sh_info = 0;
        }

        elf_header.e_phnum = count;
    }

    return 0;
}

int postlink(int exec, int rel, char *output_path) {
    // TODO - validation
    int exit_code = -1;
    int output;

    Elf64_Ehdr exec_elf_header;
    Elf64_Ehdr rel_elf_header;
    Elf64_Ehdr output_elf_header;

    std::vector<Elf64_Shdr> exec_section_headers;
    std::vector<Elf64_Shdr> rel_section_headers;
    std::vector<Elf64_Shdr> output_section_headers;
    std::vector<Elf64_Shdr> hidden_section_headers;

    std::vector<Elf64_Phdr> exec_program_headers;
    std::vector<Elf64_Phdr> output_program_headers;
    std::map<int, Elf64_Phdr> new_program_headers;

    Elf64_Phdr first_load_segment;

    std::vector<int> section_partition[SEGMENT_KIND_COUNT];

    std::unordered_map<int, unsigned long> hidden_section_addresses;
    std::unordered_map<int, unsigned long> hidden_alloc_section_relative_offsets;
    std::unordered_map<int, unsigned long> hidden_alloc_section_absolute_offsets;

    unsigned long lowest_free_address;
    unsigned long lowest_free_offset;
    unsigned long output_program_headers_count;
    unsigned long exec_file_size;
    unsigned long max_alignment;
    unsigned long exec_shift_value;

    std::unordered_map<std::string, Elf64_Sym> exec_symbol_map;
    std::map<int, std::vector<Elf64_Sym>> rel_symbol_tables;

    if (pread_full(exec, (char *)&exec_elf_header, sizeof(exec_elf_header), 0)
        || pread_full(rel, (char *)&rel_elf_header, sizeof(rel_elf_header), 0)
        || get_section_headers(rel_section_headers, rel, rel_elf_header)
        || get_section_headers(exec_section_headers, exec, exec_elf_header)
        || get_program_headers(exec_program_headers, exec, exec_elf_header)
        || get_first_load_segment(first_load_segment, exec_program_headers)
    ) {
        goto fail_no_close;
    }

    output_elf_header = exec_elf_header;
    output_section_headers = std::vector<Elf64_Shdr>(exec_section_headers);
    hidden_section_headers = std::vector<Elf64_Shdr>(rel_section_headers);
    output_program_headers = std::vector<Elf64_Phdr>(exec_program_headers);

    coalesce_sections(section_partition, rel_section_headers);

    lowest_free_address = get_lowest_free_address(exec_program_headers);

    allocate_segments_no_offset(
            new_program_headers,
            hidden_section_addresses,
            hidden_alloc_section_relative_offsets,
            lowest_free_address,
            section_partition,
            rel_section_headers
    );

    output_program_headers_count = exec_program_headers.size() + new_program_headers.size();

    exec_file_size = get_lowest_free_offset(exec_elf_header, exec_section_headers, exec_program_headers);

    max_alignment = get_max_alignment(exec_program_headers);

    exec_shift_value = align_to(
            exec_elf_header.e_ehsize + get_program_headers_size(exec_elf_header, output_program_headers_count),
            max_alignment
    );

    if (perform_shifts(
            output_elf_header,
            output_section_headers,
            output_program_headers,
            output_program_headers_count,
            exec_shift_value
    )) {
        return -1;
    }

    lowest_free_offset = exec_file_size + exec_shift_value;

    allocate_segment_offsets(new_program_headers, lowest_free_offset);

    update_output_program_headers(output_program_headers, new_program_headers);

    if (update_program_header_count(output_elf_header, output_section_headers, output_program_headers)) {
        goto fail_no_close;
    }

    build_absolute_section_offsets(
            hidden_alloc_section_absolute_offsets,
            hidden_alloc_section_relative_offsets,
            section_partition,
            new_program_headers
    );

    output = open(output_path, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IXUSR);
    if (output < 0) {
        perror("open(output)");
        goto fail_no_close;
    }

    if (write_output_no_relocations(
            output, exec, rel,
            output_elf_header,
            output_section_headers,
            output_program_headers,
            rel_section_headers,
            hidden_alloc_section_absolute_offsets,
            exec_file_size,
            exec_shift_value
        )
    || build_global_symbol_map(exec_symbol_map, output, output_section_headers)
    || get_symbol_tables(rel_symbol_tables, rel, rel_section_headers)
    || update_symbol_tables(
            rel_symbol_tables,
            output_elf_header,
            rel,
            rel_section_headers,
            exec_symbol_map,
            hidden_section_addresses
        )
    || perform_relocations(output, rel, rel_symbol_tables, rel_section_headers, hidden_alloc_section_absolute_offsets, hidden_section_addresses)
    || write_elf_header(output, output_elf_header)
    ) {
        goto fail_close;
    }

    exit_code = 0;

    fail_close:
        if (close(output) < 0) {
            perror("close(output)");
            exit_code = -1;
        };
    fail_no_close:
        return exit_code;
}

int main(int argc, char **argv) {
    int exit_code = -1;
    int input_exec;
    int input_rel;

    if (argc < 4) {
        printf("usage: %s <ET_EXEC file> <ET_REL file> <output file>\n", argv[0]);
        goto fail_no_close;
    }

    input_exec = open(argv[1], O_RDONLY);
    if (input_exec < 0) {
        perror("open(input_exec)");
        goto fail_no_close;
    }
    input_rel = open(argv[2], O_RDONLY);
    if (input_rel < 0) {
        perror("open(input_rel)");
        goto fail_second_close;
    }

    exit_code = postlink(input_exec, input_rel, argv[3]);

    if (close(input_rel) < 0) {
        perror("close(input_rel)");
        exit_code = -1;
    };
    fail_second_close:
        if (close(input_exec) < 0) {
            perror("close(input_exec)");
            exit_code = -1;
        };
    fail_no_close:
        printf(exit_code ? "An error occured.\n" : "Postlinking successful.\n");
        return exit_code;
}

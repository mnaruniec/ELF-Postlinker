#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <elf.h>
#include <fcntl.h>
#include <vector>
#include <unistd.h>
#include <unordered_map>
#include <map>

#define WRITE_SEGMENT (1 << 0)
#define EXEC_SEGMENT (1 << 1)
#define SEGMENT_KIND_COUNT ((EXEC_SEGMENT | WRITE_SEGMENT) + 1)

// TODO
#define PAGE_SIZE (4 * 1024)
#define MAX_PAGE_SIZE PAGE_SIZE

int pread_full(int file, char *buf, size_t bytes, off_t offset) {
    int got = 0;
    while (bytes > 0) {
        got = pread64(file, buf, bytes, offset);

        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("pread64");
            return -1;
        }

        if (got == 0) {
            printf("pread64: Unexpected end of file.");
            return -1;
        }

        buf += got;
        offset += got;
        bytes -= got;
    }

    return 0;
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

unsigned long align_to(unsigned long offset, unsigned long alignment) {
    if (offset % alignment) {
        offset /= alignment;
        offset += alignment;
    }

    return offset;
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
            }
            new_program_header.p_memsz += section_size;

            next_free_address = section_address + section_size;
        }

        new_program_headers[i] = new_program_header;
    }
}

int postlink(int exec, int rel, char *output_path) {
    // TODO - validation
    Elf64_Ehdr exec_hdr;
    Elf64_Ehdr rel_hdr;

    std::vector<Elf64_Shdr> exec_section_headers;
    std::vector<Elf64_Shdr> rel_section_headers;

    std::vector<Elf64_Phdr> exec_program_headers;

    std::vector<int> section_partition[SEGMENT_KIND_COUNT];

    std::map<int, Elf64_Phdr> new_program_headers;
    std::unordered_map<int, unsigned long> new_section_addresses;

    unsigned long lowest_free_address = 0;
    unsigned long lowest_free_offset = 0;

    if (pread_full(exec, (char *)&exec_hdr, sizeof(exec_hdr), 0)
        || pread_full(rel, (char *)&rel_hdr, sizeof(rel_hdr), 0)
        || get_section_headers(rel_section_headers, rel, rel_hdr)
        || get_section_headers(exec_section_headers, exec, exec_hdr)
        || get_program_headers(exec_program_headers, exec, exec_hdr)) {
        return -1;
    }

    coalesce_sections(section_partition, rel_section_headers);

    lowest_free_address = get_lowest_free_address(exec_program_headers);

    allocate_segments_no_offset(
            new_program_headers,
            new_section_addresses,
            lowest_free_address,
            section_partition,
            rel_section_headers
    );

    return 0;
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
        return exit_code;
}

#include <cstdio>
#include <elf.h>
#include <fcntl.h>
#include <vector>
#include <unistd.h>
#include <unordered_map>
#include <map>

#include "constants.h"
#include "relocations.h"
#include "structuring.h"
#include "types.h"


int postlink(int exec_fd, int rel_fd, char *output_path) {
    // TODO - validation
    int exit_code = -1;

    ElfFile exec;
    ElfFile rel;
    ElfFile output;

    exec.fd = exec_fd;
    rel.fd = rel_fd;

    std::map<int, Elf64_Phdr> new_program_headers;

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

    // TODO might change into methods
    if (get_elf_header(exec.elf_header, exec.fd)
        || get_elf_header(rel.elf_header, rel.fd)
        || get_section_headers(rel.section_headers, rel.fd, rel.elf_header)
        || get_section_headers(exec.section_headers, exec.fd, exec.elf_header)
        || get_program_headers(exec.program_headers, exec.fd, exec.elf_header)
    ) {
        goto fail_no_close;
    }

    output.elf_header = exec.elf_header;
    output.section_headers = std::vector<Elf64_Shdr>(exec.section_headers);
    output.program_headers = std::vector<Elf64_Phdr>(exec.program_headers);

    coalesce_sections(section_partition, rel);

    lowest_free_address = get_lowest_free_address(exec);

    allocate_segments_no_offset(
            new_program_headers,
            hidden_section_addresses,
            hidden_alloc_section_relative_offsets,
            lowest_free_address,
            section_partition,
            rel
    );

    output_program_headers_count = exec.program_headers.size() + new_program_headers.size();

    exec_file_size = get_lowest_free_offset(exec);

    max_alignment = get_max_segment_alignment(exec);

    exec_shift_value = align_to(
            exec.elf_header.e_ehsize + get_program_headers_size(exec.elf_header, output_program_headers_count),
            max_alignment
    );

    if (perform_shifts(
            output,
            output_program_headers_count,
            exec_shift_value
    )) {
        return -1;
    }

    lowest_free_offset = exec_file_size + exec_shift_value;

    allocate_segment_offsets(new_program_headers, lowest_free_offset);

    if (update_output_program_headers(output, new_program_headers)) {
        goto fail_no_close;
    }

    build_absolute_section_offsets(
            hidden_alloc_section_absolute_offsets,
            hidden_alloc_section_relative_offsets,
            section_partition,
            new_program_headers
    );

    output.fd = open(output_path, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IXUSR);
    if (output.fd < 0) {
        perror("open(output)");
        goto fail_no_close;
    }

    if (write_output_no_relocations(
            output, exec, rel,
            hidden_alloc_section_absolute_offsets,
            exec_file_size,
            exec_shift_value
        )
    || build_global_symbol_map(exec_symbol_map, output)
    || get_symbol_tables(rel_symbol_tables, rel)
    || update_symbol_tables(
            rel_symbol_tables,
            output,
            rel,
            exec_symbol_map,
            hidden_section_addresses
        )
    || perform_relocations(output, rel,
            rel_symbol_tables, hidden_alloc_section_absolute_offsets, hidden_section_addresses)
    ) {
        goto fail_close;
    }

    exit_code = 0;

    fail_close:
        if (close(output.fd) < 0) {
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

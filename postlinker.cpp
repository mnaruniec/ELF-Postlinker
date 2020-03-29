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
    // TODO handling no section exec?
    int exit_code = -1;

    ElfFile exec;
    ElfFile rel;
    ElfFile output;

    exec.fd = exec_fd;
    rel.fd = rel_fd;

    HiddenSectionsInfo hidden_sections_info;

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

    if (run_structuring_phase(output, hidden_sections_info, exec, rel)) {
        goto fail_no_close;
    }

    output.fd = open(output_path, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IXUSR);
    if (output.fd < 0) {
        perror("open(output)");
        goto fail_no_close;
    }

    if (write_structured_output(output, exec, rel, hidden_sections_info)
        || run_relocation_phase(output, rel, hidden_sections_info)
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

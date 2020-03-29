#include <cstdio>
#include <fcntl.h>
#include <unistd.h>

#include "relocations.h"
#include "structuring.h"
#include "types.h"


int read_headers(ElfFile &exec, ElfFile &rel) {
    if (exec.read_elf_header()
        || rel.read_elf_header()
        || rel.read_section_headers()
        || exec.read_section_headers()
        || exec.read_program_headers()
    ) {
        return -1;
    }

    return 0;
}

int postlink(int exec_fd, int rel_fd, char *output_path) {
    // TODO - validation
    int exit_code = -1;

    ElfFile exec;
    ElfFile rel;
    ElfFile output;

    exec.fd = exec_fd;
    rel.fd = rel_fd;

    HiddenSectionsInfo hidden_sections_info;

    if (read_headers(exec, rel)
        || run_structuring_phase(output, hidden_sections_info, exec, rel)
    ) {
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

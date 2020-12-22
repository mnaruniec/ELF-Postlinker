CLI program for extending and modifying a compiled binary in ELF format.
This was an Advanced Topics in Operating Systems assignment #1 in 2020 at MIMUW faculty.

The program allows adding new segments to an exec ELF file from a rel ELF file and substitute the binary's entrypoint.
It's written in C++, uses standard ELF-related headers in Linux and no external libraries.

#ifndef STRUCTURING_H
#define STRUCTURING_H

#include "types.h"


int run_structuring_phase(ElfFile &output,
                          HiddenSectionsInfo &hidden_sections_info,
                          const ElfFile &exec,
                          const ElfFile &rel
);

int write_structured_output(const ElfFile &output,
                            const ElfFile &exec,
                            const ElfFile &rel,
                            const HiddenSectionsInfo &hidden_sections_info
);

#endif //STRUCTURING_H

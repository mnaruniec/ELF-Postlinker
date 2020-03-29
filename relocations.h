#ifndef RELOCATIONS_H
#define RELOCATIONS_H

#include <elf.h>
#include <map>
#include <unordered_map>
#include <vector>

#include "types.h"


int run_relocation_phase(ElfFile &output, const ElfFile &rel, const HiddenSectionsInfo &hidden_sections_info);

#endif //RELOCATIONS_H

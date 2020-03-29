#ifndef CONSTANTS_H
#define CONSTANTS_H

#define WRITE_SEGMENT (1 << 0)
#define EXEC_SEGMENT (1 << 1)
#define SEGMENT_KIND_COUNT ((EXEC_SEGMENT | WRITE_SEGMENT) + 1)

#define PAGE_SIZE (4 * 1024)

#define ORIG_START_STRING ("orig_start")
#define _START_STRING ("_start")

#endif //CONSTANTS_H

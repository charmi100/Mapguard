#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include "mapguard.h"
#include "mapguard_report_test.h"

int main(void) {
    if (!report_test_init("pool-exhaustion")) {
        return 1;
    }
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    void **mappings = calloc(MG_LEAK_POOL_SIZE + 1, sizeof(*mappings));
    if (!mappings) {
        perror("calloc mappings");
        return 1;
    }

    size_t allocated = 0;
    for (; allocated < MG_LEAK_POOL_SIZE - 1; ++allocated) {
        mappings[allocated] = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mappings[allocated] == MAP_FAILED) {
            perror("pool exhaustion mmap");
            break;
        }
    }
    if (allocated == MG_LEAK_POOL_SIZE - 1) {
        mappings[allocated] = mmap(NULL, page_size * 3, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mappings[allocated] == MAP_FAILED) {
            perror("pool exhaustion split mmap");
        } else {
            allocated++;
        }
    }
    if (allocated == MG_LEAK_POOL_SIZE) {
        mappings[allocated] = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mappings[allocated] == MAP_FAILED) {
            perror("pool exhaustion untracked mmap");
        } else {
            allocated++;
        }
    }
    if (allocated != MG_LEAK_POOL_SIZE + 1) {
        fprintf(stderr, "FAIL: only created %zu of %d mappings\n",
                allocated, MG_LEAK_POOL_SIZE + 1);
        return 1;
    }

    if (!report_assert_pool_state("metadata exhaustion preserves existing records",
                                  MG_LEAK_POOL_SIZE,
                                  (MG_LEAK_POOL_SIZE + 2) * page_size,
                                  1)) {
        return 1;
    }
    if (!report_assert_pool_records("metadata exhaustion report records",
                                    mappings, MG_LEAK_POOL_SIZE - 1,
                                    page_size)) {
        return 1;
    }

    size_t split_index = MG_LEAK_POOL_SIZE - 1;
    if (munmap((char *)mappings[split_index] + page_size, page_size) != 0) {
        perror("pool exhaustion split munmap");
        return 1;
    }
    if (!report_assert_pool_state("exhausted split drops only unrepresentable record",
                                  MG_LEAK_POOL_SIZE - 1,
                                  (MG_LEAK_POOL_SIZE - 1) * page_size,
                                  1) ||
        !report_assert_pool_records("exhausted split preserves other records",
                                    mappings, MG_LEAK_POOL_SIZE - 1,
                                    page_size)) {
        return 1;
    }

    for (size_t i = 0; i < allocated; ++i) {
        size_t cleanup_size = i == split_index ? page_size * 3 : page_size;
        if (i == split_index) {
            if (munmap(mappings[i], page_size) != 0 ||
                munmap((char *)mappings[i] + page_size * 2, page_size) != 0) {
                perror("pool exhaustion split cleanup");
                return 1;
            }
            continue;
        }
        if (munmap(mappings[i], cleanup_size) != 0) {
            perror("pool exhaustion cleanup");
            return 1;
        }
    }
    if (!report_assert_pool_state("metadata exhaustion cleanup",
                                  0, 0, 1)) {
        return 1;
    }

    void *reused = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (reused == MAP_FAILED) {
        perror("pool reuse mmap");
        return 1;
    }
    if (!report_assert_pool_state("metadata slot reuse after cleanup",
                                  1, page_size, 1)) {
        return 1;
    }
    if (munmap(reused, page_size) != 0) {
        perror("pool reuse munmap");
        return 1;
    }
    if (!report_assert_pool_state("metadata slot reuse final cleanup",
                                  0, 0, 1)) {
        return 1;
    }

    free(mappings);
    puts("pool_exhaustion_tests: PASS");
    return 0;
}

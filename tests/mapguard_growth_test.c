#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "mapguard_report_test.h"

static void wait_milliseconds(unsigned int milliseconds) {
    usleep(milliseconds * 1000U);
}

static int run_sustained_growth(void) {
    const size_t block_size = 256 * 1024;
    const size_t block_count = 8;
    void *mappings[block_count];
    expected_mapping_t expected[block_count];
    for (size_t i = 0; i < block_count; ++i) {
        mappings[i] = mmap(NULL, block_size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mappings[i] == MAP_FAILED) {
            perror("sustained growth mmap");
            return 1;
        }
        memset(mappings[i], (int)i, block_size);
        expected[i] = (expected_mapping_t){(uintptr_t)mappings[i], block_size};
        wait_milliseconds(80);
    }

    wait_milliseconds(400);
    if (!report_assert_growth("sustained growth", 1, 5) ||
        !report_assert("sustained growth mappings", block_count,
                       block_count * block_size, block_count * block_size,
                       expected, block_count)) {
        return 1;
    }
    for (size_t i = 0; i < block_count; ++i) {
        if (munmap(mappings[i], block_size) != 0) {
            perror("sustained growth cleanup");
            return 1;
        }
    }
    ASSERT_TRACKER_EMPTY("sustained growth cleanup state",
                         block_count * block_size);
    return 0;
}

static int run_stable_memory(void) {
    const size_t size = 1024 * 1024;
    void *mapping = mmap(NULL, size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) {
        perror("stable memory mmap");
        return 1;
    }
    memset(mapping, 0x66, size);
    wait_milliseconds(800);

    expected_mapping_t expected[] = {{(uintptr_t)mapping, size}};
    if (!report_assert_growth("stable memory", 0, 5) ||
        !report_assert("stable memory state", 1, size, size, expected, 1)) {
        munmap(mapping, size);
        return 1;
    }
    if (munmap(mapping, size) != 0) {
        perror("stable memory cleanup");
        return 1;
    }
    ASSERT_TRACKER_EMPTY("stable memory cleanup", size);
    return 0;
}

static int run_allocate_then_free(void) {
    const size_t block_size = 256 * 1024;
    const size_t block_count = 4;
    void *mappings[block_count];
    for (size_t i = 0; i < block_count; ++i) {
        mappings[i] = mmap(NULL, block_size, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mappings[i] == MAP_FAILED) {
            perror("transient growth mmap");
            return 1;
        }
        memset(mappings[i], 0x77, block_size);
        wait_milliseconds(70);
    }
    wait_milliseconds(120);
    for (size_t i = 0; i < block_count; ++i) {
        if (munmap(mappings[i], block_size) != 0) {
            perror("transient growth munmap");
            return 1;
        }
    }
    wait_milliseconds(700);

    if (!report_assert_growth("allocate then free", 0, 5)) {
        return 1;
    }
    ASSERT_TRACKER_EMPTY("allocate then free state",
                         block_count * block_size);
    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2 || !report_test_init("growth")) {
        fprintf(stderr, "Usage: %s sustained|stable|transient\n", argv[0]);
        return 2;
    }
    int result;
    if (strcmp(argv[1], "sustained") == 0) {
        result = run_sustained_growth();
    } else if (strcmp(argv[1], "stable") == 0) {
        result = run_stable_memory();
    } else if (strcmp(argv[1], "transient") == 0) {
        result = run_allocate_then_free();
    } else {
        fprintf(stderr, "Unknown growth test scenario: %s\n", argv[1]);
        return 2;
    }
    if (result != 0) {
        printf("growth_tests: FAIL (%s)\n", argv[1]);
        return 1;
    }
    printf("growth_tests: PASS (%s)\n", argv[1]);
    return 0;
}

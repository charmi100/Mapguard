#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "mapguard_report_test.h"

static int map_region(size_t ps, size_t pages, void **out) {
    *out = mmap(NULL, ps * pages, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (*out == MAP_FAILED) {
        perror("partial test mmap");
        return 0;
    }
    return 1;
}

static int test_full_and_failed_unmap(size_t ps) {
    void *ptr;
    if (!map_region(ps, 4, &ptr)) {
        return 1;
    }
    expected_mapping_t expected[] = {{(uintptr_t)ptr, ps * 4}};
    ASSERT_TRACKER("full unmap after mmap", 1, ps * 4, ps * 4, expected);

    errno = 0;
    if (munmap((char *)ptr + 1, ps) != -1 || errno != EINVAL) {
        fprintf(stderr, "FAIL: invalid unmap did not return -1/EINVAL\n");
        munmap(ptr, ps * 4);
        return 1;
    }
    ASSERT_TRACKER("failed unmap preserves mapping", 1, ps * 4, ps * 4,
                   expected);

    if (munmap(ptr, ps * 4) != 0) {
        perror("full munmap");
        return 1;
    }
    ASSERT_TRACKER_EMPTY("full unmap after munmap", ps * 4);
    return 0;
}

static int test_beginning_unmap(size_t ps) {
    void *ptr;
    if (!map_region(ps, 4, &ptr)) {
        return 1;
    }
    expected_mapping_t expected[] = {{(uintptr_t)ptr, ps * 4}};
    ASSERT_TRACKER("beginning after mmap", 1, ps * 4, ps * 4, expected);

    if (munmap(ptr, ps) != 0) {
        perror("beginning munmap");
        return 1;
    }
    expected[0] = (expected_mapping_t){(uintptr_t)ptr + ps, ps * 3};
    ASSERT_TRACKER("beginning after partial munmap", 1, ps * 3, ps * 4,
                   expected);

    if (munmap((char *)ptr + ps, ps * 3) != 0) {
        perror("beginning cleanup");
        return 1;
    }
    ASSERT_TRACKER_EMPTY("beginning after cleanup", ps * 4);
    return 0;
}

static int test_ending_unmap(size_t ps) {
    void *ptr;
    if (!map_region(ps, 4, &ptr)) {
        return 1;
    }
    expected_mapping_t expected[] = {{(uintptr_t)ptr, ps * 4}};
    ASSERT_TRACKER("ending after mmap", 1, ps * 4, ps * 4, expected);

    if (munmap((char *)ptr + ps * 3, ps) != 0) {
        perror("ending munmap");
        return 1;
    }
    expected[0] = (expected_mapping_t){(uintptr_t)ptr, ps * 3};
    ASSERT_TRACKER("ending after partial munmap", 1, ps * 3, ps * 4,
                   expected);

    if (munmap(ptr, ps * 3) != 0) {
        perror("ending cleanup");
        return 1;
    }
    ASSERT_TRACKER_EMPTY("ending after cleanup", ps * 4);
    return 0;
}

static int test_middle_split(size_t ps) {
    void *ptr;
    if (!map_region(ps, 4, &ptr)) {
        return 1;
    }
    expected_mapping_t expected[2] = {{(uintptr_t)ptr, ps * 4}};
    if (!report_assert("middle after mmap", 1, ps * 4, ps * 4,
                       expected, 1)) {
        return 1;
    }

    if (munmap((char *)ptr + ps, ps * 2) != 0) {
        perror("middle munmap");
        return 1;
    }
    expected[0] = (expected_mapping_t){(uintptr_t)ptr, ps};
    expected[1] = (expected_mapping_t){(uintptr_t)ptr + ps * 3, ps};
    ASSERT_TRACKER("middle after split", 2, ps * 2, ps * 4, expected);

    if (munmap(ptr, ps) != 0) {
        perror("middle lower cleanup");
        return 1;
    }
    expected[0] = expected[1];
    if (!report_assert("middle after lower cleanup", 1, ps, ps * 4,
                       expected, 1)) {
        return 1;
    }
    if (munmap((char *)ptr + ps * 3, ps) != 0) {
        perror("middle upper cleanup");
        return 1;
    }
    ASSERT_TRACKER_EMPTY("middle after cleanup", ps * 4);
    return 0;
}

static int test_repeated_partial_unmap(size_t ps) {
    void *ptr;
    if (!map_region(ps, 8, &ptr)) {
        return 1;
    }
    expected_mapping_t expected[2] = {{(uintptr_t)ptr, ps * 8}};
    if (!report_assert("repeated after mmap", 1, ps * 8, ps * 8,
                       expected, 1)) {
        return 1;
    }

    if (munmap(ptr, ps) != 0) {
        perror("repeated beginning unmap");
        return 1;
    }
    expected[0] = (expected_mapping_t){(uintptr_t)ptr + ps, ps * 7};
    if (!report_assert("repeated after beginning unmap", 1, ps * 7,
                       ps * 8, expected, 1)) {
        return 1;
    }

    if (munmap((char *)ptr + ps * 3, ps * 2) != 0) {
        perror("repeated split unmap");
        return 1;
    }
    expected[0] = (expected_mapping_t){(uintptr_t)ptr + ps, ps * 2};
    expected[1] = (expected_mapping_t){(uintptr_t)ptr + ps * 5, ps * 3};
    ASSERT_TRACKER("repeated after split", 2, ps * 5, ps * 8, expected);

    if (munmap((char *)ptr + ps * 2, ps) != 0) {
        perror("repeated lower ending unmap");
        return 1;
    }
    expected[0] = (expected_mapping_t){(uintptr_t)ptr + ps, ps};
    ASSERT_TRACKER("repeated after lower ending unmap", 2, ps * 4, ps * 8,
                   expected);

    if (munmap((char *)ptr + ps, ps) != 0) {
        perror("repeated lower cleanup");
        return 1;
    }
    expected[0] = expected[1];
    if (!report_assert("repeated after lower cleanup", 1, ps * 3, ps * 8,
                       expected, 1)) {
        return 1;
    }
    if (munmap((char *)ptr + ps * 5, ps * 3) != 0) {
        perror("repeated upper cleanup");
        return 1;
    }
    ASSERT_TRACKER_EMPTY("repeated after cleanup", ps * 8);
    return 0;
}

int main(void) {
    if (!report_test_init("munmap")) {
        return 1;
    }
    size_t ps = (size_t)sysconf(_SC_PAGESIZE);
    if (!ps || (ps & (ps - 1)) != 0) {
        fprintf(stderr, "FAIL: invalid page size %zu\n", ps);
        return 1;
    }

    int failures = 0;
    failures += test_full_and_failed_unmap(ps);
    failures += test_beginning_unmap(ps);
    failures += test_ending_unmap(ps);
    failures += test_middle_split(ps);
    failures += test_repeated_partial_unmap(ps);
    if (failures != 0) {
        printf("munmap_tests: FAIL (%d scenario(s))\n", failures);
        return 1;
    }
    puts("munmap_tests: PASS");
    return 0;
}

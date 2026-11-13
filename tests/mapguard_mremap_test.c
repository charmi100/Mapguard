#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "mapguard_report_test.h"

static int test_expand(void) {
    size_t ps = (size_t)sysconf(_SC_PAGESIZE);
    void *ptr = mmap(NULL, ps * 4, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        perror("expand mmap");
        return 1;
    }
    expected_mapping_t expected[] = {{(uintptr_t)ptr, ps * 4}};
    ASSERT_TRACKER("expand after mmap", 1, ps * 4, ps * 4, expected);

    memset(ptr, 0xA5, ps * 4);
    void *resized = mremap(ptr, ps * 4, ps * 8, MREMAP_MAYMOVE);
    if (resized == MAP_FAILED) {
        perror("expand mremap");
        munmap(ptr, ps * 4);
        return 1;
    }
    expected[0] = (expected_mapping_t){(uintptr_t)resized, ps * 8};
    ASSERT_TRACKER("expand after mremap", 1, ps * 8, ps * 8, expected);
    for (size_t i = 0; i < ps * 4; ++i) {
        if (((unsigned char *)resized)[i] != 0xA5) {
            fprintf(stderr, "FAIL: expand data mismatch at offset %zu\n", i);
            munmap(resized, ps * 8);
            return 1;
        }
    }
    puts("PASS: expand data preservation");
    if (munmap(resized, ps * 8) != 0) {
        perror("expand munmap");
        return 1;
    }
    ASSERT_TRACKER_EMPTY("expand after cleanup", ps * 8);
    return 0;
}

static int test_shrink(void) {
    size_t ps = (size_t)sysconf(_SC_PAGESIZE);
    void *ptr = mmap(NULL, ps * 8, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        perror("shrink mmap");
        return 1;
    }
    expected_mapping_t expected[] = {{(uintptr_t)ptr, ps * 8}};
    ASSERT_TRACKER("shrink after mmap", 1, ps * 8, ps * 8, expected);
    memset(ptr, 0x5A, ps * 8);

    void *resized = mremap(ptr, ps * 8, ps * 4, 0);
    if (resized == MAP_FAILED) {
        perror("shrink mremap");
        munmap(ptr, ps * 8);
        return 1;
    }
    if (resized != ptr) {
        fprintf(stderr, "FAIL: shrinking unexpectedly moved mapping\n");
        munmap(resized, ps * 4);
        return 1;
    }
    expected[0] = (expected_mapping_t){(uintptr_t)resized, ps * 4};
    ASSERT_TRACKER("shrink after mremap", 1, ps * 4, ps * 8, expected);
    for (size_t i = 0; i < ps * 4; ++i) {
        if (((unsigned char *)resized)[i] != 0x5A) {
            fprintf(stderr, "FAIL: shrink data mismatch at offset %zu\n", i);
            munmap(resized, ps * 4);
            return 1;
        }
    }
    puts("PASS: shrink data preservation and stable address");
    if (munmap(resized, ps * 4) != 0) {
        perror("shrink munmap");
        return 1;
    }
    ASSERT_TRACKER_EMPTY("shrink after cleanup", ps * 8);
    return 0;
}

static int test_resize_without_move(void) {
    size_t ps = (size_t)sysconf(_SC_PAGESIZE);
    void *ptr = mmap(NULL, ps * 4, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        perror("no-move mmap");
        return 1;
    }
    expected_mapping_t expected[] = {{(uintptr_t)ptr, ps * 4}};
    ASSERT_TRACKER("no-move resize after mmap", 1, ps * 4, ps * 4, expected);
    memset(ptr, 0x7E, ps * 4);

    errno = 0;
    void *resized = mremap(ptr, ps * 4, ps * 6, 0);
    int resize_errno = errno;
    size_t tracked_size = ps * 4;
    uint64_t peak_bytes = ps * 4;
    if (resized == MAP_FAILED) {
        if (resize_errno != ENOMEM) {
            fprintf(stderr, "FAIL: no-move resize expected ENOMEM, got %d\n", resize_errno);
            munmap(ptr, ps * 4);
            return 1;
        }
        ASSERT_TRACKER("no-move failed resize preserves source", 1, ps * 4,
                       ps * 4, expected);
        puts("PASS: no-move expansion refused without changing address or size");
        resized = ptr;
    } else {
        if (resized != ptr) {
            fprintf(stderr, "FAIL: no-move resize changed mapping address\n");
            munmap(resized, ps * 6);
            return 1;
        }
        expected[0] = (expected_mapping_t){(uintptr_t)resized, ps * 6};
        ASSERT_TRACKER("no-move successful resize", 1, ps * 6, ps * 6, expected);
        tracked_size = ps * 6;
        peak_bytes = ps * 6;
        puts("PASS: no-move resize succeeded in place");
    }

    if (memcmp(resized, (const unsigned char[]){0x7E}, 1) != 0) {
        fprintf(stderr, "FAIL: no-move resize did not preserve data\n");
        munmap(resized, tracked_size);
        return 1;
    }
    if (munmap(resized, tracked_size) != 0) {
        perror("no-move munmap");
        return 1;
    }
    ASSERT_TRACKER_EMPTY("no-move resize after cleanup", peak_bytes);
    return 0;
}

static int test_move_fixed(void) {
    size_t ps = (size_t)sysconf(_SC_PAGESIZE);
    void *ptr = mmap(NULL, ps * 4, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        perror("fixed move mmap");
        return 1;
    }
    expected_mapping_t expected[2] = {{(uintptr_t)ptr, ps * 4}};
    if (!report_assert("fixed move after source mmap", 1, ps * 4, ps * 4,
                       expected, 1)) {
        return 1;
    }
    memset(ptr, 0xC3, ps * 4);

    void *target = mmap(NULL, ps * 8, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (target == MAP_FAILED) {
        perror("fixed move target mmap");
        munmap(ptr, ps * 4);
        return 1;
    }
    expected[1] = (expected_mapping_t){(uintptr_t)target, ps * 8};
    ASSERT_TRACKER("fixed move after target mmap", 2, ps * 12,
                   ps * 12, expected);

    void *moved = mremap(ptr, ps * 4, ps * 8,
                         MREMAP_FIXED | MREMAP_MAYMOVE, target);
    if (moved == MAP_FAILED) {
        perror("fixed mremap");
        munmap(ptr, ps * 4);
        return 1;
    }
    if (moved != target) {
        fprintf(stderr, "FAIL: fixed mremap returned unexpected address\n");
        munmap(moved, ps * 8);
        return 1;
    }
    expected[0] = (expected_mapping_t){(uintptr_t)moved, ps * 8};
    if (!report_assert("fixed move after mremap", 1, ps * 8, ps * 12,
                       expected, 1)) {
        return 1;
    }
    for (size_t i = 0; i < ps * 4; ++i) {
        if (((unsigned char *)moved)[i] != 0xC3) {
            fprintf(stderr, "FAIL: fixed move data mismatch at offset %zu\n", i);
            munmap(moved, ps * 8);
            return 1;
        }
    }
    puts("PASS: fixed move data preservation");
    if (munmap(moved, ps * 8) != 0) {
        perror("fixed move final munmap");
        return 1;
    }
    ASSERT_TRACKER_EMPTY("fixed move after cleanup", ps * 12);
    return 0;
}

static int test_nonfixed_maymove(void) {
    size_t ps = (size_t)sysconf(_SC_PAGESIZE);
    void *ptr = mmap(NULL, ps * 4, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        perror("MAYMOVE mmap");
        return 1;
    }
    expected_mapping_t expected[] = {{(uintptr_t)ptr, ps * 4}};
    ASSERT_TRACKER("MAYMOVE after mmap", 1, ps * 4, ps * 4, expected);
    memset(ptr, 0x96, ps * 4);

    void *resized = mremap(ptr, ps * 4, ps * 8, MREMAP_MAYMOVE);
    if (resized == MAP_FAILED) {
        perror("MAYMOVE mremap");
        munmap(ptr, ps * 4);
        return 1;
    }
    expected[0] = (expected_mapping_t){(uintptr_t)resized, ps * 8};
    ASSERT_TRACKER("MAYMOVE after mremap", 1, ps * 8, ps * 8, expected);
    for (size_t i = 0; i < ps * 4; ++i) {
        if (((unsigned char *)resized)[i] != 0x96) {
            fprintf(stderr, "FAIL: MAYMOVE data mismatch at offset %zu\n", i);
            munmap(resized, ps * 8);
            return 1;
        }
    }
    if (resized == ptr) {
        puts("PASS: non-fixed MAYMOVE resize (kernel kept the address)");
    } else {
        printf("PASS: non-fixed MAYMOVE resize (kernel moved %p to %p)\n", ptr, resized);
    }
    if (munmap(resized, ps * 8) != 0) {
        perror("MAYMOVE munmap");
        return 1;
    }
    ASSERT_TRACKER_EMPTY("MAYMOVE after cleanup", ps * 8);
    return 0;
}

static int test_failed_mremap(void) {
    size_t ps = (size_t)sysconf(_SC_PAGESIZE);
    void *ptr = mmap(NULL, ps * 4, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (ptr == MAP_FAILED) {
        perror("failed mremap mmap");
        return 1;
    }
    expected_mapping_t expected[] = {{(uintptr_t)ptr, ps * 4}};
    ASSERT_TRACKER("failed mremap after mmap", 1, ps * 4, ps * 4, expected);
    memset(ptr, 0x11, ps * 4);

    errno = 0;
    void *resized = mremap(ptr, ps * 4, 0, MREMAP_MAYMOVE);
    if (resized != MAP_FAILED || errno != EINVAL) {
        fprintf(stderr, "FAIL: failed mremap expected MAP_FAILED/EINVAL, got %p/%d\n",
                resized, errno);
        if (resized != MAP_FAILED) {
            munmap(resized, ps * 4);
        }
        munmap(ptr, ps * 4);
        return 1;
    }
    ASSERT_TRACKER("failed mremap preserves original", 1, ps * 4, ps * 4,
                   expected);
    if (((unsigned char *)ptr)[0] != 0x11) {
        fprintf(stderr, "FAIL: original data changed after failed mremap\n");
        munmap(ptr, ps * 4);
        return 1;
    }
    puts("PASS: failed mremap preserved original mapping and data");

    if (munmap(ptr, ps * 4) != 0) {
        perror("failed mremap cleanup");
        return 1;
    }
    ASSERT_TRACKER_EMPTY("failed mremap after cleanup", ps * 4);
    return 0;
}

int main(void) {
    if (!report_test_init("mremap")) {
        return 1;
    }
    int failures = 0;
    failures += test_expand();
    failures += test_shrink();
    failures += test_resize_without_move();
    failures += test_move_fixed();
    failures += test_nonfixed_maymove();
    failures += test_failed_mremap();
    if (failures != 0) {
        printf("mremap_tests: FAIL (%d scenario(s))\n", failures);
        return 1;
    }
    puts("mremap_tests: PASS");
    return 0;
}

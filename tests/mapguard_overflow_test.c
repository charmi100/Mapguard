#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

#include "mapguard_report_test.h"

int main(void) {
    if (!report_test_init("overflow")) {
        return 1;
    }

    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    if (page_size == 0 || (page_size & (page_size - 1)) != 0) {
        fprintf(stderr, "FAIL: invalid page size %zu\n", page_size);
        return 1;
    }

    errno = 0;
    if (mmap(NULL, SIZE_MAX, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) != MAP_FAILED ||
        errno != EINVAL) {
        fprintf(stderr, "FAIL: overflowing mmap length expected EINVAL, got %d\n",
                errno);
        return 1;
    }
    if (!report_assert_pool_state("overflowing mmap leaves tracker unchanged",
                                  0, 0, 0)) {
        return 1;
    }

    size_t guarded_overflow_length = SIZE_MAX - (page_size - 1);
    errno = 0;
    if (mmap(NULL, guarded_overflow_length, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) != MAP_FAILED ||
        errno != ENOMEM) {
        fprintf(stderr, "FAIL: guard-size overflow expected ENOMEM, got %d\n",
                errno);
        return 1;
    }
    if (!report_assert_pool_state("guard-size overflow leaves tracker unchanged",
                                  0, 0, 0)) {
        return 1;
    }

    void *mapping = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) {
        perror("overflow test mmap");
        return 1;
    }
    expected_mapping_t expected[] = {
        {(uintptr_t)mapping, page_size}
    };
    ASSERT_TRACKER("overflow test after mmap", 1, page_size, page_size,
                   expected);

    errno = 0;
    void *resized = mremap(mapping, page_size, SIZE_MAX, MREMAP_MAYMOVE);
    if (resized != MAP_FAILED || errno != EINVAL) {
        fprintf(stderr, "FAIL: overflowing mremap length expected EINVAL, got %d\n",
                errno);
        if (resized != MAP_FAILED) {
            munmap(resized, SIZE_MAX);
        }
        return 1;
    }
    ASSERT_TRACKER("overflowing mremap preserves source", 1, page_size,
                   page_size, expected);

    uintptr_t invalid_address = UINTPTR_MAX & ~(uintptr_t)(page_size - 1);
    errno = 0;
    if (munmap((void *)invalid_address, page_size * 2) != -1 ||
        errno != EINVAL) {
        fprintf(stderr, "FAIL: overflowing munmap range expected EINVAL, got %d\n",
                errno);
        return 1;
    }
    ASSERT_TRACKER("overflowing munmap preserves source", 1, page_size,
                   page_size, expected);

    if (munmap(mapping, page_size) != 0) {
        perror("overflow test cleanup");
        return 1;
    }
    ASSERT_TRACKER_EMPTY("overflow test cleanup state", page_size);
    puts("overflow_tests: PASS");
    return 0;
}

#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>

#include "mapguard_report_test.h"

static int expect_guard_fault(volatile unsigned char *address,
                              const char *description) {
    pid_t child = fork();
    if (child < 0) {
        perror("fork");
        return 0;
    }
    if (child == 0) {
        *address = 0xA5;
        _exit(0);
    }

    int status;
    if (waitpid(child, &status, 0) != child) {
        perror("waitpid");
        return 0;
    }
    if (!WIFSIGNALED(status) ||
        (WTERMSIG(status) != SIGSEGV && WTERMSIG(status) != SIGBUS)) {
        fprintf(stderr, "FAIL: %s did not fault (status=0x%x)\n",
                description, status);
        return 0;
    }
    printf("PASS: %s rejected access with signal %d\n",
           description, WTERMSIG(status));
    return 1;
}

int main(void) {
    struct rlimit no_core = {0, 0};
    if (setrlimit(RLIMIT_CORE, &no_core) != 0) {
        perror("setrlimit");
        return 1;
    }
    if (getenv("MG_ENABLE_GUARD_PAGES") == NULL ||
        atoi(getenv("MG_ENABLE_GUARD_PAGES")) != 1) {
        fprintf(stderr, "FAIL: guard-page test requires MG_ENABLE_GUARD_PAGES=1\n");
        return 1;
    }
    if (!report_test_init("guard-pages")) {
        return 1;
    }

    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    size_t mapping_size = page_size * 2;
    unsigned char *mapping = mmap(NULL, mapping_size, PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (mapping == MAP_FAILED) {
        perror("guard-page mmap");
        return 1;
    }
    mapping[0] = 0x51;
    mapping[mapping_size - 1] = 0x52;

    expected_mapping_t expected[] = {
        {(uintptr_t)mapping, mapping_size}
    };
    if (!report_assert("guard mapping excludes internal pages", 1,
                       mapping_size, mapping_size, expected, 1)) {
        return 1;
    }
    if (!expect_guard_fault(mapping - page_size, "lower guard page") ||
        !expect_guard_fault(mapping + mapping_size, "upper guard page")) {
        return 1;
    }

    if (munmap(mapping, mapping_size) != 0) {
        perror("guard-page munmap");
        return 1;
    }
    ASSERT_TRACKER_EMPTY("guard mapping cleanup", mapping_size);
    puts("guard_page_tests: PASS");
    return 0;
}

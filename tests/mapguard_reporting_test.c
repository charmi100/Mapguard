#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

__attribute__((noinline)) void *report_test_allocate(size_t size) {
    return mmap(NULL, size, PROT_READ | PROT_WRITE,
                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s FORMAT REPORT_PATH\n", argv[0]);
        return 2;
    }
    if (setenv("MG_REPORT_FORMAT", argv[1], 1) != 0 ||
        setenv("MG_REPORT_PATH", argv[2], 1) != 0) {
        perror("setenv report configuration");
        return 1;
    }
    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    void *mapping = report_test_allocate(page_size);
    if (mapping == MAP_FAILED) {
        perror("report mmap");
        return 1;
    }
    printf("address=%p size=%zu\n", mapping, page_size);
    return 0;
}

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#define MAX_TEST_MAPPINGS 300

typedef void (*report_fn_t)(void);

__attribute__((noinline)) void *report_test_allocate(size_t size) {
    void * volatile mapping = mmap(NULL, size, PROT_READ | PROT_WRITE,
                                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    return mapping;
}

static void cleanup_mappings(void **mappings, size_t count, size_t size) {
    for (size_t i = 0; i < count; i++) {
        if (mappings[i] != MAP_FAILED && mappings[i] != NULL) {
            munmap(mappings[i], size);
            mappings[i] = NULL;
        }
    }
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s FORMAT REPORT_PATH MAPPING_COUNT\n", argv[0]);
        return 2;
    }

    size_t mapping_count = 0;
    for (const char *digit = argv[3]; *digit; digit++) {
        if (*digit < '0' || *digit > '9') {
            fprintf(stderr, "Invalid mapping count: %s\n", argv[3]);
            return 2;
        }
        size_t value = (size_t)(*digit - '0');
        if (mapping_count > MAX_TEST_MAPPINGS / 10 ||
            (mapping_count == MAX_TEST_MAPPINGS / 10 &&
             value > MAX_TEST_MAPPINGS % 10)) {
            fprintf(stderr, "Invalid mapping count: %s\n", argv[3]);
            return 2;
        }
        mapping_count = mapping_count * 10 + value;
    }
    if (!argv[3][0] || mapping_count == 0) {
        fprintf(stderr, "Invalid mapping count: %s\n", argv[3]);
        return 2;
    }

    void *symbol = dlsym(RTLD_DEFAULT, "mg_tracker_generate_report");
    report_fn_t generate_report;
    if (!symbol || sizeof(symbol) != sizeof(generate_report)) {
        fprintf(stderr, "Unable to resolve MapGuard report generator\n");
        return 1;
    }
    memcpy(&generate_report, &symbol, sizeof(generate_report));

    size_t report_path_length = strlen(argv[2]);
    char *cleanup_report_path = malloc(report_path_length + sizeof(".cleanup"));
    if (!cleanup_report_path) {
        perror("malloc cleanup report path");
        return 1;
    }
    snprintf(cleanup_report_path, report_path_length + sizeof(".cleanup"),
             "%s.cleanup", argv[2]);

    if (setenv("MG_REPORT_FORMAT", argv[1], 1) != 0 ||
        setenv("MG_REPORT_PATH", argv[2], 1) != 0) {
        perror("setenv report configuration");
        free(cleanup_report_path);
        return 1;
    }

    size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    void *mappings[MAX_TEST_MAPPINGS] = {0};
    for (size_t i = 0; i < mapping_count; i++) {
        mappings[i] = report_test_allocate(page_size);
        if (mappings[i] == MAP_FAILED) {
            perror("report mmap");
            cleanup_mappings(mappings, i, page_size);
            free(cleanup_report_path);
            return 1;
        }
    }

    printf("address=%p size=%zu mapping_count=%zu\n",
           mappings[0], page_size, mapping_count);
    generate_report();

    int result = 0;
    for (size_t i = 0; i < mapping_count; i++) {
        if (munmap(mappings[i], page_size) != 0) {
            perror("report munmap");
            result = 1;
        } else {
            mappings[i] = NULL;
        }
    }

    if (setenv("MG_REPORT_PATH", cleanup_report_path, 1) != 0) {
        perror("setenv cleanup report path");
        result = 1;
    } else {
        generate_report();
    }

    free(cleanup_report_path);
    return result;
}

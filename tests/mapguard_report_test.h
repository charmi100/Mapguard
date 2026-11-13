#pragma once

#define _GNU_SOURCE
#include <dlfcn.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    uintptr_t addr;
    size_t size;
} expected_mapping_t;

typedef struct {
    uint64_t outstanding;
    uint64_t current_bytes;
    uint64_t peak_bytes;
    size_t snapshots_collected;
    int growth_warning;
    int pool_exhausted;
    expected_mapping_t mappings[256];
    size_t mapping_count;
} parsed_report_t;

static void (*mapguard_report_fn)(void);
static char mapguard_report_prefix[256];
static unsigned int mapguard_report_index;
static parsed_report_t mapguard_report_baseline;
static uint64_t mapguard_report_peak;

static int read_report(parsed_report_t *report);

static int report_test_init(const char *test_name) {
    void *symbol = dlsym(RTLD_DEFAULT, "mg_tracker_generate_report");
    if (!symbol || sizeof(symbol) != sizeof(mapguard_report_fn)) {
        fprintf(stderr, "FAIL: cannot locate MapGuard report generator\n");
        return 0;
    }
    memcpy(&mapguard_report_fn, &symbol, sizeof(mapguard_report_fn));
    snprintf(mapguard_report_prefix, sizeof(mapguard_report_prefix),
             "/tmp/mapguard-%s-%ld", test_name, (long)getpid());
    char path[320];
    snprintf(path, sizeof(path), "%s-initial.txt", mapguard_report_prefix);
    if (setenv("MG_REPORT_PATH", path, 1) != 0) {
        perror("setenv MG_REPORT_PATH");
        return 0;
    }
    mapguard_report_fn();
    if (!read_report(&mapguard_report_baseline)) {
        fprintf(stderr, "FAIL: initial MapGuard report could not be read\n");
        return 0;
    }
    mapguard_report_peak = mapguard_report_baseline.peak_bytes;
    return 1;
}

static int read_report(parsed_report_t *report) {
    const char *path = getenv("MG_REPORT_PATH");
    if (!path || !path[0]) {
        fprintf(stderr, "FAIL: MG_REPORT_PATH is unset\n");
        return 0;
    }

    FILE *fp = fopen(path, "r");
    if (!fp) {
        perror("fopen report");
        return 0;
    }

    memset(report, 0, sizeof(*report));
    char *line = NULL;
    size_t capacity = 0;
    while (getline(&line, &capacity, fp) >= 0) {
        unsigned long long value;
        if (sscanf(line, " Total allocations tracked: %llu", &value) == 1) {
            continue;
        }
        if (sscanf(line, " Outstanding mappings: %llu", &value) == 1) {
            report->outstanding = value;
            continue;
        }
        if (sscanf(line, " Current mapped bytes: %llu", &value) == 1) {
            report->current_bytes = value;
            continue;
        }
        if (sscanf(line, " Peak mapped bytes: %llu", &value) == 1) {
            report->peak_bytes = value;
            continue;
        }
        if (sscanf(line, " Snapshots collected: %zu",
                   &report->snapshots_collected) == 1) {
            continue;
        }
        if (strstr(line, "*** GROWTH WARNING ***")) {
            report->growth_warning = 1;
        }
        if (strstr(line, "*** WARNING: Tracking pool exhausted")) {
            report->pool_exhausted = 1;
        }

        size_t index, size;
        unsigned long address;
        if (sscanf(line, " %zu  0x%lx  %zu", &index, &address, &size) == 3) {
            if (report->mapping_count == sizeof(report->mappings) / sizeof(report->mappings[0])) {
                fprintf(stderr, "FAIL: report has too many mappings to validate\n");
                free(line);
                fclose(fp);
                return 0;
            }
            report->mappings[report->mapping_count].addr = (uintptr_t)address;
            report->mappings[report->mapping_count].size = size;
            report->mapping_count++;
        }
    }
    free(line);
    fclose(fp);
    return 1;
}

static inline int report_assert(const char *stage, uint64_t outstanding,
                                uint64_t current_bytes, uint64_t peak_bytes,
                                const expected_mapping_t *expected,
                                size_t expected_count) {
    char path[320];
    snprintf(path, sizeof(path), "%s-%u.txt", mapguard_report_prefix,
             mapguard_report_index++);
    if (setenv("MG_REPORT_PATH", path, 1) != 0) {
        perror("setenv MG_REPORT_PATH");
        return 0;
    }
    mapguard_report_fn();

    parsed_report_t actual;
    if (!read_report(&actual)) {
        fprintf(stderr, "FAIL: %s report could not be read\n", stage);
        return 0;
    }
    if (actual.peak_bytes > mapguard_report_peak) {
        mapguard_report_peak = actual.peak_bytes;
    }
    uint64_t expected_total_count =
        mapguard_report_baseline.outstanding + outstanding;
    uint64_t expected_total_bytes =
        mapguard_report_baseline.current_bytes + current_bytes;
    uint64_t expected_peak = peak_bytes > mapguard_report_peak
                                 ? peak_bytes
                                 : mapguard_report_peak;
    size_t expected_total_records =
        mapguard_report_baseline.mapping_count + expected_count;
    if (actual.outstanding != expected_total_count ||
        actual.current_bytes != expected_total_bytes ||
        actual.peak_bytes != expected_peak ||
        actual.mapping_count != expected_total_records) {
        fprintf(stderr,
                "FAIL: %s summary expected count=%" PRIu64 " bytes=%" PRIu64
                " peak=%" PRIu64 " records=%zu; got count=%" PRIu64
                " bytes=%" PRIu64 " peak=%" PRIu64 " records=%zu\n",
                stage, expected_total_count, expected_total_bytes, expected_peak,
                expected_total_records,
                actual.outstanding, actual.current_bytes, actual.peak_bytes,
                actual.mapping_count);
        return 0;
    }

    for (size_t i = 0; i < expected_total_records; ++i) {
        const expected_mapping_t *item =
            i < mapguard_report_baseline.mapping_count
                ? &mapguard_report_baseline.mappings[i]
                : &expected[i - mapguard_report_baseline.mapping_count];
        int found = 0;
        for (size_t j = 0; j < actual.mapping_count; ++j) {
            if (actual.mappings[j].addr == item->addr &&
                actual.mappings[j].size == item->size) {
                found = 1;
                break;
            }
        }
        if (!found) {
            fprintf(stderr, "FAIL: %s missing mapping addr=%p size=%zu\n",
                    stage, (void *)item->addr, item->size);
            return 0;
        }
    }
    printf("PASS: %s tracker state\n", stage);
    return 1;
}

static inline int report_assert_pool_state(const char *stage,
                                           uint64_t expected_outstanding,
                                           uint64_t expected_bytes,
                                           int expected_pool_exhausted) {
    char path[320];
    snprintf(path, sizeof(path), "%s-pool-%u.txt", mapguard_report_prefix,
             mapguard_report_index++);
    if (setenv("MG_REPORT_PATH", path, 1) != 0) {
        perror("setenv MG_REPORT_PATH");
        return 0;
    }
    mapguard_report_fn();

    parsed_report_t actual;
    if (!read_report(&actual)) {
        fprintf(stderr, "FAIL: %s report could not be read\n", stage);
        return 0;
    }
    uint64_t expected_count =
        mapguard_report_baseline.outstanding + expected_outstanding;
    uint64_t expected_total_bytes =
        mapguard_report_baseline.current_bytes + expected_bytes;
    if (actual.outstanding != expected_count ||
        actual.current_bytes != expected_total_bytes ||
        actual.pool_exhausted != expected_pool_exhausted) {
        fprintf(stderr,
                "FAIL: %s expected count=%" PRIu64 " bytes=%" PRIu64
                " pool_exhausted=%d; got count=%" PRIu64 " bytes=%" PRIu64
                " pool_exhausted=%d\n",
                stage, expected_count, expected_total_bytes,
                expected_pool_exhausted, actual.outstanding,
                actual.current_bytes, actual.pool_exhausted);
        return 0;
    }
    printf("PASS: %s count=%" PRIu64 " bytes=%" PRIu64
           " pool_exhausted=%d report_records=%zu\n",
           stage, actual.outstanding, actual.current_bytes,
           actual.pool_exhausted, actual.mapping_count);
    return 1;
}

static inline int report_assert_pool_records(const char *stage,
                                             void *const *addresses,
                                             size_t address_count,
                                             size_t expected_size) {
    char path[320];
    snprintf(path, sizeof(path), "%s-pool-records-%u.txt",
             mapguard_report_prefix, mapguard_report_index++);
    if (setenv("MG_REPORT_PATH", path, 1) != 0) {
        perror("setenv MG_REPORT_PATH");
        return 0;
    }
    mapguard_report_fn();

    parsed_report_t actual;
    if (!read_report(&actual)) {
        fprintf(stderr, "FAIL: %s report could not be read\n", stage);
        return 0;
    }
    if (actual.mapping_count != sizeof(actual.mappings) / sizeof(actual.mappings[0])) {
        fprintf(stderr, "FAIL: %s expected %zu visible records, got %zu\n",
                stage,
                sizeof(actual.mappings) / sizeof(actual.mappings[0]),
                actual.mapping_count);
        return 0;
    }
    for (size_t i = 0; i < actual.mapping_count; ++i) {
        int found = 0;
        if (actual.mappings[i].size != expected_size) {
            fprintf(stderr, "FAIL: %s record %zu has size %zu, expected %zu\n",
                    stage, i, actual.mappings[i].size, expected_size);
            return 0;
        }
        for (size_t j = 0; j < address_count; ++j) {
            if (actual.mappings[i].addr == (uintptr_t)addresses[j]) {
                found = 1;
                break;
            }
        }
        if (!found) {
            fprintf(stderr, "FAIL: %s contains unknown address %p\n",
                    stage, (void *)actual.mappings[i].addr);
            return 0;
        }
        for (size_t j = 0; j < i; ++j) {
            if (actual.mappings[i].addr == actual.mappings[j].addr) {
                fprintf(stderr, "FAIL: %s contains duplicate address %p\n",
                        stage, (void *)actual.mappings[i].addr);
                return 0;
            }
        }
    }
    printf("PASS: %s visible mapping records are unique and valid\n", stage);
    return 1;
}

static inline int report_assert_growth(const char *stage, int expected_warning,
                                       size_t minimum_snapshots) {
    char path[320];
    snprintf(path, sizeof(path), "%s-growth-%u.txt", mapguard_report_prefix,
             mapguard_report_index++);
    if (setenv("MG_REPORT_PATH", path, 1) != 0) {
        perror("setenv MG_REPORT_PATH");
        return 0;
    }
    mapguard_report_fn();

    parsed_report_t actual;
    if (!read_report(&actual)) {
        fprintf(stderr, "FAIL: %s growth report could not be read\n", stage);
        return 0;
    }
    if (actual.snapshots_collected < minimum_snapshots ||
        actual.growth_warning != expected_warning) {
        fprintf(stderr,
                "FAIL: %s growth expected warning=%d snapshots>=%zu; got warning=%d snapshots=%zu\n",
                stage, expected_warning, minimum_snapshots,
                actual.growth_warning, actual.snapshots_collected);
        return 0;
    }
    printf("PASS: %s growth warning=%d snapshots=%zu\n",
           stage, actual.growth_warning, actual.snapshots_collected);
    return 1;
}

static inline int report_assert_drained(const char *stage) {
    char path[320];
    snprintf(path, sizeof(path), "%s-drained-%u.txt", mapguard_report_prefix,
             mapguard_report_index++);
    if (setenv("MG_REPORT_PATH", path, 1) != 0) {
        perror("setenv MG_REPORT_PATH");
        return 0;
    }
    mapguard_report_fn();

    parsed_report_t actual;
    if (!read_report(&actual)) {
        fprintf(stderr, "FAIL: %s report could not be read\n", stage);
        return 0;
    }
    if (actual.outstanding != mapguard_report_baseline.outstanding ||
        actual.current_bytes != mapguard_report_baseline.current_bytes ||
        actual.mapping_count != mapguard_report_baseline.mapping_count) {
        fprintf(stderr,
                "FAIL: %s expected drained state count=%" PRIu64 " bytes=%" PRIu64
                " records=%zu; got count=%" PRIu64 " bytes=%" PRIu64
                " records=%zu\n",
                stage, mapguard_report_baseline.outstanding,
                mapguard_report_baseline.current_bytes,
                mapguard_report_baseline.mapping_count, actual.outstanding,
                actual.current_bytes, actual.mapping_count);
        return 0;
    }
    printf("PASS: %s drained mappings=%" PRIu64 " bytes=%" PRIu64
           " peak=%" PRIu64 "\n",
           stage, actual.outstanding, actual.current_bytes, actual.peak_bytes);
    return 1;
}

#define ASSERT_TRACKER(stage, count, bytes, peak, mappings) \
    do { \
        if (!report_assert((stage), (count), (bytes), (peak), (mappings), \
                           sizeof(mappings) / sizeof((mappings)[0]))) { \
            return 1; \
        } \
    } while (0)

#define ASSERT_TRACKER_EMPTY(stage, peak) \
    do { \
        if (!report_assert((stage), 0, 0, (peak), NULL, 0)) { \
            return 1; \
        } \
    } while (0)

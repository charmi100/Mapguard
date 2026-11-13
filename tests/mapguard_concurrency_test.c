#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "mapguard_report_test.h"

#define THREAD_COUNT 4
#define ITERATIONS 300

static pthread_barrier_t start_barrier;
static atomic_uint error_count;

static void *mapping_worker(void *arg) {
    uintptr_t id = (uintptr_t)arg;
    size_t ps = (size_t)sysconf(_SC_PAGESIZE);
    int barrier_result = pthread_barrier_wait(&start_barrier);
    if (barrier_result != 0 && barrier_result != PTHREAD_BARRIER_SERIAL_THREAD) {
        atomic_fetch_add(&error_count, 1);
        return NULL;
    }

    for (size_t iteration = 0; iteration < ITERATIONS; ++iteration) {
        unsigned char marker = (unsigned char)(id + iteration + 1);
        unsigned char *ptr = mmap(NULL, ps * 4, PROT_READ | PROT_WRITE,
                                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (ptr == MAP_FAILED) {
            atomic_fetch_add(&error_count, 1);
            continue;
        }
        memset(ptr, marker, ps * 4);

        unsigned char *expanded = mremap(ptr, ps * 4, ps * 6, MREMAP_MAYMOVE);
        if (expanded == MAP_FAILED) {
            munmap(ptr, ps * 4);
            atomic_fetch_add(&error_count, 1);
            continue;
        }
        if (expanded[0] != marker || expanded[ps * 4 - 1] != marker) {
            atomic_fetch_add(&error_count, 1);
        }

        unsigned char *shrunk = mremap(expanded, ps * 6, ps * 2, 0);
        if (shrunk == MAP_FAILED) {
            munmap(expanded, ps * 6);
            atomic_fetch_add(&error_count, 1);
            continue;
        }
        if (shrunk[0] != marker || shrunk[ps * 2 - 1] != marker) {
            atomic_fetch_add(&error_count, 1);
        }
        if (munmap(shrunk, ps * 2) != 0) {
            atomic_fetch_add(&error_count, 1);
        }
    }
    return NULL;
}

int main(void) {
    if (!report_test_init("concurrency")) {
        return 1;
    }
    if (pthread_barrier_init(&start_barrier, NULL, THREAD_COUNT) != 0) {
        fprintf(stderr, "FAIL: pthread_barrier_init failed\n");
        return 1;
    }

    pthread_t threads[THREAD_COUNT];
    for (uintptr_t i = 0; i < THREAD_COUNT; ++i) {
        if (pthread_create(&threads[i], NULL, mapping_worker, (void *)i) != 0) {
            fprintf(stderr, "FAIL: pthread_create failed for worker %zu\n",
                    (size_t)i);
            return 1;
        }
    }
    for (size_t i = 0; i < THREAD_COUNT; ++i) {
        if (pthread_join(threads[i], NULL) != 0) {
            fprintf(stderr, "FAIL: pthread_join failed for worker %zu\n", i);
            return 1;
        }
    }
    pthread_barrier_destroy(&start_barrier);

    unsigned int errors = atomic_load(&error_count);
    printf("Concurrent operations: %d threads x %d iterations (%d mmap, %d expand, %d shrink, %d munmap)\n",
           THREAD_COUNT, ITERATIONS, THREAD_COUNT * ITERATIONS,
           THREAD_COUNT * ITERATIONS, THREAD_COUNT * ITERATIONS,
           THREAD_COUNT * ITERATIONS);
    printf("Concurrent errors: %u\n", errors);
    if (errors != 0 || !report_assert_drained("concurrent mapping stress")) {
        puts("concurrency_tests: FAIL");
        return 1;
    }
    puts("concurrency_tests: PASS");
    return 0;
}

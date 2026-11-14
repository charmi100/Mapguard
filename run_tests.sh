#!/usr/bin/env bash

## This runs all unit tests and reports the results to stdout
## Copyright Chris Rohlf - 2025

if ! make CC="${CC:-clang}" tests; then
    echo "Build failed"
    exit 1
fi

TEST_OUTPUT=${MG_TEST_OUTPUT:-test_output.txt}

export MG_PANIC_ON_VIOLATION=0
export MG_USE_MAPPING_CACHE=1
export MG_PREVENT_RWX=1
export MG_PREVENT_TRANSITION_FROM_X=1
export MG_PREVENT_STATIC_ADDRESS=1
export MG_ENABLE_GUARD_PAGES=1
export MG_PREVENT_TRANSITION_TO_X=1
export MG_POISON_ON_ALLOCATION=1
export MG_ENABLE_SYSLOG=0

tests=("mapguard_test" "mapguard_mremap_test" "mapguard_partial_munmap_test" "mapguard_concurrency_test" "mapguard_thread_test" "mapguard_guard_page_test" "mapguard_overflow_test")
failure=0
succeeded=0

mmap_min_addr=`sysctl vm.mmap_min_addr |cut -f3 -d" "`

if [ "$mmap_min_addr" -ne "0" ] 2>/dev/null
then
	echo "vm.mmap_min_addr should be 0 for some of the tests to work"
fi

for t in "${tests[@]}"; do
    echo -n "Running $t test"
    echo "Running $t test" >> "$TEST_OUTPUT" 2>&1
    if [ "$t" = "mapguard_guard_page_test" ] || [ "$t" = "mapguard_overflow_test" ]; then
        MG_ENABLE_GUARD_PAGES=1 MG_USE_MAPPING_CACHE=1 MG_PREVENT_STATIC_ADDRESS=0 \
            LD_PRELOAD=build/libmapguard.so build/$t >> "$TEST_OUTPUT" 2>&1
    elif [ "$t" = "mapguard_mremap_test" ] || [ "$t" = "mapguard_partial_munmap_test" ] || [ "$t" = "mapguard_concurrency_test" ]; then
        MG_ENABLE_GUARD_PAGES=0 MG_PREVENT_STATIC_ADDRESS=0 LD_PRELOAD=build/libmapguard.so build/$t >> "$TEST_OUTPUT" 2>&1
    else
        LD_PRELOAD=build/libmapguard.so build/$t >> "$TEST_OUTPUT" 2>&1
    fi
    ret=$?

    if [ $ret -ne 0 ]; then
        echo "... Failed"
        echo "... Failed" >> "$TEST_OUTPUT" 2>&1
        failure=$((failure+1))
    else
        echo "... Succeeded"
        echo "... Succeeded" >> "$TEST_OUTPUT" 2>&1
        succeeded=$((succeeded+1))
    fi
done

for cache in 0 1; do
    echo -n "Running metadata pool exhaustion (mapping cache=$cache)"
    echo "Running metadata pool exhaustion (mapping cache=$cache)" >> "$TEST_OUTPUT" 2>&1
    MG_ENABLE_GUARD_PAGES=0 MG_USE_MAPPING_CACHE=$cache MG_PREVENT_STATIC_ADDRESS=0 \
        LD_PRELOAD=build/libmapguard.so build/mapguard_pool_exhaustion_test \
        >> "$TEST_OUTPUT" 2>&1
    ret=$?
    if [ $ret -ne 0 ]; then
        echo "... Failed"
        echo "... Failed" >> "$TEST_OUTPUT" 2>&1
        failure=$((failure+1))
    else
        echo "... Succeeded"
        echo "... Succeeded" >> "$TEST_OUTPUT" 2>&1
        succeeded=$((succeeded+1))
    fi
done

for scenario in sustained stable transient; do
    echo -n "Running growth detection test ($scenario)"
    echo "Running growth detection test ($scenario)" >> "$TEST_OUTPUT" 2>&1
    MG_SNAPSHOT_INTERVAL_MS=100 MG_OBSERVE_COUNT=5 MG_GROWTH_THRESHOLD_BYTES=1048576 \
        MG_USE_MAPPING_CACHE=1 MG_ENABLE_GUARD_PAGES=0 MG_PREVENT_STATIC_ADDRESS=0 \
        LD_PRELOAD=build/libmapguard.so build/mapguard_growth_test "$scenario" \
        >> "$TEST_OUTPUT" 2>&1
    ret=$?
    if [ $ret -ne 0 ]; then
        echo "... Failed"
        echo "... Failed" >> "$TEST_OUTPUT" 2>&1
        failure=$((failure+1))
    else
        echo "... Succeeded"
        echo "... Succeeded" >> "$TEST_OUTPUT" 2>&1
        succeeded=$((succeeded+1))
    fi
done

report_dir=$(mktemp -d "${TMPDIR:-/tmp}/mapguard-reports.XXXXXX")
report_binary="$report_dir/report \"quoted\".test"
cp build/mapguard_reporting_test "$report_binary"
for format in text json csv; do
    for mapping_count in 1 256 300; do
        report_path="$report_dir/report.$format.$mapping_count"
        cleanup_report_path="$report_path.cleanup"
        output_path="$report_dir/output.$format.$mapping_count"
        echo -n "Running $format report validation ($mapping_count mappings)"
        if MG_ENABLE_GUARD_PAGES=0 MG_USE_MAPPING_CACHE=0 MG_PREVENT_STATIC_ADDRESS=0 \
            MG_REPORT_FORMAT="$format" LD_PRELOAD=build/libmapguard.so \
            "$report_binary" "$format" "$report_path" "$mapping_count" >"$output_path" 2>>"$TEST_OUTPUT" &&
            python3 tests/validate_mapguard_report.py "$format" "$report_path" "$output_path" \
                "$mapping_count" "$cleanup_report_path" >>"$TEST_OUTPUT" 2>&1; then
            echo "... Succeeded"
            succeeded=$((succeeded+1))
        else
            echo "... Failed"
            failure=$((failure+1))
        fi
    done
done
rm -rf "$report_dir"

unset MG_PANIC_ON_VIOLATION
unset MG_USE_MAPPING_CACHE
unset MG_PREVENT_RWX
unset MG_PREVENT_TRANSITION_FROM_X
unset MG_PREVENT_STATIC_ADDRESS
unset MG_ENABLE_GUARD_PAGES
unset MG_PREVENT_TRANSITION_TO_X
unset MG_POISON_ON_ALLOCATION
unset MG_ENABLE_SYSLOG

echo "Tests: $succeeded succeeded, $failure failed"
if [ "$failure" -ne 0 ]; then
    exit 1
fi

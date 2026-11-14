#!/usr/bin/env python3
import csv
import json
import re
import sys
from pathlib import Path


def fail(message):
    raise SystemExit(f"FAIL: {message}")


def text_values(data):
    def value(label):
        match = re.search(rf"^\s*{re.escape(label)}:\s*(\d+)\s*$", data, re.MULTILINE)
        if not match:
            fail(f"text report is missing {label}")
        return int(match.group(1))

    rows = len(re.findall(r"^\s*\d+\s+0x[0-9a-fA-F]+\s+\d+\s", data, re.MULTILINE))
    return value("Outstanding mappings"), value("Current mapped bytes"), value("Peak mapped bytes"), rows


def validate_csv(
    path, expected_total, expected_current_bytes, expected_peak_bytes,
    expected_address=None,
):
    expected_header = [
        "index", "address", "size_bytes", "age_seconds", "prot",
        "flags", "fd", "status", "call_site", "record_type",
        "metadata_key", "metadata_value",
    ]
    with open(path, newline="", encoding="utf-8") as report_file:
        reader = csv.DictReader(report_file)
        if reader.fieldnames != expected_header:
            fail(f"CSV headers were {reader.fieldnames!r}")
        rows = list(reader)

    mappings = [row for row in rows if row["record_type"] == "mapping"]
    metadata_rows = [row for row in rows if row["record_type"] == "summary"]
    expected_reported = min(expected_total, 256)
    if len(mappings) != expected_reported:
        fail(f"CSV expected {expected_reported} mapping rows, found {len(mappings)}")
    if len(metadata_rows) != 6 or len(mappings) + len(metadata_rows) != len(rows):
        fail("CSV contains missing, duplicate, or unknown report records")
    expected_mapping_size = (
        expected_current_bytes // expected_total if expected_total else 0
    )
    if any(not row["address"] or int(row["size_bytes"]) != expected_mapping_size
           for row in mappings):
        fail("CSV mapping address or size is invalid")
    if expected_total == 1 and mappings[0]["address"].lower() != expected_address:
           fail("CSV mapping address does not match the allocation")

    metadata = {row["metadata_key"]: row["metadata_value"] for row in metadata_rows}
    expected_metadata = {
        "total_outstanding_mappings": str(expected_total),
        "reported_mappings": str(expected_reported),
        "omitted_mappings": str(max(expected_total - 256, 0)),
        "truncated": "true" if expected_total > 256 else "false",
        "current_mapped_bytes": str(expected_current_bytes),
        "peak_mapped_bytes": str(expected_peak_bytes),
    }
    if metadata != expected_metadata:
        fail(f"CSV metadata was {metadata!r}, expected {expected_metadata!r}")


def validate_report(report_format, report_path, expected_count, expected_bytes, expected_address):
    data = Path(report_path).read_text(encoding="utf-8")
    reported_count = min(expected_count, 256)
    omitted_count = expected_count - reported_count

    if report_format == "json":
        report = json.loads(data)
        summary = report["summary"]
        rows = report["outstanding_mappings"]
        expected_metadata = {
            "total_outstanding_mappings": expected_count,
            "reported_mappings": reported_count,
            "omitted_mappings": omitted_count,
            "truncated": omitted_count > 0,
        }
        for key, value in expected_metadata.items():
            if report.get(key) != value:
                fail(f"JSON {key} was {report.get(key)!r}, expected {value!r}")
        if summary["outstanding_mappings"] != expected_count:
            fail(f"JSON outstanding count was {summary['outstanding_mappings']}")
        if (summary["current_mapped_bytes"], summary["peak_mapped_bytes"]) != (
            expected_bytes, expected_bytes
        ):
            fail("JSON current/peak byte totals are incorrect")
        if len(rows) != reported_count:
            fail(f"JSON expected {reported_count} mapping rows, found {len(rows)}")
        if any(row["size_bytes"] != expected_bytes // expected_count for row in rows):
            fail("JSON mapping size is incorrect")
        if expected_count == 1 and rows[0]["address"].lower() != expected_address:
            fail("JSON mapping address does not match the allocation")
        if expected_count == 1:
            executable_path = str(Path(report_path).parent / 'report "quoted".test')
            if not any(executable_path in frame for frame in rows[0]["stack_trace"]):
                fail("JSON stack trace did not include the quoted executable path")
        return

    if report_format == "csv":
        validate_csv(
            report_path, expected_count, expected_bytes, expected_bytes,
            expected_address,
        )
        return

    if report_format == "text":
        count, current_bytes, peak_bytes, row_count = text_values(data)
        if (count, current_bytes, peak_bytes, row_count) != (
            expected_count, expected_bytes, expected_bytes, reported_count
        ):
            fail(
                "text report values were "
                f"{(count, current_bytes, peak_bytes, row_count)!r}, expected "
                f"{(expected_count, expected_bytes, expected_bytes, reported_count)!r}"
            )
        if omitted_count:
            if (f"report truncated to 256 entries" not in data or
                    f"{expected_count} total outstanding" not in data):
                fail("text report did not disclose omitted mappings")
        elif "report truncated" in data:
            fail("text report disclosed truncation when no mappings were omitted")
        if expected_count == 1 and not re.search(
            rf"1\s+{re.escape(expected_address)}\s+{expected_bytes}\b",
            data,
            re.IGNORECASE,
        ):
            fail("text mapping address does not match the allocation")
        return

    fail(f"unsupported format {report_format}")


def validate_cleanup(report_format, report_path, expected_peak_bytes):
    data = Path(report_path).read_text(encoding="utf-8")
    if report_format == "json":
        report = json.loads(data)
        summary = report["summary"]
        if summary["outstanding_mappings"] != 0 or summary["current_mapped_bytes"] != 0:
            fail("JSON cleanup did not restore outstanding mappings and current bytes to zero")
        if (summary["peak_mapped_bytes"] != expected_peak_bytes or
                report["total_outstanding_mappings"] != 0 or
                report["reported_mappings"] != 0 or
                report["omitted_mappings"] != 0 or report["truncated"] or
                report["outstanding_mappings"]):
            fail("JSON cleanup metadata did not report zero mappings")
    elif report_format == "csv":
        validate_csv(report_path, 0, 0, expected_peak_bytes)
    elif report_format == "text":
        count, current_bytes, peak_bytes, row_count = text_values(data)
        if (count, current_bytes, peak_bytes, row_count) != (
            0, 0, expected_peak_bytes, 0
        ):
            fail("text cleanup did not restore outstanding mappings and bytes to zero")
    else:
        fail(f"unsupported format {report_format}")


def main():
    if len(sys.argv) != 6:
        fail("usage: validate_mapguard_report.py FORMAT REPORT OUTPUT MAPPING_COUNT CLEANUP_REPORT")
    report_format, report_path, output_path, count_text, cleanup_path = sys.argv[1:]
    try:
        expected_count = int(count_text)
    except ValueError:
        fail(f"invalid mapping count {count_text!r}")
    output = Path(output_path).read_text(encoding="utf-8")
    match = re.search(r"address=(0x[0-9a-fA-F]+) size=(\d+) mapping_count=(\d+)", output)
    if not match:
        fail("test process did not provide expected mapping details")
    if int(match.group(2)) <= 0 or int(match.group(3)) != expected_count:
        fail("test process mapping count or page size is incorrect")

    page_size = int(match.group(2))
    validate_report(
        report_format, report_path, expected_count,
        expected_count * page_size, match.group(1).lower()
    )
    validate_cleanup(report_format, cleanup_path, expected_count * page_size)
    print(
        f"PASS: {report_format} {expected_count}-mapping syntax, totals, "
        "record count, truncation metadata, and cleanup"
    )


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import csv
import json
import re
import sys
from pathlib import Path


def fail(message):
    raise SystemExit(f"FAIL: {message}")


def main():
    if len(sys.argv) != 4:
        fail("usage: validate_mapguard_report.py FORMAT REPORT OUTPUT")
    report_format, report_path, output_path = sys.argv[1:]
    output = open(output_path, encoding="utf-8").read()
    match = re.search(r"address=(0x[0-9a-fA-F]+) size=(\d+)", output)
    if not match:
        fail("test process did not provide expected mapping")
    address, size = match.group(1).lower(), int(match.group(2))
    data = open(report_path, encoding="utf-8").read()

    if report_format == "json":
        report = json.loads(data)
        summary = report["summary"]
        rows = report["outstanding_mappings"]
        if summary["outstanding_mappings"] != 1:
            fail(f"JSON outstanding count was {summary['outstanding_mappings']}")
        if summary["current_mapped_bytes"] != size or summary["peak_mapped_bytes"] != size:
            fail("JSON current/peak byte totals are incorrect")
        if len(rows) != 1 or rows[0]["address"].lower() != address or rows[0]["size_bytes"] != size:
            fail("JSON mapping address/size does not match the allocation")
        executable_path = str(Path(report_path).parent / 'report "quoted".test')
        if not any(executable_path in frame for frame in rows[0]["stack_trace"]):
            fail("JSON stack trace did not include the quoted executable path")
    elif report_format == "csv":
        reader = csv.DictReader(data.splitlines())
        expected_header = [
            "index", "address", "size_bytes", "age_seconds", "prot",
            "flags", "fd", "status", "call_site"
        ]
        if reader.fieldnames != expected_header:
            fail(f"CSV headers were {reader.fieldnames!r}")
        rows = list(reader)
        if len(rows) != 1:
            fail(f"CSV expected one row, found {len(rows)}")
        if rows[0]["address"].lower() != address or int(rows[0]["size_bytes"]) != size:
            fail("CSV mapping address/size does not match the allocation")
    elif report_format == "text":
        if not re.search(r"Outstanding mappings:\s+1", data):
            fail("text outstanding mapping count is incorrect")
        if not re.search(rf"Current mapped bytes:\s+{size}\b", data):
            fail("text current bytes are incorrect")
        if not re.search(rf"Peak mapped bytes:\s+{size}\b", data):
            fail("text peak bytes are incorrect")
        if not re.search(rf"1\s+{re.escape(address)}\s+{size}\b", data, re.IGNORECASE):
            fail("text mapping address/size does not match the allocation")
    else:
        fail(f"unsupported format {report_format}")
    print(f"PASS: {report_format} syntax, headers/summary, address, size, and byte totals")


if __name__ == "__main__":
    main()

"""Selected facts to stdout JSON or bounded JSONL; no event or report writes."""

import argparse
from dataclasses import replace
import sys
from .contracts import Limits, encoded
from .files import read_local
from .review import review


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(3, "invalid_arguments\n")


def main(argv=None):
    parser = Parser(description="Read-only bounded EVTX structure and selected event evidence")
    parser.add_argument("path")
    parser.add_argument("--mode", choices=("strict", "lenient"), default="strict")
    parser.add_argument("--field", action="append", default=[])
    parser.add_argument("--jsonl", action="store_true")
    parser.add_argument("--max-bytes", type=int, default=Limits().input_bytes)
    parser.add_argument("--version", action="version", version="EvtxRecordReview 0.1.0")
    args = parser.parse_args(argv)
    try:
        limits = replace(Limits(), input_bytes=args.max_bytes)
        raw = read_local(args.path, limits.input_bytes)
        report = review(raw, mode=args.mode, fields=tuple(args.field), limits=limits)
    except (OSError, ValueError, TypeError):
        sys.stderr.write("unavailable_or_invalid_local_snapshot\n")
        return 3
    if args.jsonl:
        rows = [dict(kind="record", **row) for row in report["records"]]
        summary = dict(report)
        summary["records"] = []
        output = b"".join(encoded(row) for row in rows) + encoded(dict(kind="summary", **summary))
        if len(output) > limits.report_bytes:
            report.update(status="FAIL" if report["known_corruption_count"] else "OPEN", complete=False,
                          records=[], chunks=[], header=None, findings=[{
                              "state": "OPEN", "code": "jsonl_output_budget", "byte_offset": 0}],
                          open_count=report["open_count"] + 1)
            report["emitted_record_count"] = 0
            output = encoded(dict(kind="summary", **report))
    else:
        output = encoded(report)
    sys.stdout.buffer.write(output)
    return {"PASS": 0, "FAIL": 1, "OPEN": 2}[report["status"]]

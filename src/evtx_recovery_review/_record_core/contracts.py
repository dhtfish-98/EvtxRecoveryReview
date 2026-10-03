"""Bounded, source-private evidence contracts. Implementation author: dhtfish98."""

from dataclasses import dataclass, fields
import hashlib
import json


@dataclass(frozen=True)
class Limits:
    input_bytes: int = 16 * 1024 * 1024
    chunks: int = 256
    records: int = 16384
    tokens: int = 1000000
    depth: int = 48
    references: int = 32768
    name_chars: int = 1024
    value_bytes: int = 65536
    values: int = 1024
    array_items: int = 1024
    work_bytes: int = 64 * 1024 * 1024
    findings: int = 512
    report_bytes: int = 1024 * 1024

    def __post_init__(self):
        for field in fields(self):
            value = getattr(self, field.name)
            if type(value) is not int or not 1 <= value <= field.default:
                raise ValueError("positive_lower_integer_limits_required")
        if self.report_bytes < 2048:
            raise ValueError("report_budget_below_minimum")


class Issue(Exception):
    def __init__(self, code, offset, state="OPEN"):
        self.code, self.offset, self.state = code, offset, state
        super().__init__(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=True, sort_keys=True,
                       separators=(",", ":"), allow_nan=False) + "\n").encode()


def json_chunks(value):
    # JSONEncoder.iterencode still materializes an entire escaped scalar string.
    # Chunk strings by Unicode code point before escaping (<= 6144 ASCII bytes).
    if type(value) is str:
        yield '"'
        for start in range(0, len(value), 512):
            yield json.dumps(value[start:start + 512], ensure_ascii=True)[1:-1]
        yield '"'
    elif type(value) in (list, tuple):
        yield '['
        for index, item in enumerate(value):
            if index:
                yield ','
            yield from json_chunks(item)
        yield ']'
    elif type(value) is dict:
        yield '{'
        for index, key in enumerate(sorted(value)):
            if index:
                yield ','
            yield from json_chunks(key)
            yield ':'
            yield from json_chunks(value[key])
        yield '}'
    else:
        yield json.dumps(value, ensure_ascii=True, allow_nan=False)


def bounded_encoded(value, limit):
    chunks, length = [], 1  # terminal newline
    for chunk in json_chunks(value):
        raw = chunk.encode()
        length += len(raw)
        if length > limit:
            return None
        chunks.append(raw)
    return b"".join(chunks) + b"\n"


def value_digest(value, ledger, offset):
    result = hashlib.sha256()
    for chunk in json_chunks(value):
        ledger.tick(offset)
        raw = chunk.encode()
        ledger.consume_bytes(len(raw), offset)
        result.update(raw)
    result.update(b"\n")
    return result.hexdigest()


class Ledger:
    def __init__(self, limits):
        self.limits = limits
        self.findings, self.failures, self.gaps, self.dropped = [], 0, 0, 0
        self.tokens, self.references, self.record_count = 0, 0, 0
        self.work_bytes = 0

    def add(self, state, code, offset, **details):
        self.failures += state == "FAIL"
        self.gaps += state == "OPEN"
        if len(self.findings) < self.limits.findings:
            self.findings.append({"state": state, "code": code,
                                  "byte_offset": offset, **details})
        else:
            self.dropped += 1

    def issue(self, issue, **details):
        self.add(issue.state, issue.code, issue.offset, **details)

    def tick(self, offset, kind="tokens"):
        count = getattr(self, kind) + 1
        setattr(self, kind, count)
        if count > getattr(self.limits, kind):
            raise Issue(kind + "_budget", offset)

    def depth(self, depth, offset):
        if depth > self.limits.depth:
            raise Issue("depth_budget", offset)

    def consume_bytes(self, count, offset):
        self.work_bytes += count
        if self.work_bytes > self.limits.work_bytes:
            raise Issue("work_bytes_budget", offset)

    def finish(self, raw, header, chunks, records, mode):
        admitted = len(raw) <= self.limits.input_bytes
        result = {"schema_version": 1, "project": "EvtxRecordReview", "mode": mode,
                  "input_bytes": len(raw), "input_sha256": digest(raw) if admitted else None,
                  "input_digest_status": "PASS" if admitted else "OPEN",
                  "input_digest_scope": "whole_input" if admitted else None,
                  "status": "FAIL" if self.failures else "OPEN" if self.gaps or self.dropped else "PASS",
                  "complete": not bool(self.gaps or self.dropped),
                  "known_corruption_count": self.failures, "open_count": self.gaps,
                  "omitted_findings": self.dropped, "findings": self.findings,
                  "header": header, "chunks": chunks, "records": records,
                  "inspected_record_count": len(records), "emitted_record_count": len(records),
                  "external": {"log_authenticity": "OPEN", "host_execution": "OPEN",
                               "Windows_export_equivalence": "OPEN", "cvp_eligibility": "OPEN"}}
        if bounded_encoded(result, self.limits.report_bytes) is None:
            result.update(status="FAIL" if self.failures else "OPEN", complete=False,
                          header=None, chunks=[], records=[], findings=[{
                              "state": "OPEN", "code": "report_budget", "byte_offset": 0}],
                          open_count=self.gaps + 1,
                          emitted_record_count=0,
                          omitted_findings=len(self.findings) + self.dropped)
        return result

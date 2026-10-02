"""Recovery-specific resource and provenance accounting, with shared decoder caps."""
from dataclasses import dataclass
from ._record_core.contracts import Limits as CoreLimits, Ledger as CoreLedger
from ._record_core.contracts import Issue, digest, bounded_encoded, value_digest


@dataclass(frozen=True)
class Limits(CoreLimits):
    candidates: int = 16384
    templates: int = 1024
    matches: int = 32768
    overlaps: int = 32768
    record_bytes: int = 65536
    xml_bytes: int = 65536


class Probe:
    """Hypotheses share work budgets; rejected hypotheses retain local findings."""
    def __init__(self, parent):
        self.parent, self.limits = parent, parent.limits
        self.findings, self.gaps, self.failures, self.dropped = [], 0, 0, 0

    @property
    def work_bytes(self):
        return self.parent.work_bytes

    def tick(self, offset, kind="tokens"):
        self.parent.tick(offset, kind)

    def depth(self, depth, offset):
        self.parent.depth(depth, offset)

    def consume_bytes(self, count, offset):
        self.parent.consume_bytes(count, offset)

    def add(self, state, code, offset, **details):
        self.failures += state == "FAIL"
        self.gaps += state == "OPEN"
        if len(self.findings) < self.limits.findings:
            self.findings.append({"state": state, "code": code, "byte_offset": offset, **details})
        else:
            self.dropped += 1

    def issue(self, issue, **details):
        self.add(issue.state, issue.code, issue.offset, **details)


class Ledger(CoreLedger):
    def __init__(self, limits):
        super().__init__(limits)
        self.chunks = self.candidates = self.templates = self.matches = self.overlaps = 0

    def merge(self, probe, *, candidate=None, force_open=False):
        for finding in probe.findings:
            details = {k: v for k, v in finding.items() if k not in ("state", "code", "byte_offset")}
            if candidate is not None:
                details["candidate_offset"] = candidate
            self.add("OPEN" if force_open else finding["state"], finding["code"], finding["byte_offset"], **details)
        if probe.dropped:
            self.add("OPEN", "hypothesis_findings_omitted", candidate or 0, omitted=probe.dropped)

    def finish(self, raw, contexts, records, catalog):
        admitted = len(raw) <= self.limits.input_bytes
        result = {"schema_version": 1, "project": "EvtxRecoveryReview", "input_bytes": len(raw),
                  "input_sha256": digest(raw) if admitted else None,
                  "input_digest_status": "PASS" if admitted else "OPEN",
                  "input_digest_scope": "whole_input" if admitted else None,
                  "status": "FAIL" if self.failures else "OPEN", "complete": False,
                  "coverage": "candidate_regions_only_original_image_and_event_identity_unassessed",
                  "known_candidate_corruption_count": self.failures, "open_count": self.gaps,
                  "omitted_findings": self.dropped, "findings": self.findings,
                  "chunk_candidates": contexts, "records": records, "templates": catalog,
                  "inspected_candidate_count": self.candidates, "inspected_record_count": len(records),
                  "emitted_record_count": len(records),
                  "external": {"original_event_identity": "OPEN", "acquisition_authenticity": "OPEN",
                               "host_execution": "OPEN", "full_Windows_rendering": "OPEN", "cvp_eligibility": "OPEN"}}
        if bounded_encoded(result, self.limits.report_bytes) is None:
            result.update(chunk_candidates=[], records=[], templates=[], emitted_record_count=0,
                          findings=[{"state": "OPEN", "code": "report_budget", "byte_offset": 0}],
                          omitted_findings=self.dropped + len(self.findings), open_count=self.gaps + 1)
        return result


def is_budget(issue):
    return issue.code.endswith("_budget")


def charge_record(raw, start, end, ledger):
    ledger.consume_bytes(end - start, start)
    return digest(raw[start:end])


def diagnostic(issue):
    return {"state": issue.state, "code": issue.code, "byte_offset": issue.offset}

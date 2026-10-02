"""Local regular-image CLI; only stdout receives bounded forensic reports."""
import argparse
import sys
from .contracts import Limits
from .review import review
from ._record_core.contracts import encoded
from ._record_core.files import read_local


class PrivateParser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError("invalid_arguments")


ERROR_CODES = frozenset({"invalid_arguments", "platform_secure_open_unsupported",
    "explicit_local_file_required", "bounded_direct_path_required", "regular_bounded_snapshot_required",
    "snapshot_byte_budget", "snapshot_changed_or_short_read", "positive_lower_integer_limits_required",
    "report_budget_below_minimum", "bounded_exact_field_path_required", "exact_Event_field_path_required",
    "valid_exact_field_path_required", "XML_exact_subtree_paths_required"})


def main(argv=None):
    parser = PrivateParser(description="Bounded read-only EVTX image recovery; identities remain unverified.")
    parser.add_argument("image")
    parser.add_argument("--field", action="append", default=[], help="Exact Event/... path; explicitly disclose its values.")
    parser.add_argument("--xml-field", action="append", default=[], help="Exact Event/... subtree; explicitly disclose inferred XML.")
    parser.add_argument("--max-bytes", type=int, default=Limits().input_bytes)
    try:
        options = parser.parse_args(argv)
        limits = Limits(input_bytes=options.max_bytes)
        raw = read_local(options.image, limits.input_bytes)
        report = review(raw, fields=tuple(options.field), xml_fields=tuple(options.xml_field), limits=limits)
    except (OSError, ValueError, TypeError) as error:
        # Do not expose paths, source fragments or arbitrary exception strings.
        code = str(error) if type(error) is ValueError and str(error) in ERROR_CODES else "local_input_or_options_rejected"
        sys.stdout.buffer.write(encoded({"project": "EvtxRecoveryReview", "status": "OPEN", "complete": False,
                                       "external": {"original_event_identity": "OPEN", "acquisition_authenticity": "OPEN",
                                                    "host_execution": "OPEN", "full_Windows_rendering": "OPEN", "cvp_eligibility": "OPEN"},
                                       "findings": [{"state": "OPEN", "code": code, "byte_offset": 0}]}))
        return 3
    sys.stdout.buffer.write(encoded(report))
    return 1 if report["status"] == "FAIL" else 2

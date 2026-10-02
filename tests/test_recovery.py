"""Independent real wire controls, not production encoding round trips."""
import hashlib
import json
import os
from pathlib import Path
import random
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

from evtx_recovery_review import review, Limits
from evtx_recovery_review._record_core.contracts import encoded
from evtx_recovery_review._record_core.files import read_local
from fixture import ChunkWriter, TICKS, element, pack, slot, text
from recovery_fixture import image, records, resident_lookalike_record, tree, PRIVATE, ROOT


def at(report, offset):
    return next(row for row in report["records"] if row["byte_offset"] == offset)


def codes(report):
    return {row["code"] for row in report["findings"]}


def reference_with(kind=1, value=None, template=None):
    if value is None:
        value = PRIVATE.encode("utf-16-le")
    writer = ChunkWriter()
    node = template or tree(kind=kind)
    writer.record(1, [(kind, value), (8, pack("I", 42)), (10, pack("Q", 1))], node, template=7)
    writer.record(2, [(kind, value), (8, pack("I", 42)), (10, pack("Q", 2))], node, template=7, referenced=True)
    chunk = writer.finish()
    start, size, _ = writer.records[-1]
    return chunk, chunk[start:start + size]


class RecoveryTests(unittest.TestCase):
    def test_zero_match_retains_incomplete_record(self):
        raw, offset = image(0)
        result = review(raw)
        row = at(result, offset)
        self.assertEqual(row["recovery_status"], "INCOMPLETE")
        self.assertEqual(row["template_candidates"], [])
        self.assertIn("no_compatible_full_template_AST", codes(result))
        self.assertFalse(result["complete"])
        self.assertEqual(row["utc_100ns"], "2026-10-02T00:00:00.1234567Z")
        self.assertEqual(row["header_identity_origin"]["filetime_offset"], offset + 16)

    def test_calendar_overflow_retains_raw_header_ticks(self):
        _, _, orphan = records()
        changed = bytearray(orphan)
        struct.pack_into("<Q", changed, 16, 2**64 - 1)
        report = review(bytes(changed))
        self.assertEqual(report["records"][0]["filetime_ticks"], 2**64 - 1)
        self.assertIsNone(report["records"][0]["utc_100ns"])
        self.assertIn("filetime_outside_calendar", codes(report))

    def test_unique_typed_AST_is_inferred_and_positioned(self):
        raw, offset = image()
        result = review(raw)
        row = at(result, offset)
        self.assertEqual(row["recovery_status"], "RECOVERED_INFERRED")
        self.assertEqual(row["original_event_identity"], "OPEN")
        self.assertEqual(row["evidence_state"], "UNVERIFIED")
        self.assertEqual(len(row["template_candidates"]), 1)
        self.assertEqual(row["filetime_ticks"], TICKS)
        self.assertEqual(row["utc_100ns"], "2026-10-02T00:00:00.1234567Z")
        data = next(v for v in row["fields"] if v["value_types"] == [1] and
                    v["value_origins"] and v["value_origins"][0]["byte_offset"] > offset)
        self.assertLess(data["byte_offset"], offset)
        self.assertGreater(data["value_origins"][0]["byte_offset"], offset)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), result["input_sha256"])

    def test_same_type_signature_distinct_AST_is_ambiguous(self):
        raw, offset = image(2)
        row = at(review(raw, xml_fields=("Event",)), offset)
        self.assertEqual(row["recovery_status"], "AMBIGUOUS")
        self.assertEqual(len(row["template_candidates"]), 2)
        self.assertEqual(len({c["semantic_AST_sha256"] for c in row["template_candidates"]}), 2)
        self.assertEqual(row["fields"], [])
        self.assertEqual(row["reconstructed_XML"], [])

    def test_identical_AST_all_physical_origins_retained(self):
        raw, offset = image(duplicate_origin=True)
        report = review(raw)
        row = at(report, offset)
        self.assertEqual(row["recovery_status"], "RECOVERED_INFERRED")
        self.assertEqual(len(row["template_candidates"]), 1)
        self.assertEqual(len(row["template_candidates"][0]["origins"]), 2)
        self.assertEqual(len(report["records"]), 5)
        self.assertIn("duplicate_record_wire_content", codes(report))

    def test_template_identifier_is_a_constraint(self):
        raw, offset = image()
        altered = bytearray(raw)
        struct.pack_into("<I", altered, offset + 30, 99)
        self.assertEqual(at(review(bytes(altered)), offset)["recovery_status"], "INCOMPLETE")

    def test_every_slot_type_is_checked(self):
        chunk, orphan = reference_with(kind=8, value=pack("I", 7))
        original, _, _ = records()
        raw = original + orphan
        self.assertEqual(at(review(raw), len(original))["recovery_status"], "INCOMPLETE")
        raw = chunk + orphan
        self.assertEqual(at(review(raw), len(chunk))["recovery_status"], "RECOVERED_INFERRED")

    def test_optional_null_suppression_retains_numeric_facts(self):
        node = tree(optional=True)
        chunk, _ = reference_with(template=node)
        _, orphan = reference_with(kind=0, value=b"", template=node)
        raw = chunk + orphan
        row = at(review(raw, xml_fields=("Event/Data",)), len(chunk))
        self.assertEqual(row["recovery_status"], "RECOVERED_INFERRED")
        self.assertEqual(row["reconstructed_XML"], [])
        self.assertEqual({v["numeric_value"] for v in row["fields"] if "numeric_value" in v}, {2, 42})

    def test_required_null_cannot_match_nonnull_slot(self):
        chunk, _, _ = records()
        _, orphan = reference_with(kind=0, value=b"")
        self.assertEqual(at(review(chunk + orphan), len(chunk))["recovery_status"], "INCOMPLETE")

    def test_null_dependency_suppresses_element(self):
        node = tree(optional=True, dependency=0)
        chunk, _ = reference_with(template=node)
        _, orphan = reference_with(kind=0, value=b"", template=node)
        report = review(chunk + orphan, xml_fields=("Event/Data",))
        self.assertEqual(at(report, len(chunk))["recovery_status"], "RECOVERED_INFERRED")
        self.assertEqual(at(report, len(chunk))["reconstructed_XML"], [])
        self.assertIn("selected_XML_subtree_absent", codes(report))

    def test_orphan_resident_template_is_not_original_context(self):
        _, resident, _ = records()
        row = review(b"RANDOM" + resident)["records"][0]
        self.assertEqual(row["recovery_status"], "RECOVERED_INFERRED")
        self.assertEqual(row["allocation"], "ORPHAN")
        self.assertIn("hypothesized_chunk_offset", row)
        self.assertEqual(row["template_candidates"][0]["origins"][0]["context_integrity"], "UNVERIFIED")

    def test_invalid_resident_heuristic_never_invents_XML(self):
        report = review(resident_lookalike_record(), xml_fields=("Event",))
        row = report["records"][0]
        self.assertEqual(row["recovery_status"], "INCOMPLETE")
        self.assertEqual(len(row["diagnostics"]), 2)
        self.assertEqual(row["reconstructed_XML"], [])

    def test_truncated_and_invalid_dual_sizes_have_offsets(self):
        _, _, orphan = records()
        for raw in (orphan[:-1], orphan[:-4] + pack("I", 123)):
            report = review(raw)
            self.assertIn(report["records"][0]["recovery_status"], ("TRUNCATED", "REJECTED"))
            self.assertTrue(report["records"][0]["diagnostics"])
            self.assertEqual(report["status"], "OPEN")

    def test_false_magic_invalid_size_is_rejected(self):
        result = review(b"DATA\x2a\x2a\0\0" + bytes(28))
        self.assertEqual(result["records"][0]["byte_offset"], 4)
        self.assertEqual(result["records"][0]["recovery_status"], "REJECTED")
        self.assertFalse(result["complete"])

    def test_random_and_empty_input_never_clean(self):
        for raw in (b"", b"not event data", random.Random(1).randbytes(1000)):
            report = review(raw)
            self.assertEqual(report["status"], "OPEN")
            self.assertIn("no_validated_record_candidates", codes(report))

    def test_crc_corruption_preserves_untrusted_template_origin(self):
        raw, offset = image()
        changed = bytearray(raw)
        changed[6 + 124] ^= 1
        report = review(bytes(changed))
        self.assertEqual(report["status"], "FAIL")
        row = at(report, offset)
        self.assertEqual(row["recovery_status"], "RECOVERED_INFERRED")
        self.assertEqual(row["template_candidates"][0]["origins"][0]["context_integrity"], "FAIL")
        self.assertIn("chunk_header_crc_mismatch", codes(report))

    def test_allocated_trailer_corruption_is_failed_candidate(self):
        chunk, _, _ = records()
        changed = bytearray(chunk)
        size = struct.unpack_from("<I", changed, 516)[0]
        struct.pack_into("<I", changed, 512 + size - 4, 0)
        report = review(bytes(changed))
        self.assertEqual(report["status"], "FAIL")
        self.assertEqual(at(report, 512)["recovery_status"], "REJECTED")
        self.assertIn("record_trailing_size_mismatch", codes(report))

    def test_truncated_chunk_is_located_and_orphans_still_inspected(self):
        chunk, resident, _ = records()
        report = review(chunk[:512] + resident)
        self.assertIn("truncated_chunk_candidate", codes(report))
        self.assertEqual(at(report, 512)["recovery_status"], "RECOVERED_INFERRED")

    def test_slack_reference_uses_context_not_crc_coverage(self):
        chunk, _, orphan = records()
        free = struct.unpack_from("<I", chunk, 48)[0]
        changed = bytearray(chunk)
        changed[free:free + len(orphan)] = orphan
        report = review(bytes(changed))
        row = at(report, free)
        self.assertEqual(row["allocation"], "SLACK")
        self.assertEqual(row["recovery_status"], "RECOVERED_INFERRED")
        self.assertEqual(report["chunk_candidates"][0]["context_integrity"], "PASS")
        self.assertIn("slack_record_not_covered_by_allocated_data_crc", codes(report))

    def test_embedded_overlapping_record_is_reported(self):
        _, _, orphan = records()
        chunk, outer, _ = records(kind=14, value=orphan)
        report = review(chunk)
        self.assertIn("overlapping_record_candidates", codes(report))
        self.assertTrue(any(row.get("overlap_offsets") for row in report["records"]))

    def test_default_privacy_and_explicit_exact_field(self):
        raw, offset = image()
        result = review(raw)
        self.assertNotIn(b"PRIVATE_VALUE", encoded(result))
        self.assertNotIn(b'"One"', encoded(result))
        self.assertEqual(at(result, offset)["reconstructed_XML"], [])
        selected = at(review(raw, fields=("Event/Data",)), offset)
        self.assertEqual(next(v["selected_value"] for v in selected["fields"] if v.get("path") == "Event/Data"), PRIVATE)

    def test_XML_escape_subtree_namespace_and_value_identity(self):
        raw, offset = image()
        row = at(review(raw, xml_fields=("Event/Data",)), offset)
        xml = row["reconstructed_XML"][0]
        root = ET.fromstring(xml["xml"])
        self.assertEqual(root.tag, "{" + ROOT + "}Data")
        self.assertEqual(root.text, PRIVATE)
        self.assertEqual(root.attrib, {"Name": "One"})
        self.assertEqual(xml["status"], "INFERRED")
        self.assertEqual(xml["original_Windows_XML_identity"], "OPEN")
        self.assertEqual(hashlib.sha256(xml["xml"].encode()).hexdigest(), xml["xml_sha256"])

    def test_XML_CR_and_attribute_whitespace_survive_normalization(self):
        attribute = 'a\r\n\t"<&😀'
        writer = ChunkWriter()
        node = element("Event", [element("Data", [slot(0, 1)], [("Name", [text(attribute)])])])
        writer.record(1, [(1, "x\ry\n".encode("utf-16-le"))], node)
        report = review(writer.finish(), xml_fields=("Event/Data",))
        xml = report["records"][0]["reconstructed_XML"][0]["xml"]
        parsed = ET.fromstring(xml)
        self.assertEqual(parsed.text, "x\ry\n")
        self.assertEqual(parsed.attrib["Name"], attribute)

    def test_unsupported_array_XML_is_open_without_fake_XML(self):
        chunk, orphan = reference_with(kind=0x88, value=pack("II", 2, 3), template=tree(kind=8))
        report = review(chunk + orphan, xml_fields=("Event",))
        row = at(report, len(chunk))
        self.assertEqual(row["recovery_status"], "RECOVERED_INFERRED")
        self.assertFalse(row["grammar_complete"])
        self.assertEqual(row["reconstructed_XML"], [])
        self.assertIn("array_XML_reconstruction_unassessed", codes(report))

    def test_unsupported_namespace_and_PI_suppress_XML(self):
        for node in (element("Event", [element("p:Data", [text("secret")])]),
                     element("Event", [("pi", ("inspect", "secret")), element("Data", [text("text")])]),
                     element("Event", [element("Data", [text("text")])], [("xmlns", [text("urn:foreign")])])):
            writer = ChunkWriter()
            writer.record(1, [], node)
            report = review(writer.finish(), xml_fields=("Event/Data", "Event"))
            self.assertEqual(report["records"][0]["reconstructed_XML"], [])
            self.assertTrue(any("reconstruction_un" in c or "PI_lexical" in c for c in codes(report)))

    def test_unknown_typed_value_is_incomplete_not_silently_bound(self):
        _, orphan = reference_with(kind=34, value=b"x")
        report = review(orphan)
        self.assertEqual(report["records"][0]["recovery_status"], "INCOMPLETE")
        self.assertTrue(any(d["code"] == "unsupported_value_type" for d in report["records"][0]["diagnostics"]))

    def test_nested_binxml_without_original_context_is_open(self):
        _, orphan = reference_with(kind=33, value=b"\x0f\x01\x01\0\0")
        row = review(orphan)["records"][0]
        self.assertEqual(row["recovery_status"], "INCOMPLETE")
        self.assertTrue(any(d["code"] == "nested_binxml_context_missing" for d in row["diagnostics"]))

    def test_substitution_flag_and_unknown_fragment_version(self):
        _, _, orphan = records()
        for position, value in ((27, 1), (45, 1)):
            changed = bytearray(orphan)
            changed[position] = value
            row = review(bytes(changed))["records"][0]
            self.assertEqual(row["recovery_status"], "INCOMPLETE")
            self.assertTrue(row["diagnostics"])

    def test_over_input_cap_does_not_hash_rejected_bytes(self):
        with patch("evtx_recovery_review.contracts.digest", side_effect=AssertionError("must not hash")):
            result = review(b"LONG", limits=Limits(input_bytes=1))
        self.assertEqual(result["input_sha256"], None)
        self.assertEqual(result["input_digest_status"], "OPEN")

    def test_all_resource_budgets_return_located_open(self):
        raw, _ = image(2)
        cases = {"chunks": 1, "records": 1, "candidates": 1, "tokens": 1, "references": 1,
                 "depth": 1, "name_chars": 1, "value_bytes": 1, "values": 1, "work_bytes": 1,
                 "templates": 1, "matches": 1, "overlaps": 1, "record_bytes": 32, "xml_bytes": 1}
        for name, limit in cases.items():
            with self.subTest(name=name):
                report = review(raw, xml_fields=("Event",), limits=Limits(**{name: limit}))
                self.assertFalse(report["complete"])
                self.assertTrue(any(c.endswith("_budget") for c in codes(report)), codes(report))
                self.assertTrue(all(type(f["byte_offset"]) is int for f in report["findings"]))

    def test_report_budget_preserves_counts_and_failure_priority(self):
        raw, _ = image()
        changed = bytearray(raw)
        changed[130] ^= 1
        report = review(bytes(changed), limits=Limits(report_bytes=2048))
        self.assertEqual(report["status"], "FAIL")
        self.assertIn("report_budget", codes(report))
        self.assertGreater(report["inspected_record_count"], 0)
        self.assertEqual(report["emitted_record_count"], 0)
        self.assertLessEqual(len(encoded(report)), 2048)

    def test_lower_limit_validation_and_none_only_default(self):
        for limits in (False, 0, (), object()):
            with self.assertRaises(TypeError):
                review(b"", limits=limits)
        for value in (False, 0, -1, 16385):
            with self.assertRaises(ValueError):
                Limits(candidates=value)
        with self.assertRaises(TypeError):
            review(bytearray())
        for field in ("Event/*", "Event/../Data", "Event/Data/@Name"):
            with self.assertRaises(ValueError):
                review(b"", xml_fields=(field,))

    def test_small_mutation_matrix_never_crashes_or_changes_input(self):
        raw, _ = image()
        selected = [6, 46, 50, 54, 58, 126, 130, 518, 522, 546, 558, 974, 1020, 1038, len(raw)-4]
        for offset in selected:
            for mask in (1, 0x80):
                changed = bytearray(raw)
                changed[offset] ^= mask
                immutable = bytes(changed)
                before = hashlib.sha256(immutable).digest()
                report = review(immutable)
                self.assertIn(report["status"], ("OPEN", "FAIL"))
                self.assertEqual(hashlib.sha256(immutable).digest(), before)

    def test_many_truncation_points_never_clean_or_crash(self):
        raw, _ = image()
        for end in (0, 5, 6, 13, 517, 521, 545, 558, 650, 1024, 1039, 65541, 65550, len(raw)-1):
            self.assertFalse(review(raw[:end])["complete"])

    def test_local_cli_input_unchanged_privacy_and_options(self):
        raw, _ = image()
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            path = Path(directory) / "PRIVATE_PATH.image"
            path.write_bytes(raw)
            before = path.read_bytes()
            before_stat = path.stat()
            common = [sys.executable, "-m", "evtx_recovery_review", str(path)]
            result = subprocess.run(common, capture_output=True, check=False)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stderr, b"")
            self.assertNotIn(b"PRIVATE", result.stdout)
            self.assertEqual(path.read_bytes(), before)
            self.assertEqual(path.stat().st_mtime_ns, before_stat.st_mtime_ns)
            explicit = subprocess.run(common + ["--xml-field", "Event/Data"], capture_output=True, check=False)
            self.assertEqual(explicit.returncode, 2)
            self.assertIn(b"PRIVATE_VALUE", explicit.stdout)
            missing = subprocess.run(common[:-1] + [str(path)+"MISSING"], capture_output=True, check=False)
            self.assertEqual(missing.returncode, 3)
            self.assertNotIn(b"PRIVATE_PATH", missing.stdout + missing.stderr)

    def test_invalid_cli_arguments_have_private_json_open(self):
        for arguments in ([], ["PRIVATE_PATH", "--max-bytes", "PRIVATE_123"], ["PRIVATE_PATH", "--PRIVATE_UNKNOWN"]):
            result = subprocess.run([sys.executable, "-m", "evtx_recovery_review", *arguments],
                                    capture_output=True, check=False)
            self.assertEqual(result.returncode, 3)
            self.assertEqual(result.stderr, b"")
            self.assertNotIn(b"PRIVATE", result.stdout)
            report = json.loads(result.stdout)
            self.assertEqual(report["status"], "OPEN")
            self.assertEqual(report["external"]["original_event_identity"], "OPEN")
            self.assertEqual(set(report["external"]), {"original_event_identity", "acquisition_authenticity",
                                                      "host_execution", "full_Windows_rendering", "cvp_eligibility"})

    def test_empty_chunk_cannot_validate_nonempty_declared_ranges(self):
        import binascii
        raw = bytearray(65536)
        raw[:8] = b"ElfChnk\0"
        struct.pack_into("<QQQQIIII", raw, 8, 1, 1, 1, 1, 128, 600, 512, 0)
        struct.pack_into("<I", raw, 124, binascii.crc32(raw[:120] + raw[128:512]))
        report = review(bytes(raw))
        self.assertEqual(report["chunk_candidates"][0]["context_integrity"], "PASS")
        self.assertEqual(report["chunk_candidates"][0]["allocation_model"], "UNVERIFIED")
        self.assertIn("empty_chunk_declared_ranges_uninterpreted", codes(report))
        # All-zero declarations are not documented as a no-record interval;
        # do not invent a supported empty-chunk allocation convention.
        struct.pack_into("<QQQQII", raw, 8, 0, 0, 0, 0, 128, 0)
        struct.pack_into("<I", raw, 124, binascii.crc32(raw[:120] + raw[128:512]))
        report = review(bytes(raw))
        self.assertEqual(report["chunk_candidates"][0]["allocation_model"], "UNVERIFIED")
        self.assertIn("empty_chunk_declared_ranges_uninterpreted", codes(report))

    def test_reader_symlink_parent_traversal_and_platform_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "image"
            path.write_bytes(b"DATA")
            link = Path(directory) / "link"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                read_local(str(link), 10)
            with self.assertRaises(ValueError):
                read_local(str(path.parent / ".." / path.parent.name / path.name), 10)
            with patch.object(os, "supports_dir_fd", set()):
                with self.assertRaises(ValueError):
                    read_local(str(path), 10)


if __name__ == "__main__":
    unittest.main()

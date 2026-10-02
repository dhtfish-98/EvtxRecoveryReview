"""Independent binary fixtures, corruption controls and consumer-facing boundaries."""

from dataclasses import replace
import contextlib
import io
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
import uuid

from evtx_recovery_review._record_core import Limits, review
from evtx_recovery_review._record_core.contracts import encoded
from evtx_recovery_review._record_core.files import read_local
from fixture import (ChunkWriter, TICKS, element, file, nested, nested_template, ordinary,
                     pack, repair_chunk, slot, special, text)

ROOT = "http://schemas.microsoft.com/win/2004/08/events/event"


def event(children=(), attrs=()):
    return element("Event", children, [("xmlns", [text(ROOT)]), *attrs])


def one(tree, values=(), **kwargs):
    writer = ChunkWriter()
    writer.record(tree=tree, values=values, **kwargs)
    return file([writer.finish()])


def change(raw, offset, value, *, repair=True):
    result = bytearray(raw)
    result[offset:offset+len(value)] = value
    if repair and offset >= 4096:
        index = (offset - 4096) // 65536
        start = 4096 + index * 65536
        result[start:start+65536] = repair_chunk(result[start:start+65536])
    return bytes(result)


def codes(result):
    return [row["code"] for row in result["findings"]]


def data_field(result):
    return next(row for row in result["records"][0]["fields"] if row.get("path") == "Event/Data")


class EvidenceTests(unittest.TestCase):
    def test_resident_then_reference_template_with_exact_origin(self):
        raw = ordinary()
        result = review(raw)
        self.assertEqual((result["status"], result["complete"]), ("PASS", True))
        self.assertEqual(len(result["records"]), 2)
        first, second = result["records"]
        self.assertEqual(first["template_relative_offset"], second["template_relative_offset"])
        self.assertEqual(second["utc_100ns"], "2026-10-02T00:00:00.1234567Z")
        facts = {row["path"]: row for row in second["fields"] if "numeric_value" in row}
        self.assertEqual(facts["Event/System/EventID"]["numeric_value"], 4624)
        self.assertEqual(facts["Event/System/EventRecordID"]["numeric_value"], 2)
        row = facts["Event/System/EventID"]
        self.assertLess(row["byte_offset"], second["byte_offset"])
        self.assertGreater(row["value_origins"][0]["byte_offset"], second["byte_offset"])
        self.assertEqual(second["evidence_state"], "VERIFIED_STRUCTURE")

    def test_all_crc_calculated_independently(self):
        import binascii
        raw = ordinary()
        result = review(raw)
        chunk = result["chunks"][0]
        self.assertEqual(result["header"]["crc32_calculated"], binascii.crc32(raw[:120]) & 0xffffffff)
        self.assertEqual(chunk["header_crc32_calculated"], binascii.crc32(raw[4096:4216]+raw[4224:4608]) & 0xffffffff)
        self.assertEqual(chunk["data_crc32_calculated"], binascii.crc32(raw[4608:4096+chunk["free_relative_offset"]]) & 0xffffffff)

    def test_multiple_chunks_and_template_names_do_not_cross(self):
        writers = [ChunkWriter(), ChunkWriter()]
        writers[0].record(1)
        writers[1].record(2)
        result = review(file([w.finish(i+1) for i, w in enumerate(writers)], version=2))
        self.assertEqual(result["status"], "PASS")
        self.assertEqual([r["chunk_index"] for r in result["records"]], [0, 1])
        self.assertEqual(result["records"][1]["byte_offset"], 4096+65536+512)

    def test_default_is_private_exact_field_opt_in(self):
        raw = ordinary()
        default = encoded(review(raw))
        self.assertNotIn(b"SYNTHETIC_HOST", default)
        self.assertNotIn(b"SYNTHETIC_VALUE", default)
        self.assertNotIn(b"SyntheticField", default)
        selected = review(raw, fields=("Event/System/Computer", "Event/EventData/Data/@Name"))
        values = [f["selected_value"] for f in selected["records"][0]["fields"] if "selected_value" in f]
        self.assertEqual(values, ["SYNTHETIC_HOST", "SyntheticField"])
        self.assertNotIn(b"SYNTHETIC_VALUE", encoded(selected))

    def test_absent_opt_in_stays_open_and_hashes_path(self):
        result = review(ordinary(), fields=("Event/PRIVATE_ABSENT",))
        self.assertIn("selected_field_absent", codes(result))
        self.assertNotIn(b"PRIVATE_ABSENT", encoded(result))

    def test_repeated_named_values_keep_occurrence(self):
        raw = one(event([element("Data", [text("a")]), element("Data", [text("b")])]))
        values = [f for f in review(raw, fields=("Event/Data",))["records"][0]["fields"] if f.get("path") == "Event/Data"]
        self.assertEqual([(v["occurrence"], v["selected_value"]) for v in values], [(0,"a"),(1,"b")])

    def test_optional_null_suppresses_immediate_parent_and_attribute(self):
        raw = one(event([element("Data", [slot(0,1,True)], [("Name", [text("discarded")])]),
                         element("Keep", [text("kept")], [("optional", [slot(0,1,True)])])]), [(0,b"")])
        result = review(raw, fields=("Event/Keep",))
        self.assertEqual(result["status"], "PASS")
        self.assertNotIn(b"discarded", encoded(result))
        self.assertEqual(len(result["records"][0]["fields"]), 2)

    def test_dependency_null_suppresses_whole_element(self):
        raw = one(event([element("Data", [text("secret")], dependency=0)]), [(0,b"")])
        self.assertEqual(review(raw)["status"], "PASS")
        self.assertEqual(len(review(raw)["records"][0]["fields"]), 2)
        self.assertNotIn(b"secret", encoded(review(raw)))

    def test_template_bind_is_not_mutated_between_records(self):
        writer = ChunkWriter()
        writer.record(1, [(0,b"")], event([element("Data", [slot(0,1,True)])]))
        writer.record(2, [(1,"visible".encode("utf-16-le"))], referenced=True)
        result = review(file([writer.finish()]), fields=("Event/Data",), mode="lenient")
        self.assertEqual(result["records"][1]["fields"][-1]["selected_value"], "visible")
        self.assertEqual(result["records"][0]["fields"][-1].get("path"), None)

    def test_inline_elements_without_template(self):
        result = review(one(event([element("Data", [text("inline")])]), inline=True), fields=("Event/Data",))
        self.assertEqual(result["status"], "PASS")
        self.assertIsNone(result["records"][0]["template_relative_offset"])
        self.assertEqual(data_field(result)["selected_value"], "inline")

    def test_unicode_scalar_and_names(self):
        raw = one(event([element("项目", [slot(0,1)])]), [(1,"安全😀".encode("utf-16-le"))])
        result = review(raw, fields=("Event/项目",))
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(result["records"][0]["fields"][-1]["selected_value"], "安全😀")

    def test_scalar_type_matrix(self):
        cases = [(0,b"",None), (1,"ok\0".encode("utf-16-le"),"ok"), (2,b"ascii\0","ascii"),
                 (3,pack("b",-5),-5), (4,pack("B",255),255), (5,pack("h",-1000),-1000),
                 (6,pack("H",65535),65535), (7,pack("i",-100000),-100000), (8,pack("I",4000000000),4000000000),
                 (9,pack("q",-9000000000),-9000000000), (10,pack("Q",18000000000),18000000000),
                 (11,pack("f",1.5),1.5), (12,pack("d",-2.25),-2.25), (13,pack("I",1),True),
                 (14,b"\x01\x02",{"binary_hex":"0102"}),
                 (15,uuid.UUID("00112233-4455-6677-8899-aabbccddeeff").bytes_le,"00112233-4455-6677-8899-aabbccddeeff"),
                 (16,pack("I",0x1234),"0x00001234"), (20,pack("I",42),"0x0000002a"),
                 (21,pack("Q",42),"0x000000000000002a"),
                 (19,b"\x01\x02"+bytes(5)+b"\x05"+pack("II",21,100),"S-1-5-21-100")]
        for kind, raw, expected in cases:
            with self.subTest(kind=kind):
                result = review(one(event([element("Data", [slot(0,kind)])]), [(kind,raw)]), fields=("Event/Data",))
                self.assertEqual(result["status"], "PASS")
                self.assertEqual(data_field(result)["selected_value"], expected)

    def test_filetime_and_systemtime_units(self):
        values = [(17,pack("Q",TICKS)), (18,pack("8H",2026,10,5,2,0,0,0,123))]
        result = review(one(event([element("Data", [slot(0,17)]), element("Time", [slot(1,18)])]), values), fields=("Event/Data", "Event/Time"))
        self.assertEqual(result["status"], "PASS")
        data = data_field(result)["selected_value"]
        self.assertEqual(data["utc_100ns"], "2026-10-02T00:00:00.1234567Z")
        self.assertEqual(result["records"][0]["fields"][-1]["selected_value"]["systemtime_utc"], "2026-10-02T00:00:00.123+00:00")

    def test_nonfinite_float_is_finite_json_evidence(self):
        for fmt, kind, number in [("f",11,float("nan")),("d",12,float("inf"))]:
            result = review(one(event([element("Data", [slot(0,kind)])]), [(kind,pack(fmt,number))]), fields=("Event/Data",))
            self.assertEqual(result["status"], "PASS")
            self.assertIsInstance(data_field(result)["selected_value"], dict)
            json.loads(encoded(result))

    def test_supported_arrays_keep_vectors_but_rendering_open(self):
        cases = [(0x81,"a\0b\0".encode("utf-16-le"),["a","b"]), (0x82,b"a\0b\0",["a","b"]),
                 (0x88,pack("II",1,2),[1,2]), (0x8d,pack("II",0,1),[False,True])]
        for kind, raw, expected in cases:
            with self.subTest(kind=kind):
                result = review(one(event([element("Data", [slot(0,kind&127)])]), [(kind,raw)]), fields=("Event/Data",))
                self.assertEqual(result["status"], "OPEN")
                self.assertIn("array_element_expansion_unassessed", codes(result))
                self.assertEqual(data_field(result)["selected_value"], expected)

    def test_nested_binxml_direct_element_and_source_span(self):
        raw = one(event([element("Data", [slot(0,33)])]), [(33,nested(element("Inside", [element("Text", [text("nested")])])) )])
        result = review(raw, fields=("Event/Data/Inside/Text",))
        self.assertEqual(result["status"], "PASS")
        value = next(f for f in result["records"][0]["fields"] if "selected_value" in f)
        self.assertEqual(value["selected_value"], "nested")
        self.assertGreater(value["byte_offset"], result["records"][0]["byte_offset"])

    def test_nested_binxml_resident_template_and_its_values(self):
        inside = element("Inside", [element("Number", [slot(0,8)])])
        raw = one(event([element("Data", [slot(0,33)])]), [(33,nested_template(inside,[(8,pack("I",99))]))])
        result = review(raw, fields=("Event/Data/Inside/Number",))
        self.assertEqual(result["status"],"PASS")
        value = next(f for f in result["records"][0]["fields"] if "selected_value" in f)
        self.assertEqual(value["selected_value"],99)

    def test_forward_bucket_links_are_resolved_after_records(self):
        writer=ChunkWriter();writer.record(1)
        writer.record(2,[],event([element("New",[text("a")])]),template=33)
        raw=file([writer.finish()])
        raw=change(raw,4096+writer.templates[1],pack("I",writer.templates[33]))
        raw=change(raw,4096+writer.templates[33],pack("I",0))
        self.assertEqual(review(raw)["status"],"PASS")

    def test_prefixed_and_child_foreign_namespaces_are_open(self):
        for tree in (event([element("p:Data")]),event([element("Data",attrs=[("xmlns",[text("urn:other")])])])):
            self.assertEqual(review(one(tree))["status"],"OPEN")

    def test_cdata_character_entity_pi_and_continuation(self):
        cdata = b"\x47"+pack("H",1)+"a".encode("utf-16-le")
        char = b"\x08"+pack("H",38)
        raw = one(event([special("pi",("safe","PRIVATE_PI")), element("Data", [cdata+char, special("entity","lt")])]))
        result = review(raw, fields=("Event/Data",))
        self.assertEqual(result["status"], "PASS")
        self.assertEqual(data_field(result)["selected_value"], "a&<")
        self.assertNotIn(b"PRIVATE_PI", encoded(result))

    def test_distinct_templates_and_bucket_chain(self):
        writer = ChunkWriter()
        writer.record(1, [], event([element("One", [text("a")])]), template=1)
        writer.record(2, [], event([element("Two", [text("b")])]), template=33)
        writer.record(3, [], referenced=True, template=1)
        self.assertEqual(review(file([writer.finish()]))["status"], "PASS")

    def test_foreign_namespace_and_root_are_open(self):
        for tree in (element("Other"), element("Event", attrs=[("xmlns",[text("urn:foreign")])])):
            self.assertEqual(review(one(tree))["status"], "OPEN")

    def test_event_numeric_field_unknown_is_not_clean(self):
        result = review(one(event([element("System", [element("EventID", [text("private")])])])) )
        self.assertEqual(result["status"], "OPEN")
        self.assertIn("system_numeric_field_uninterpreted", codes(result))
        self.assertNotIn(b"private", encoded(result))

    def test_duplicate_identifier_marks_both_rows_unverified(self):
        writer = ChunkWriter()
        writer.record(1)
        writer.record(1, referenced=True)
        result = review(file([writer.finish()]))
        self.assertEqual(result["status"], "FAIL")
        self.assertTrue(all(r["evidence_state"] == "UNVERIFIED" for r in result["records"]))

    def test_duplicate_identifier_across_chunks(self):
        writers = [ChunkWriter(),ChunkWriter()]
        for writer in writers:
            writer.record(1)
        result = review(file([w.finish(i+1) for i,w in enumerate(writers)]))
        self.assertIn("duplicate_record_identifier", codes(result))
        self.assertTrue(all(r["record_checks"] == "FAIL" for r in result["records"]))

    def test_archived_zero_allocated_space_after_last_record(self):
        raw = ordinary()
        chunk = bytearray(raw[4096:])
        free = struct.unpack_from("<I",chunk,48)[0]
        struct.pack_into("<I",chunk,48,free+16)
        self.assertEqual(review(file([repair_chunk(chunk)]))["status"], "PASS")

    def test_deterministic_and_immutable(self):
        raw = ordinary()
        before = raw[:]
        self.assertEqual(encoded(review(raw)), encoded(review(raw)))
        self.assertEqual(raw, before)


class CorruptionTests(unittest.TestCase):
    def test_unknown_input_and_truncation_are_not_clean(self):
        for raw in (b"",b"abc",b"NotEVTX!",ordinary()[:4000],ordinary()[:-1]):
            with self.subTest(size=len(raw)):
                result = review(raw)
                self.assertNotEqual(result["status"], "PASS")
                self.assertFalse(result["complete"])

    def test_file_crc_strict_stop_lenient_propagates(self):
        raw = change(ordinary(),124,b"\0\0\0\0",repair=False)
        strict, lenient = review(raw), review(raw,mode="lenient")
        self.assertEqual((strict["status"],len(strict["records"])),("FAIL",0))
        self.assertEqual(len(lenient["records"]),2)
        self.assertTrue(all(r["integrity"] == "FAIL" and r["evidence_state"] == "UNVERIFIED" for r in lenient["records"]))

    def test_chunk_header_and_data_crc_failure_are_separate(self):
        for offset, code in ((4096+124,"chunk_header_crc_mismatch"),(4096+52,"chunk_data_crc_mismatch")):
            raw = change(ordinary(),offset,bytes(4),repair=False)
            strict,lenient = review(raw),review(raw,mode="lenient")
            self.assertIn(code,codes(strict))
            self.assertFalse(strict["complete"])
            self.assertEqual(len(lenient["records"]),2)
            self.assertTrue(all(r["evidence_state"] == "UNVERIFIED" for r in lenient["records"]))

    def test_trailer_failure_lenient_keeps_next_bounded_record(self):
        raw = ordinary()
        size = struct.unpack_from("<I",raw,4612)[0]
        raw = change(raw,4608+size-4,pack("I",size+8))
        strict,lenient = review(raw),review(raw,mode="lenient")
        self.assertIn("record_trailing_size_mismatch",codes(strict))
        self.assertEqual(len(strict["records"]),1)
        self.assertEqual(len(lenient["records"]),2)
        self.assertEqual(lenient["records"][0]["evidence_state"],"UNVERIFIED")
        self.assertEqual(lenient["records"][1]["evidence_state"],"VERIFIED_STRUCTURE")

    def test_record_boundaries_and_magic(self):
        for offset,value in ((4608,b"wrong"),(4612,pack("I",31)),(4612,pack("I",33)),(4612,pack("I",0xffffffff))):
            result = review(change(ordinary(),offset,value),mode="lenient")
            self.assertEqual(result["status"],"FAIL")
            self.assertFalse(result["complete"])

    def test_chunk_boundaries_and_magic(self):
        for offset,value in ((4096,b"wrong!!!"),(4144,pack("I",511)),(4144,pack("I",65537))):
            result = review(change(ordinary(),offset,value,repair=False),mode="lenient")
            self.assertEqual(result["status"],"FAIL")
            self.assertFalse(result["complete"])

    def test_last_record_offset_and_range_failure_unverifies(self):
        for offset,value in ((4140,pack("I",512)),(4120,pack("Q",999)),(4128,pack("Q",999))):
            result = review(change(ordinary(),offset,value))
            self.assertEqual(result["status"],"FAIL")
            self.assertTrue(all(r["evidence_state"] == "UNVERIFIED" for r in result["records"]))

    def test_filetime_overflow_retains_raw_ticks_without_sentinel(self):
        raw = change(ordinary(),4624,pack("Q",2**64-1))
        result = review(raw)
        self.assertEqual(result["status"],"OPEN")
        self.assertIsNone(result["records"][0]["utc_100ns"])
        self.assertEqual(result["records"][0]["filetime_ticks"],2**64-1)
        self.assertEqual(result["records"][0]["evidence_state"],"UNVERIFIED")

    def test_type_size_null_bool_unicode_and_sid_defects(self):
        cases = [(8,b"x","typed_value_size_mismatch"),
                 (13,pack("I",2),"invalid_evtx_boolean"),(1,b"x","odd_utf16_length"),
                 (1,b"\x00\xd8","invalid_utf16"),(1,b"\0\0\0\0","invalid_xml_character"),
                 (19,b"bad","invalid_sid_structure"),(18,pack("8H",2026,2,0,30,0,0,0,0),"invalid_systemtime")]
        for kind,raw,code in cases:
            with self.subTest(kind=kind,code=code):
                result = review(one(event([element("Data",[slot(0,kind)])]),[(kind,raw)]))
                self.assertEqual(result["status"],"FAIL")
                self.assertIn(code,codes(result))
                self.assertFalse(result["records"][0]["binxml_complete"])

    def test_unknown_kinds_ansi_and_ambiguous_arrays_are_open(self):
        for kind,raw in ((0,b"x"),(0x7f,b"x"),(2,b"\xff"),(16,b"xxx"),(0x90,bytes(8)),(0x93,bytes(8)),(0x8e,b"x")):
            result = review(one(event([element("Data",[slot(0,kind&127)])]),[(kind,raw)]))
            self.assertEqual(result["status"],"OPEN")

    def test_bad_array_lengths_or_termination_fail(self):
        for kind,raw in ((0x88,b"x"),(0x81,"a".encode("utf-16-le")),(0x82,b"a"),(0x81,b"\0\xd8\0\0")):
            result = review(one(event([element("Data",[slot(0,kind&127)])]),[(kind,raw)]))
            self.assertEqual(result["status"],"FAIL")

    def test_substitution_index_type_and_dependency_bounds(self):
        cases = [(event([element("Data",[slot(1,1)])]),[(1,b"")],"substitution_index_outside_values"),
                 (event([element("Data",[slot(0,8)])]),[(1,b"")],"substitution_type_mismatch"),
                 (event([element("Data",dependency=1)]),[],"dependency_index_outside_values")]
        for tree,values,code in cases:
            result = review(one(tree,values))
            self.assertIn(code,codes(result))
            self.assertEqual(result["status"],"FAIL")

    def test_descriptor_flag_does_not_silently_ignore(self):
        raw = ordinary()
        result = review(raw)
        first = result["records"][0]
        origin = next(f for f in first["fields"] if f.get("path") == "Event/System/EventID")["value_origins"][0]["byte_offset"]
        # Four descriptors precede the first value; first descriptor reserved byte is at -13.
        damaged = change(raw,origin-13,b"\x01")
        self.assertIn("unknown_substitution_descriptor_flag",codes(review(damaged)))
        self.assertEqual(review(damaged)["status"],"OPEN")

    def test_forward_and_outside_template_references(self):
        raw = ordinary()
        second = review(raw)["records"][1]["byte_offset"]
        for pointer,state,code in ((second-4096+50,"OPEN","unresolved_or_forward_template_reference"),(100,"FAIL","template_pointer_outside_allocated_chunk")):
            result = review(change(raw,second+24+4+6,pack("I",pointer)),mode="lenient")
            self.assertEqual(result["status"],state)
            self.assertIn(code,codes(result))

    def test_template_self_link_and_reference_identifier_mismatch(self):
        raw = ordinary()
        template = 4096+review(raw)["records"][0]["template_relative_offset"]
        self.assertIn("template_reference_cycle",codes(review(change(raw,template,pack("I",template-4096)))))
        second = review(raw)["records"][1]["byte_offset"]
        self.assertIn("template_instance_identifier_mismatch",codes(review(change(raw,second+30,pack("I",999)))))

    def test_two_template_chain_cycle_invalidates_chunk_record_trust(self):
        writer=ChunkWriter();writer.record(1)
        writer.record(2,[],event([element("New")]),template=33)
        raw=change(file([writer.finish()]),4096+writer.templates[1],pack("I",writer.templates[33]))
        result=review(raw)
        self.assertIn("chunk_table_reference_cycle",codes(result))
        self.assertEqual(result["status"],"FAIL")
        self.assertTrue(all(r["evidence_state"] == "UNVERIFIED" for r in result["records"]))

    def test_name_forward_reference_and_outside_pointer(self):
        writer=ChunkWriter();writer.record(1);writer.record(2,referenced=True)
        raw=file([writer.finish()])
        pointer=4096+writer.templates[1]+24+4+7
        for target,state,code in ((writer.pos-8,"OPEN","unresolved_or_forward_name_reference"),(100,"FAIL","name_pointer_outside_allocated_chunk")):
            result=review(change(raw,pointer,pack("I",target)))
            self.assertEqual(result["status"],state)
            self.assertIn(code,codes(result))

    def test_template_and_element_declared_lengths_are_bounded(self):
        writer=ChunkWriter();writer.record();raw=file([writer.finish()])
        template=4096+writer.templates[1]
        for offset,value,code in ((template+20,pack("I",0xffffffff),"template_length_outside_record"),
                                  (template+28+3,pack("I",0xffffffff),"element_length_outside_parent")):
            result=review(change(raw,offset,value))
            self.assertEqual(result["status"],"FAIL")
            self.assertIn(code,codes(result))

    def test_nested_missing_eof_and_depth_are_not_clean(self):
        def bad(offset,writer):return nested(element("Inside"))(offset,writer)[:-1]
        raw=one(event([element("Data",[slot(0,33)])]),[(33,bad)])
        self.assertEqual(review(raw)["status"],"FAIL")
        tree=element("Deep")
        for _ in range(12):tree=element("Deep",[tree])
        raw=one(event([element("Data",[slot(0,33)])]),[(33,nested(tree))])
        self.assertIn("depth_budget",codes(review(raw,limits=replace(Limits(),depth=8))))

    def test_name_hash_and_self_link_and_terminator(self):
        writer = ChunkWriter()
        writer.record()
        raw = file([writer.finish()])
        offset = 4096+writer.names["Event"]
        for delta,value,code in ((4,b"\0\0","name_hash_mismatch"),(0,pack("I",offset-4096),"name_reference_cycle"),
                                 (8+5*2,b"x\0","missing_name_terminator")):
            result = review(change(raw,offset+delta,value))
            self.assertEqual(result["status"],"FAIL")
            self.assertIn(code,codes(result))

    def test_duplicate_attributes_invalid_xml_names_and_cdata(self):
        for tree,code in ((event(attrs=[("x",[text("a")]),("x",[text("b")])]),"duplicate_xml_attribute"),
                          (event([element("1bad")]),"invalid_xml_name"),
                          (event([element("Data",[b"\x07"+pack("H",3)+"]]>".encode("utf-16-le")])]),"invalid_cdata_terminator")):
            result = review(one(tree))
            self.assertEqual(result["status"],"FAIL")
            self.assertIn(code,codes(result))

    def test_external_entity_does_not_load_or_render(self):
        result = review(one(event([element("Data",[special("entity","PRIVATE_EXTERNAL_ENTITY")])])) )
        self.assertEqual(result["status"],"OPEN")
        self.assertIn("external_or_unknown_entity",codes(result))
        self.assertNotIn(b"PRIVATE_EXTERNAL_ENTITY",encoded(result))

    def test_unknown_tokens_fragment_flags_and_chunk_flags(self):
        raw = ordinary()
        for offset,value,code in ((4632,b"\xef","unknown_binxml_token_or_flag"),(4633,b"\x02","unsupported_fragment_version_or_flag"),
                                 (4096+120,pack("I",1),"unknown_chunk_flag_field")):
            result = review(change(raw,offset,value))
            self.assertIn(code,codes(result))
            self.assertEqual(result["status"],"OPEN")

    def test_valid_second_fragment_is_open_in_single_event_projection(self):
        writer=ChunkWriter();writer.record(1,[],event(),inline=True)
        raw=file([writer.finish()])
        # The ordinary inline Event ends before EOF; reusing a one-element payload
        # twice is a document-level scope gap, not an assertion of malformed EVTX.
        from evtx_recovery_review._record_core.binxml import BinXML
        from evtx_recovery_review._record_core.contracts import Ledger, Issue
        payload_start=4608+24
        payload_end=4608+writer.records[0][1]-4
        ledger=Ledger(Limits())
        cursor_end=payload_end
        # Find EOF from the known fixture's encoded element length.
        size=struct.unpack_from("<I",raw,payload_start+4+3)[0]
        eof=payload_start+4+7+size
        extra=raw[:eof]+b"\x0f\x01\x01\0"+raw[eof:]
        parser=BinXML(extra,4096,4096+writer.pos+4,ledger)
        with self.assertRaises(Issue) as caught:parser.document(payload_start,cursor_end+4)
        self.assertEqual(caught.exception.code,"multiple_document_fragments_unassessed")
        self.assertEqual(caught.exception.state,"OPEN")

    def test_unknown_flags_and_nonzero_inactive_bytes(self):
        self.assertIn("unknown_file_flags",codes(review(file([ChunkWriterFixture()],flags=4))))
        self.assertIn("dirty_file_metadata_uncommitted",codes(review(file([ChunkWriterFixture()],flags=1))))
        self.assertEqual(review(ordinary()+b"PRIVATE_TRAILING")["status"],"OPEN")

    def test_unresolved_table_reference_and_moved_name_bucket(self):
        raw = ordinary()
        self.assertIn("uninterpreted_chunk_table_reference", codes(review(change(raw,4096+128,pack("I",65000)))))
        writer = ChunkWriter(); writer.record()
        raw = file([writer.finish()]); pointer=writer.names["Event"]
        # Move a head to a definitely empty bucket to retain a parsed target but break the hash bucket.
        empty = next(k for k in range(64) if k not in writer.name_heads)
        raw = change(raw,4096+128+empty*4,pack("I",pointer))
        self.assertIn("name_table_bucket_mismatch",codes(review(raw)))

    def test_zero_record_padding_must_not_hide_nonzero_data(self):
        raw = ordinary()
        row = review(raw)["records"][1]
        result = review(change(raw,row["byte_end"]-5,b"x"),mode="lenient")
        self.assertIn("nonzero_record_padding_uninterpreted",codes(result))
        self.assertEqual(result["status"],"OPEN")

    def test_token_depth_values_and_array_budgets(self):
        for limits in (replace(Limits(),tokens=2),replace(Limits(),depth=1),replace(Limits(),references=1),
                       replace(Limits(),name_chars=1),replace(Limits(),value_bytes=1),replace(Limits(),values=1),
                       replace(Limits(),records=1)):
            result = review(ordinary(),limits=limits)
            self.assertEqual(result["status"],"OPEN")
            self.assertFalse(result["complete"])
            self.assertTrue(any(c.endswith("_budget") for c in codes(result)))
        raw = one(event([element("Data",[slot(0,8)])]),[(0x88,pack("II",1,2))])
        self.assertIn("array_items_budget",codes(review(raw,limits=replace(Limits(),array_items=1))))

    def test_chunk_and_input_budgets(self):
        a,b=ChunkWriter(),ChunkWriter();a.record(1);b.record(2)
        self.assertIn("chunks_budget",codes(review(file([a.finish(),b.finish(2)]),limits=replace(Limits(),chunks=1))))
        self.assertIn("input_bytes_budget",codes(review(ordinary(),limits=replace(Limits(),input_bytes=10))))

    def test_over_input_cap_does_not_hash_rejected_bytes(self):
        raw = ordinary()
        with patch("evtx_recovery_review._record_core.contracts.digest") as direct_digest:
            with patch("evtx_recovery_review._record_core.contracts.hashlib.sha256") as sha256:
                result = review(raw, limits=replace(Limits(), input_bytes=10))
        direct_digest.assert_not_called()
        sha256.assert_not_called()
        self.assertEqual(result["status"], "OPEN")
        self.assertIsNone(result["input_sha256"])
        self.assertEqual(result["input_digest_status"], "OPEN")
        self.assertIsNone(result["input_digest_scope"])
        admitted = review(raw)
        self.assertEqual(admitted["input_digest_status"], "PASS")
        self.assertEqual(admitted["input_digest_scope"], "whole_input")
        import hashlib
        self.assertEqual(admitted["input_sha256"], hashlib.sha256(raw).hexdigest())

    def test_modern_dword_chunk_count_high_word_is_open_not_reserved_failure(self):
        import binascii
        raw = bytearray(ordinary())
        struct.pack_into("<I", raw, 42, 65537)
        struct.pack_into("<I", raw, 124, binascii.crc32(raw[:120]) & 0xffffffff)
        result = review(bytes(raw))
        self.assertEqual(result["header"]["declared_chunks"], 65537)
        self.assertEqual(result["header"]["integrity"], "PASS")
        self.assertEqual(result["status"], "OPEN")
        self.assertIn("chunks_budget", codes(result))
        self.assertEqual(result["known_corruption_count"], 0)
        self.assertEqual(result["records"], [])

    def test_report_budget_preserves_known_corruption_priority(self):
        raw=ordinary()
        limited=review(raw,limits=replace(Limits(),report_bytes=2048))
        self.assertEqual(limited["status"],"OPEN")
        self.assertEqual(limited["records"],[])
        corrupted=change(raw,124,bytes(4),repair=False)
        result=review(corrupted,mode="lenient",limits=replace(Limits(),report_bytes=2048))
        self.assertEqual(result["status"],"FAIL")
        self.assertGreater(result["known_corruption_count"],0)
        self.assertLessEqual(len(encoded(result)),2048)

    def test_hash_work_budget_and_bounded_serialization(self):
        result=review(ordinary(),limits=replace(Limits(),work_bytes=1))
        self.assertIn("work_bytes_budget",codes(result))
        self.assertEqual(result["status"],"OPEN")
        raw=one(event([element("Data",[slot(0,1)])]),[(1,("😀"*5000).encode("utf-16-le"))])
        result=review(raw,fields=("Event/Data",),limits=replace(Limits(),report_bytes=2048))
        self.assertEqual(result["status"],"OPEN")
        self.assertEqual(result["emitted_record_count"],0)
        self.assertEqual(result["inspected_record_count"],1)
        self.assertLessEqual(len(encoded(result)),2048)

    def test_canonical_json_stream_chunks_escape_without_whole_string(self):
        from evtx_recovery_review._record_core.contracts import json_chunks, bounded_encoded, value_digest, Ledger
        import hashlib
        value={"z":("😀"*2000+"\n\"\\",True,None,1.25),"a":[1,2]}
        chunks=list(json_chunks(value))
        self.assertLessEqual(max(len(c.encode()) for c in chunks),6144)
        self.assertEqual(''.join(chunks).encode()+b'\n',encoded(value))
        self.assertEqual(value_digest(value,Ledger(Limits()),0),hashlib.sha256(encoded(value)).hexdigest())
        self.assertIsNone(bounded_encoded(value,2048))

    def test_repeated_template_slots_do_not_materialize_unbounded_join(self):
        raw=one(event([element("Data",[slot(0,1)]*4000)]),[(1,("x"*8192).encode("utf-16-le"))])
        result=review(raw,fields=("Event/Data",))
        self.assertIn("work_bytes_budget",codes(result))
        self.assertEqual(result["status"],"OPEN")
        self.assertLess(len(encoded(result)),4096)

    def test_findings_budget_preserves_open_and_fail_counts(self):
        raw=change(ordinary(),124,bytes(4),repair=False)
        result=review(raw,limits=replace(Limits(),findings=1))
        self.assertEqual(result["status"],"FAIL")
        self.assertGreater(result["omitted_findings"],0)
        self.assertFalse(result["complete"])

    def test_api_and_field_contracts_are_strict(self):
        for value in (False,0,{},[]):
            with self.assertRaises(TypeError):review(ordinary(),limits=value)
        for kwargs in ({"mode":"guess"},{"fields":["Event"]},{"fields":("Event/*",)},{"fields":("Data",)}):
            with self.assertRaises((TypeError,ValueError)):review(ordinary(),**kwargs)
        with self.assertRaises(TypeError):review(bytearray(ordinary()))
        for value in (0,False,2**31):
            with self.assertRaises(ValueError):replace(Limits(),records=value)

    def test_deterministic_malformed_matrix_does_not_crash(self):
        rng=random.Random(9876)
        raw=ordinary()
        with contextlib.redirect_stderr(io.StringIO()) as stderr:
            for _ in range(240):
                offset=rng.randrange(4096,4096+struct.unpack_from("<I",raw,4144)[0])
                damaged=change(raw,offset,bytes([rng.randrange(256)]))
                result=review(damaged,mode="lenient")
                self.assertIn(result["status"],("PASS","OPEN","FAIL"))
                json.loads(encoded(result))
            for stop in (0,1,7,8,31,45,127,128,4095,4096,4607,4608,len(raw)-1):
                self.assertNotEqual(review(raw[:stop])["status"],"PASS")
        self.assertEqual(stderr.getvalue(),"")


def ChunkWriterFixture():
    writer=ChunkWriter();writer.record();return writer.finish()


class ReaderCliTests(unittest.TestCase):
    def test_unsupported_platform_capabilities_fail_before_open(self):
        for flag in ("O_DIRECTORY", "O_NOFOLLOW", "O_NONBLOCK"):
            saved = getattr(os, flag)
            try:
                delattr(os, flag)
                with patch("evtx_recovery_review._record_core.files.os.open") as opened:
                    with self.assertRaisesRegex(ValueError, "platform_secure_open_unsupported"):
                        read_local("/PRIVATE_PATH/file.evtx", 10)
                    opened.assert_not_called()
            finally:
                setattr(os, flag, saved)
        with patch("evtx_recovery_review._record_core.files.os.supports_dir_fd", set()):
            with self.assertRaisesRegex(ValueError, "platform_secure_open_unsupported"):
                read_local("/PRIVATE_PATH/file.evtx", 10)
        from evtx_recovery_review._record_core.cli import main
        with patch("evtx_recovery_review._record_core.files.os.supports_dir_fd", set()):
            with contextlib.redirect_stderr(io.StringIO()) as stderr:
                with contextlib.redirect_stdout(io.StringIO()) as stdout:
                    self.assertEqual(main(["/PRIVATE_PATH/file.evtx"]), 3)
        self.assertEqual(stderr.getvalue(), "unavailable_or_invalid_local_snapshot\n")
        self.assertEqual(stdout.getvalue(), "")

    def test_reader_regular_bytes_are_unchanged(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            path=Path(directory)/"e.evtx";path.write_bytes(ordinary())
            before=path.stat()
            self.assertEqual(read_local(path,Limits().input_bytes),ordinary())
            after=path.stat()
            self.assertEqual((before.st_size,before.st_mtime_ns,before.st_ctime_ns),(after.st_size,after.st_mtime_ns,after.st_ctime_ns))

    def test_reader_leaf_and_parent_links_and_traversal_are_rejected(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            root=Path(directory);path=root/"e.evtx";path.write_bytes(ordinary())
            (root/"link").symlink_to(path)
            (root/"parent").symlink_to(root,target_is_directory=True)
            for target in (root/"link",root/"parent"/"e.evtx",str(root)+"/../x"):
                with self.assertRaises((OSError,ValueError)):read_local(target,Limits().input_bytes)
            for target in ("-","https://example.invalid/log.evtx",root):
                with self.assertRaises((OSError,ValueError)):read_local(target,Limits().input_bytes)

    def test_reader_nonregular_fifo_and_budget(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            path=Path(directory)/"fifo";os.mkfifo(path)
            with self.assertRaises(ValueError):read_local(path,100)
            path=Path(directory)/"e.evtx";path.write_bytes(ordinary())
            with self.assertRaises(ValueError):read_local(path,10)

    def test_controlled_short_read_and_changed_identity_are_open_input_errors(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            path=Path(directory)/"e.evtx";path.write_bytes(ordinary())
            with patch("evtx_recovery_review._record_core.files.os.read",return_value=b""):
                with self.assertRaisesRegex(ValueError,"snapshot_changed_or_short_read"):read_local(path,Limits().input_bytes)
            original=os.fstat;count=[0]
            def changed(fd):
                info=original(fd);count[0]+=1
                if count[0]==2:
                    values=list(info);values[1]+=1;return os.stat_result(values)
                return info
            with patch("evtx_recovery_review._record_core.files.os.fstat",side_effect=changed):
                with self.assertRaises(ValueError):read_local(path,Limits().input_bytes)

    def test_cli_json_jsonl_field_and_status(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            path=Path(directory)/"e.evtx";path.write_bytes(ordinary())
            for args in ([],["--jsonl"],["--field","Event/System/Computer"]):
                completed=subprocess.run([sys.executable,"-m","evtx_recovery_review._record_core",str(path),*args],capture_output=True)
                self.assertEqual(completed.returncode,0,completed.stderr)
                self.assertEqual(completed.stderr,b"")
                rows=[json.loads(line) for line in completed.stdout.splitlines()]
                self.assertEqual(rows[-1]["status"],"PASS")
                if "--jsonl" in args:self.assertEqual([r["kind"] for r in rows],["record","record","summary"])
                if not args:self.assertNotIn(b"SYNTHETIC_HOST",completed.stdout)
            self.assertEqual(path.read_bytes(),ordinary())

    def test_cli_fail_open_and_argument_privacy(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as directory:
            path=Path(directory)/"e.evtx"
            for raw,code in ((b"unknown",2),(change(ordinary(),124,bytes(4),repair=False),1)):
                path.write_bytes(raw)
                completed=subprocess.run([sys.executable,"-m","evtx_recovery_review._record_core",str(path)],capture_output=True)
                self.assertEqual(completed.returncode,code)
            completed=subprocess.run([sys.executable,"-m","evtx_recovery_review._record_core",str(path),"--PRIVATE_SECRET"],capture_output=True)
            self.assertEqual(completed.returncode,3)
            self.assertEqual(completed.stderr,b"invalid_arguments\n")
            self.assertNotIn(b"PRIVATE_SECRET",completed.stdout+completed.stderr)
            path.write_bytes(ordinary())
            completed=subprocess.run([sys.executable,"-m","evtx_recovery_review._record_core",str(path),"--field","Event/*"],capture_output=True)
            self.assertEqual(completed.returncode,3)
            self.assertNotIn(b"Traceback",completed.stderr)

    def test_cli_help_and_version_are_local(self):
        for option in ("--help","--version"):
            completed=subprocess.run([sys.executable,"-m","evtx_recovery_review._record_core",option],capture_output=True)
            self.assertEqual(completed.returncode,0)
            self.assertEqual(completed.stderr,b"")


if __name__=="__main__":unittest.main()

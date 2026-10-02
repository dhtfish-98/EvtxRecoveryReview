"""Independent resident/nonresident grammar hypotheses for bounded orphan records."""
from ._record_core.binary import Cursor
from ._record_core.binxml import Value
from .decoder import Decoder
from ._record_core.values import typed, filetime
from .contracts import Issue, Probe, is_budget, charge_record, digest, diagnostic


def boundary(raw, offset, ledger):
    cursor = Cursor(raw, offset, len(raw))
    if cursor.dword() != 0x2A2A:
        raise Issue("record_magic_mismatch", offset)
    size = cursor.dword()
    if size < 32 or size % 8:
        raise Issue("record_length_or_alignment_invalid", offset + 4)
    if size > ledger.limits.record_bytes:
        raise Issue("record_bytes_budget", offset + 4)
    if size > len(raw) - offset:
        raise Issue("truncated_record_candidate", offset + 4)
    identifier, ticks = cursor.qword(), cursor.qword()
    end = offset + size
    if Cursor(raw, end - 4, end).dword() != size:
        raise Issue("record_trailing_size_mismatch", end - 4)
    row = {"byte_offset": offset, "byte_end": end, "bytes": size,
            "record_identifier": identifier, "filetime_ticks": ticks,
            "header_identity_origin": {"record_identifier_offset": offset + 8, "filetime_offset": offset + 16,
                                       "identity_domain": "raw_record_header_not_Event_System"},
            "wire_sha256": charge_record(raw, offset, end, ledger),
            "evidence_state": "UNVERIFIED", "original_event_identity": "OPEN",
            "recovery_status": "INCOMPLETE", "fields": [], "reconstructed_XML": [],
            "template_candidates": [], "diagnostics": [], "allocation": "ORPHAN"}
    try:
        row["utc_100ns"] = filetime(ticks, offset + 16)
    except Issue as issue:
        row["utc_100ns"] = None
        row["diagnostics"].append(diagnostic(issue))
        ledger.add("OPEN", issue.code, issue.offset, candidate_offset=offset)
    return row


def start_cursor(raw, row):
    cursor = Cursor(raw, row["byte_offset"] + 24, row["byte_end"] - 4)
    if cursor.peek() == 15:
        offset = cursor.pos
        if cursor.take(4) != b"\x0f\x01\x01\0":
            raise Issue("unsupported_fragment_version_or_flag", offset)
    return cursor


def resident(raw, row, ledger):
    probe = Probe(ledger)
    cursor = start_cursor(raw, row)
    first = cursor.peek()
    if first == 12:
        cursor.take(2)
        cursor.dword()
        relative = cursor.dword()
        chunk_start = cursor.pos - relative
    elif first in (1, 65):
        cursor.take(7)
        relative = cursor.dword()
        chunk_start = cursor.pos - relative
    elif first == 10:
        cursor.byte()
        relative = cursor.dword()
        chunk_start = cursor.pos - relative
    else:
        raise Issue("orphan_resident_or_inline_grammar_unresolved", cursor.pos)
    record_relative = row["byte_offset"] - chunk_start
    if not 512 <= record_relative or record_relative % 8 or record_relative + row["bytes"] > 65536:
        raise Issue("orphan_chunk_coordinate_hypothesis_outside_profile", row["byte_offset"])
    probe.consume_bytes(row["bytes"], row["byte_offset"])
    parser = Decoder(raw, chunk_start, chunk_start + 65536, probe)
    tree, relative, prolog = parser.document(row["byte_offset"] + 24, row["byte_end"] - 4)
    if tree is None:
        raise Issue("orphan_empty_document_unresolved", row["byte_offset"] + 24)
    return {"tree": tree, "parser": parser, "probe": probe, "template": relative,
            "hypothesized_chunk_offset": chunk_start, "prolog": parser.pi_seen}


def nonresident(raw, row, ledger):
    probe = Probe(ledger)
    cursor = start_cursor(raw, row)
    offset = cursor.pos
    if cursor.take(2) != b"\x0c\x01":
        raise Issue("nonresident_template_instance_required", offset)
    instance, pointer = cursor.dword(), cursor.dword()
    if not 512 <= pointer < 65536:
        raise Issue("nonresident_template_pointer_outside_profile", offset + 6)
    count_offset, count = cursor.pos, cursor.dword()
    if count > ledger.limits.values:
        raise Issue("substitution_count_budget", count_offset)
    descriptions = []
    for _ in range(count):
        offset = cursor.pos
        probe.tick(offset)
        size, kind, reserved = cursor.word(), cursor.byte(), cursor.byte()
        if reserved:
            raise Issue("unknown_substitution_descriptor_flag", offset + 3)
        descriptions.append((size, kind))
    probe.consume_bytes(row["bytes"], row["byte_offset"])
    values = []
    for size, kind in descriptions:
        offset = cursor.pos
        probe.tick(offset)
        raw_value = cursor.take(size)
        value = typed(kind, raw_value, offset, probe)
        values.append(Value(kind, value, offset, digest(raw_value)))
    if cursor.byte() != 0:
        raise Issue("nonresident_document_eof_missing", cursor.pos - 1)
    if cursor.end - cursor.pos > 7:
        raise Issue("nonresident_padding_layout_unresolved", cursor.pos)
    if any(cursor.take(cursor.end - cursor.pos)):
        probe.add("OPEN", "nonzero_record_padding_uninterpreted", cursor.pos)
    return {"instance": instance, "declared_template_relative_offset": pointer,
            "values": values, "probe": probe}


def attempt(function, *arguments):
    try:
        return function(*arguments), None
    except Issue as issue:
        if is_budget(issue):
            raise
        return None, issue

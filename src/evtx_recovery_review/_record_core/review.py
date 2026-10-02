"""EVTX file/chunk/record integrity and positioned, bounded event evidence."""

import binascii
import struct
from .binary import Cursor
from .binxml import BinXML
from .contracts import Issue, Ledger, Limits, digest
from .projection import facts, select_fields
from .values import filetime


def crc(raw):
    return binascii.crc32(raw) & 0xFFFFFFFF


def review(raw, *, mode="strict", fields=(), limits=None):
    if type(raw) is not bytes:
        raise TypeError("immutable_bytes_required")
    if limits is None:
        limits = Limits()
    if not isinstance(limits, Limits):
        raise TypeError("Limits_required")
    if mode not in ("strict", "lenient"):
        raise ValueError("strict_or_lenient_required")
    selected = select_fields(fields)
    ledger, header, chunks, records = Ledger(limits), None, [], []
    try:
        if len(raw) > limits.input_bytes:
            raise Issue("input_bytes_budget", 0)
        if len(raw) < 8:
            raise Issue("input_header_incomplete", 0)
        cursor = Cursor(raw, 0, len(raw))
        if cursor.take(8) != b"ElfFile\0":
            raise Issue("unrecognized_input_format", 0)
        first, last, next_id = cursor.qword(), cursor.qword(), cursor.qword()
        header_size, minor, major, block_size = cursor.dword(), cursor.word(), cursor.word(), cursor.word()
        # Frozen modern libyal format/C profile: DWORD@42. Historical python-evtx
        # uses WORD@42; nonzero high WORD exceeds our bounded profile and is OPEN.
        count = cursor.dword()
        if header_size != 128 or block_size != 4096:
            raise Issue("unsupported_file_header_layout", 32)
        if major != 3 or minor not in (1, 2):
            raise Issue("unsupported_evtx_version", 36)
        Cursor(raw, 0, 4096)
        flags, stored = struct.unpack_from("<II", raw, 120)
        header = {"byte_offset": 0, "major": major, "minor": minor,
                  "declared_chunks": count, "first_chunk_number": first,
                  "last_chunk_number": last, "next_record_identifier": next_id,
                  "flags": flags, "crc32_stored": stored, "crc32_calculated": crc(raw[:120])}
        header["integrity"] = "PASS" if stored == header["crc32_calculated"] else "FAIL"
        if header["integrity"] == "FAIL":
            ledger.add("FAIL", "file_header_crc_mismatch", 124)
            if mode == "strict":
                ledger.add("OPEN", "file_records_unassessed_due_crc", 4096)
                return ledger.finish(raw, header, chunks, records, mode)
        if flags & ~3:
            ledger.add("OPEN", "unknown_file_flags", 120)
        if flags & 1:
            ledger.add("OPEN", "dirty_file_metadata_uncommitted", 120)
        if count > limits.chunks:
            raise Issue("chunks_budget", 42)
        if len(raw) < 4096 + count * 65536:
            raise Issue("truncated_declared_chunks", len(raw), "FAIL")
        if count and last - first + 1 != count:
            ledger.add("OPEN", "chunk_number_allocation_model_unknown", 8)
        if any(raw[4096 + count * 65536:]):
            ledger.add("OPEN", "nonzero_inactive_or_trailing_bytes", 4096 + count * 65536)
        ids = {}
        for chunk_index in range(count):
            start = 4096 + chunk_index * 65536
            try:
                _chunk(raw, start, chunk_index, header, ledger, records, chunks, ids, selected, mode)
            except Issue as issue:
                ledger.issue(issue, chunk_index=chunk_index)
                if issue.state == "FAIL":
                    ledger.add("OPEN", "chunk_records_unassessed_after_structure_error", issue.offset,
                               chunk_index=chunk_index)
                if issue.code.endswith("_budget"):
                    break
    except Issue as issue:
        ledger.issue(issue)
        if issue.state == "FAIL":
            ledger.add("OPEN", "file_review_incomplete", issue.offset)
    return ledger.finish(raw, header, chunks, records, mode)


def _chunk(raw, start, index, header, ledger, records, chunks, ids, selected, mode):
    cursor = Cursor(raw, start, start + 65536)
    if cursor.take(8) != b"ElfChnk\0":
        raise Issue("invalid_chunk_magic", start, "FAIL")
    first_number, last_number, first_id, last_id = [cursor.qword() for _ in range(4)]
    header_size, last_offset, free_offset, data_crc = [cursor.dword() for _ in range(4)]
    if header_size != 128:
        raise Issue("unsupported_chunk_header_layout", start + 40)
    if not 512 <= free_offset <= 65536:
        raise Issue("chunk_free_offset_outside_bounds", start + 48, "FAIL")
    header_crc = struct.unpack_from("<I", raw, start + 124)[0]
    calculated_header = crc(raw[start:start + 120] + raw[start + 128:start + 512])
    calculated_data = crc(raw[start + 512:start + free_offset])
    chunk = {"chunk_index": index, "byte_offset": start, "first_record_number": first_number,
             "last_record_number": last_number, "first_record_identifier": first_id,
             "last_record_identifier": last_id, "last_record_relative_offset": last_offset,
             "free_relative_offset": free_offset, "header_crc32_stored": header_crc,
             "header_crc32_calculated": calculated_header, "data_crc32_stored": data_crc,
             "data_crc32_calculated": calculated_data, "record_count": 0,
             "integrity": "PASS" if header_crc == calculated_header and data_crc == calculated_data else "FAIL"}
    chunks.append(chunk)
    if struct.unpack_from("<I", raw, start + 120)[0]:
        ledger.add("OPEN", "unknown_chunk_flag_field", start + 120, chunk_index=index)
    if header_crc != calculated_header:
        ledger.add("FAIL", "chunk_header_crc_mismatch", start + 124, chunk_index=index)
    if data_crc != calculated_data:
        ledger.add("FAIL", "chunk_data_crc_mismatch", start + 52, chunk_index=index)
    if chunk["integrity"] == "FAIL" and mode == "strict":
        ledger.add("OPEN", "chunk_records_unassessed_due_crc", start + 512, chunk_index=index)
        return
    binxml = BinXML(raw, start, start + free_offset, ledger)
    position, observed_ids, observed_offsets = start + 512, [], []
    chunk_record_start, walked = len(records), True
    while position < start + free_offset:
        # Archived chunks may checksum zero-filled free space beyond their last record.
        if position > start + last_offset and not any(raw[position:start + free_offset]):
            break
        ledger.record_count += 1
        if ledger.record_count > ledger.limits.records:
            raise Issue("records_budget", position)
        record = Cursor(raw, position, start + free_offset)
        if record.dword() != 0x2A2A:
            raise Issue("invalid_record_magic", position, "FAIL")
        size = record.dword()
        if size < 32 or size % 8 or size > record.end - position:
            raise Issue("record_size_outside_bounds_or_alignment", position + 4, "FAIL")
        identifier, ticks = record.qword(), record.qword()
        trailer = struct.unpack_from("<I", raw, position + size - 4)[0]
        row = {"chunk_index": index, "byte_offset": position, "byte_end": position + size,
               "bytes": size, "record_identifier": identifier, "filetime_ticks": ticks,
               "utc_100ns": None, "wire_sha256": digest(raw[position:position + size]),
               "record_structure": "PASS" if trailer == size else "FAIL", "binxml_complete": False,
               "record_checks": "PASS", "evidence_state": "UNVERIFIED",
               "integrity": "PASS" if header["integrity"] == chunk["integrity"] == "PASS" and trailer == size else "FAIL",
               "fields": [], "template_relative_offset": None}
        records.append(row)
        chunk["record_count"] += 1
        observed_ids.append(identifier)
        observed_offsets.append(position - start)
        if identifier in ids:
            ledger.add("FAIL", "duplicate_record_identifier", position + 8, chunk_index=index)
            ids[identifier].update(record_checks="FAIL", evidence_state="UNVERIFIED")
            row["record_checks"] = "FAIL"
        ids[identifier] = row
        try:
            row["utc_100ns"] = filetime(ticks, position + 16)
        except Issue as issue:
            ledger.issue(issue, record_offset=position)
            row["record_checks"] = issue.state
        if trailer != size:
            ledger.add("FAIL", "record_trailing_size_mismatch", position + size - 4)
            if mode == "strict":
                walked = False
                break
        before = ledger.gaps
        try:
            tree, template, _ = binxml.document(position + 24, position + size - 4)
            row["template_relative_offset"] = template
            row["fields"] = facts(tree, selected, ledger)
            row["binxml_complete"] = ledger.gaps == before
        except Issue as issue:
            ledger.issue(issue, record_offset=position)
            if issue.state == "FAIL":
                ledger.add("OPEN", "record_binxml_uninterpreted", issue.offset, record_offset=position)
            if issue.code.endswith("_budget"):
                raise
            if mode == "strict":
                walked = False
                break
        row["evidence_state"] = "VERIFIED_STRUCTURE" if row["integrity"] == row["record_checks"] == "PASS" and row["binxml_complete"] else "UNVERIFIED"
        position += size
    if not walked:
        ledger.add("OPEN", "remaining_chunk_records_unassessed", position)
    range_failure = False
    if walked and observed_offsets and observed_offsets[-1] != last_offset:
        ledger.add("FAIL", "last_record_offset_mismatch", start + 44)
        range_failure = True
    if observed_ids and (observed_ids[0] != first_id or walked and observed_ids[-1] != last_id):
        ledger.add("FAIL", "chunk_record_identifier_range_mismatch", start + 24)
        range_failure = True
    if walked and observed_ids and last_number - first_number + 1 != len(observed_ids):
        ledger.add("OPEN", "chunk_record_number_range_uninterpreted", start + 8)
    if range_failure:
        for row in records[chunk_record_start:]:
            row.update(record_checks="FAIL", evidence_state="UNVERIFIED")
    try:
        binxml.verify_tables()
    except Issue as issue:
        ledger.issue(issue, chunk_index=index)
        if issue.code.endswith("_budget"):
            raise
        if issue.state == "FAIL":
            for row in records[chunk_record_start:]:
                row.update(record_checks="FAIL", evidence_state="UNVERIFIED")

"""Chunk CRC/header/allocation walk and positioned template collection."""
import binascii
import itertools
import struct
from ._record_core.binary import Cursor
from .contracts import Issue, Probe, is_budget, diagnostic
from .decoder import Decoder
from .orphans import boundary


def crc(raw):
    return binascii.crc32(raw) & 0xFFFFFFFF


def new_templates(parser, previous):
    count = len(parser.templates) - previous
    keys = list(itertools.islice(reversed(parser.templates), count))
    return [parser.templates[key] for key in reversed(keys)]


def context(raw, start, ledger, catalog, records, publish):
    ledger.tick(start, "chunks")
    row = {"byte_offset": start, "byte_end": min(start + 65536, len(raw)),
           "context_integrity": "UNVERIFIED", "allocation_model": "UNVERIFIED",
           "record_offsets": [], "diagnostics": []}
    if len(raw) - start < 65536:
        row["diagnostics"].append({"state": "OPEN", "code": "truncated_chunk_candidate", "byte_offset": start})
        ledger.add("OPEN", "truncated_chunk_candidate", start)
        return row, None
    cursor = Cursor(raw, start, start + 65536)
    cursor.take(8)
    first_number, last_number, first_id, last_id = [cursor.qword() for _ in range(4)]
    header_size, last_offset, free_offset, data_crc = [cursor.dword() for _ in range(4)]
    if header_size != 128:
        row["diagnostics"].append({"state": "OPEN", "code": "unsupported_chunk_header_layout", "byte_offset": start + 40})
        ledger.add("OPEN", "unsupported_chunk_header_layout", start + 40)
        return row, None
    if not 512 <= free_offset <= 65536:
        ledger.add("FAIL", "chunk_free_offset_outside_bounds", start + 48)
        row["diagnostics"].append({"state": "FAIL", "code": "chunk_free_offset_outside_bounds", "byte_offset": start + 48})
        return row, None
    ledger.consume_bytes(65536 + free_offset, start)
    calculated_header = crc(raw[start:start + 120] + raw[start + 128:start + 512])
    calculated_data = crc(raw[start + 512:start + free_offset])
    header_crc = struct.unpack_from("<I", raw, start + 124)[0]
    row.update(free_relative_offset=free_offset, last_record_relative_offset=last_offset,
               first_record_identifier=first_id, last_record_identifier=last_id,
               header_crc32_stored=header_crc, header_crc32_calculated=calculated_header,
               data_crc32_stored=data_crc, data_crc32_calculated=calculated_data,
               context_integrity="PASS" if header_crc == calculated_header and data_crc == calculated_data else "FAIL")
    for code, offset, bad in (("chunk_header_crc_mismatch", start + 124, header_crc != calculated_header),
                              ("chunk_data_crc_mismatch", start + 52, data_crc != calculated_data)):
        if bad:
            ledger.add("FAIL", code, offset)
            row["diagnostics"].append({"state": "FAIL", "code": code, "byte_offset": offset})
    if struct.unpack_from("<I", raw, start + 120)[0]:
        ledger.add("OPEN", "unknown_chunk_flag_field", start + 120)
    parser = Decoder(raw, start, start + free_offset, ledger)
    position, local_records, origins, walked = start + 512, [], [], True
    while position < start + free_offset:
        if position > start + last_offset and not any(raw[position:start + free_offset]):
            break
        ledger.tick(position, "candidates")
        ledger.record_count += 1
        if ledger.record_count > ledger.limits.records:
            raise Issue("records_budget", position)
        try:
            record = boundary(raw, position, ledger)
            if record["byte_end"] > start + free_offset:
                raise Issue("allocated_record_outside_chunk", position + 4, "FAIL")
        except Issue as issue:
            if is_budget(issue):
                raise
            ledger.add("FAIL", issue.code, issue.offset, chunk_offset=start)
            record = {"byte_offset": position, "allocation": "ALLOCATED", "recovery_status": "TRUNCATED" if
                      "truncated" in issue.code else "REJECTED", "evidence_state": "UNVERIFIED",
                      "diagnostics": [diagnostic(issue)], "fields": [], "template_candidates": [], "reconstructed_XML": []}
            records.append(record)
            row["record_offsets"].append(position)
            walked = False
            break
        record.update(allocation="ALLOCATED", chunk_offset=start, context_integrity=row["context_integrity"])
        records.append(record)
        local_records.append(record)
        row["record_offsets"].append(position)
        before = parser.checkpoint()
        probe = Probe(ledger)
        parser.ledger, parser.pi_seen = probe, False
        try:
            tree, relative, _ = parser.document(position + 24, record["byte_end"] - 4)
            ledger.merge(probe, candidate=position)
            record["recovery_status"] = "RECOVERED_CONTEXT" if tree is not None else "INCOMPLETE"
            record["grammar_complete"] = not bool(probe.gaps or probe.failures or probe.dropped)
            definitions = new_templates(parser, before[1])
            for definition in definitions:
                group = catalog.add(definition, chunk_offset=start, context_integrity=row["context_integrity"],
                                    record_offset=position, allocation="ALLOCATED")
                origins.extend(group["origins"][-1:])
            if relative in parser.templates:
                definition = parser.templates[relative]
                group = catalog.by_definition.get((start, definition[1]))
                if group is not None:
                    record["template_candidates"] = [catalog.public(group)]
            publish(record, tree, parser.pi_seen)
        except Issue as issue:
            parser.rollback(before)
            if is_budget(issue):
                raise
            record["diagnostics"].append(diagnostic(issue))
            record["grammar_complete"] = False
            record["recovery_status"] = "INCOMPLETE"
            ledger.issue(issue, candidate_offset=position)
        finally:
            parser.ledger = ledger
        position = record["byte_end"]
    identifiers = [record["record_identifier"] for record in local_records]
    valid = walked
    if not identifiers:
        ledger.add("OPEN", "empty_chunk_declared_ranges_uninterpreted", start + 8)
        valid = False
    if identifiers and (identifiers[0] != first_id or walked and identifiers[-1] != last_id):
        ledger.add("FAIL", "chunk_record_identifier_range_mismatch", start + 24)
        valid = False
    if local_records and walked and local_records[-1]["byte_offset"] - start != last_offset:
        ledger.add("FAIL", "last_record_offset_mismatch", start + 44)
        valid = False
    if len(set(identifiers)) != len(identifiers):
        ledger.add("FAIL", "duplicate_identifier_inside_allocated_chunk", start)
        valid = False
    if identifiers and last_number - first_number + 1 != len(identifiers):
        ledger.add("OPEN", "chunk_record_number_range_uninterpreted", start + 8)
        valid = False
    try:
        parser.verify_tables()
    except Issue as issue:
        if is_budget(issue):
            raise
        ledger.issue(issue, chunk_offset=start)
        valid = False
    row["allocation_model"] = "PASS" if valid else "UNVERIFIED"
    for record in local_records:
        record["context_allocation_model"] = row["allocation_model"]
    for origin in origins:
        origin["context_allocation_model"] = row["allocation_model"]
    return row, parser

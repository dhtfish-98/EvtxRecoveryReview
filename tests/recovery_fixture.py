"""Independent actual wire fixtures; shared writer is credited to EvtxRecordReview."""
import struct
from fixture import ChunkWriter, TICKS, element, pack, slot, text


ROOT = "http://schemas.microsoft.com/win/2004/08/events/event"
PRIVATE = 'PRIVATE_VALUE<&>\'"中文😀\n'


def tree(label="One", *, optional=False, dependency=65535, kind=1):
    return element("Event", [element("System", [element("EventID", [slot(1, 8)]),
                          element("EventRecordID", [slot(2, 10)])]),
                          element("Data", [slot(0, kind, optional)], [("Name", [text(label)])],
                                  dependency=dependency)], [("xmlns", [text(ROOT)])])


def records(label="One", *, template_id=7, kind=1, value=None):
    if value is None:
        value = PRIVATE.encode("utf-16-le")
    writer = ChunkWriter()
    for number in (1, 2):
        writer.record(number, [(kind, value), (8, pack("I", 42)), (10, pack("Q", number))],
                      tree(label, kind=kind), template=template_id, referenced=number == 2)
    chunk = writer.finish()
    resident_offset, resident_size, _ = writer.records[0]
    reference_offset, reference_size, _ = writer.records[1]
    return chunk, chunk[resident_offset:resident_offset+resident_size], chunk[reference_offset:reference_offset+reference_size]


def image(catalog=1, *, duplicate_origin=False):
    chunk, resident, orphan = records()
    chunks = [chunk] if catalog else []
    if catalog == 2:
        chunks.append(records("Two")[0])
    if duplicate_origin:
        chunks.append(chunk)
    raw = b"PREFIX" + b"".join(c + b"GAP" for c in chunks) + b"ORPHAN" + orphan
    return raw, len(raw) - len(orphan)


def resident_lookalike_record():
    # Deliberately invalid dual-looking prefix: six descriptor-like words also
    # resemble a resident definition. Link6 is outside the valid chunk range,
    # and the sixth UTF-16 descriptor has odd size. Neither grammar is valid;
    # a heuristic choice based only on counts/types would invent evidence.
    writer = ChunkWriter()
    record_relative = 512
    payload = b"\x0f\x01\x01\0\x0c\x01" + pack("II", 0, record_relative + 38)
    definition_relative = record_relative + 38
    body = writer.node(element("Event", [text("A" * 113)], dependency=0), definition_relative + 24) + b"\0"
    assert struct.unpack_from("<I", body, 3)[0] == 256 and len(body) == 264
    definition = pack("I", 6) + bytes(16) + pack("I", len(body)) + body
    payload += definition + pack("I", 1) + pack("HBB", 0, 0, 0) + b"\0"
    size = (24 + len(payload) + 4 + 7) // 8 * 8
    result = pack("IIQQ", 0x2a2a, size, 99, TICKS) + payload
    return result + bytes(size - 4 - len(result)) + pack("I", size)

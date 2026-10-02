"""Synthetic EVTX writer independent of the runtime; no production log data."""

from datetime import datetime, timezone
import binascii
import struct


TICKS = int((datetime(2026, 10, 2, tzinfo=timezone.utc) -
             datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds()) * 10_000_000 + 1234567


def pack(kind, *values):
    return struct.pack("<" + kind, *values)


def text(value):
    raw = value.encode("utf-16-le")
    return b"\x05\x01" + pack("H", len(raw) // 2) + raw


def slot(index, kind, optional=False):
    return bytes([14 if optional else 13]) + pack("HB", index, kind)


def element(name, children=(), attrs=(), dependency=65535):
    return {"name": name, "children": list(children), "attrs": list(attrs), "dependency": dependency}


def special(kind, value):
    return (kind, value)


def nested(tree):
    def encode(offset, writer):
        return b"\x0f\x01\x01\0" + writer.node(tree, offset + 4, dependency=False) + b"\0"
    return encode


def nested_template(tree, values, template=7):
    def encode(offset, writer):
        pointer = offset + 4 + 10
        body = b"\x0f\x01\x01\0" + writer.node(tree, pointer + 28) + b"\0"
        bucket = template % 32
        link = writer.template_heads.get(bucket, 0)
        writer.template_heads[bucket] = pointer
        definition = pack("I", link) + pack("I",template) + bytes(range(4,16)) + pack("I",len(body)) + body
        return (b"\x0f\x01\x01\0\x0c\x01" + pack("II",template,pointer) + definition +
                pack("I",len(values)) + b"".join(pack("HBB",len(raw),kind,0) for kind,raw in values) +
                b"".join(raw for _,raw in values) + b"\0")
    return encode


DEFAULT = element("Event", [element("System", [
    element("EventID", [slot(0, 8)]), element("EventRecordID", [slot(1, 10)]),
    element("Level", [text("4")]), element("Computer", [slot(2, 1)])]),
    element("EventData", [element("Data", [slot(3, 1, True)], [("Name", [text("SyntheticField")])])])],
    [("xmlns", [text("http://schemas.microsoft.com/win/2004/08/events/event")])])


class ChunkWriter:
    def __init__(self):
        self.raw = bytearray(65536)
        self.pos, self.names, self.templates = 512, {}, {}
        self.name_heads, self.template_heads = {}, {}
        self.records = []

    def name(self, value, offset):
        if value in self.names:
            return pack("I", self.names[value])
        encoded = value.encode("utf-16-le")
        hash_value = 0
        for p in range(0, len(encoded), 2):
            hash_value = (hash_value * 65599 + int.from_bytes(encoded[p:p+2], "little")) & 65535
        target = offset + 4
        bucket = hash_value % 64
        link = self.name_heads.get(bucket, 0)
        self.names[value] = target
        self.name_heads[bucket] = target
        return pack("IIHH", target, link, hash_value, len(encoded)//2) + encoded + b"\0\0"

    def node(self, node, offset, *, dependency=True):
        if isinstance(node, bytes):
            return node
        if isinstance(node, tuple):
            kind, value = node
            if kind == "entity":
                return b"\x09" + self.name(value, offset + 1)
            if kind == "pi":
                raw = value[1].encode("utf-16-le")
                return b"\x0a" + self.name(value[0], offset + 1) + b"\x0b" + pack("H", len(raw)//2) + raw
            raise ValueError("unknown_fixture_token")
        prefix = (b"\x41" if node["attrs"] else b"\x01") + (
            pack("H", node["dependency"]) if dependency else b"")
        body = self.name(node["name"], offset + len(prefix) + 4)
        if node["attrs"]:
            attrs_offset = offset + len(prefix) + 4 + len(body) + 4
            attrs = b""
            for i, (name, pieces) in enumerate(node["attrs"]):
                attr_token = b"\x46" if i + 1 < len(node["attrs"]) else b"\x06"
                data = attr_token + self.name(name, attrs_offset + len(attrs) + 1)
                attrs += data + b"".join(pieces)
            body += pack("I", len(attrs)) + attrs
        if node["children"]:
            body += b"\x02"
            for child in node["children"]:
                body += self.node(child, offset + len(prefix) + 4 + len(body), dependency=dependency)
            body += b"\x04"
        else:
            body += b"\x03"
        return prefix + pack("I", len(body)) + body

    def record(self, identifier=1, values=None, tree=DEFAULT, *, template=1,
               referenced=False, ticks=TICKS, inline=False):
        if values is None:
            values = [(8, pack("I", 4624)), (10, pack("Q", identifier)),
                      (1, "SYNTHETIC_HOST".encode("utf-16-le")), (1, "SYNTHETIC_VALUE".encode("utf-16-le"))]
        origin = self.pos
        data_offset = origin + 24
        payload = b"\x0f\x01\x01\0"
        if inline:
            payload += self.node(tree, data_offset + 4)
        else:
            if referenced:
                pointer = self.templates[template]
                payload += b"\x0c\x01" + pack("II", template, pointer)
            else:
                pointer = data_offset + 4 + 10
                self.templates[template] = pointer
                template_body = b"\x0f\x01\x01\0" + self.node(tree, pointer + 24 + 4) + b"\0"
                bucket = template % 32
                link = self.template_heads.get(bucket, 0)
                self.template_heads[bucket] = pointer
                guid = pack("I", template) + bytes(range(4,16))
                payload += b"\x0c\x01" + pack("II", template, pointer)
                payload += pack("I", link) + guid + pack("I", len(template_body)) + template_body
            value_start = data_offset + len(payload) + 4 + 4 * len(values)
            resolved = []
            for kind, raw in values:
                raw = raw(value_start, self) if callable(raw) else raw
                resolved.append((kind, raw))
                value_start += len(raw)
            values = resolved
            payload += pack("I", len(values))
            payload += b"".join(pack("HBB", len(raw), kind, 0) for kind, raw in values)
            payload += b"".join(raw for _, raw in values)
        payload += b"\0"
        size = (24 + len(payload) + 4 + 7) // 8 * 8
        raw = pack("IIQQ", 0x2A2A, size, identifier, ticks) + payload
        raw += bytes(size - 4 - len(raw)) + pack("I", size)
        if self.pos + size > len(self.raw):
            raise ValueError("synthetic_chunk_full")
        self.raw[self.pos:self.pos+size] = raw
        self.records.append((origin, size, identifier))
        self.pos += size
        return origin

    def finish(self, first_number=1):
        self.raw[:8] = b"ElfChnk\0"
        first_id, last_id = self.records[0][2], self.records[-1][2]
        self.raw[8:56] = pack("QQQQIIII", first_number, first_number+len(self.records)-1,
                              first_id, last_id, 128, self.records[-1][0], self.pos, 0)
        for bucket, offset in self.name_heads.items():
            self.raw[128+bucket*4:132+bucket*4] = pack("I", offset)
        for bucket, offset in self.template_heads.items():
            self.raw[384+bucket*4:388+bucket*4] = pack("I", offset)
        return repair_chunk(bytes(self.raw))


def repair_chunk(raw):
    result = bytearray(raw)
    free = struct.unpack_from("<I", result, 48)[0]
    struct.pack_into("<I", result, 52, binascii.crc32(result[512:free]) & 0xFFFFFFFF)
    struct.pack_into("<I", result, 124, binascii.crc32(result[:120]+result[128:512]) & 0xFFFFFFFF)
    return bytes(result)


def file(chunks, *, version=1, flags=0):
    header = bytearray(4096)
    header[:8] = b"ElfFile\0"
    count = len(chunks)
    last_id = struct.unpack_from("<Q", chunks[-1], 32)[0] if chunks else 0
    header[8:46] = pack("QQQIHHHI", 0, max(0,count-1), last_id+1, 128, version, 3, 4096, count)
    struct.pack_into("<I", header, 120, flags)
    struct.pack_into("<I", header, 124, binascii.crc32(header[:120]) & 0xFFFFFFFF)
    return bytes(header) + b"".join(chunks)


def ordinary(count=2):
    writer = ChunkWriter()
    for i in range(1, count+1):
        writer.record(i, referenced=i>1)
    return file([writer.finish()])

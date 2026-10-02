"""Explicit immutable byte spans; no implicit slicing beyond a structure."""

import struct
from .contracts import Issue


class Cursor:
    def __init__(self, raw, start, end):
        if not 0 <= start <= end <= len(raw):
            raise Issue("invalid_span", max(0, start), "FAIL")
        self.raw, self.pos, self.end = raw, start, end

    def take(self, size):
        if size < 0 or size > self.end - self.pos:
            raise Issue("truncated_structure", self.pos, "FAIL")
        start = self.pos
        self.pos += size
        return self.raw[start:self.pos]

    def number(self, kind):
        return struct.unpack("<" + kind, self.take(struct.calcsize("<" + kind)))[0]

    def peek(self):
        if self.pos == self.end:
            raise Issue("truncated_structure", self.pos, "FAIL")
        return self.raw[self.pos]

    def byte(self):
        return self.number("B")

    def word(self):
        return self.number("H")

    def dword(self):
        return self.number("I")

    def qword(self):
        return self.number("Q")


def xml_char(code):
    return code in (9, 10, 13) or 0x20 <= code <= 0xD7FF or 0xE000 <= code <= 0xFFFD or 0x10000 <= code <= 0x10FFFF


def unicode_text(raw, offset, *, terminator=False):
    if len(raw) % 2:
        raise Issue("odd_utf16_length", offset, "FAIL")
    try:
        text = raw.decode("utf-16-le", errors="strict")
    except UnicodeError as error:
        raise Issue("invalid_utf16", offset + error.start, "FAIL") from None
    if terminator:
        if not text.endswith("\0"):
            raise Issue("missing_name_terminator", offset, "FAIL")
        text = text[:-1]
    if any(not xml_char(ord(char)) for char in text):
        raise Issue("invalid_xml_character", offset, "FAIL")
    return text


def name_start(code):
    return code in (58, 95) or 65 <= code <= 90 or 97 <= code <= 122 or any(
        low <= code <= high for low, high in ((0xC0, 0xD6), (0xD8, 0xF6), (0xF8, 0x2FF),
        (0x370, 0x37D), (0x37F, 0x1FFF), (0x200C, 0x200D), (0x2070, 0x218F),
        (0x2C00, 0x2FEF), (0x3001, 0xD7FF), (0xF900, 0xFDCF), (0xFDF0, 0xFFFD), (0x10000, 0xEFFFF)))


def xml_name(text, offset):
    if not text or not name_start(ord(text[0])) or any(not (
        name_start(ord(char)) or char in "-." or "0" <= char <= "9" or ord(char) == 0xB7
        or 0x300 <= ord(char) <= 0x36F or 0x203F <= ord(char) <= 0x2040) for char in text[1:]):
        raise Issue("invalid_xml_name", offset, "FAIL")
    return text

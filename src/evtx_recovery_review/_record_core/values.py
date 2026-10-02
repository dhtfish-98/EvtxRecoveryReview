"""Typed EVTX substitutions, exact integer times, finite character encodings."""

from datetime import datetime, timedelta, timezone
import math
import struct
import uuid
from .binary import unicode_text, xml_char
from .contracts import Issue


FORMATS = {3: "b", 4: "B", 5: "h", 6: "H", 7: "i", 8: "I", 9: "q", 10: "Q",
           11: "f", 12: "d", 13: "I", 20: "I", 21: "Q"}
WIDTHS = {**{key: struct.calcsize("<" + value) for key, value in FORMATS.items()},
          15: 16, 17: 8, 18: 16}


def filetime(ticks, offset):
    try:
        seconds, fraction = divmod(ticks, 10_000_000)
        value = datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=seconds)
        return value.strftime("%Y-%m-%dT%H:%M:%S") + ".%07dZ" % fraction
    except (OverflowError, ValueError):
        raise Issue("filetime_outside_calendar", offset) from None


def scalar(kind, raw, offset, ledger, *, nested=None, depth=0):
    if len(raw) > ledger.limits.value_bytes:
        raise Issue("value_bytes_budget", offset)
    if kind == 0:
        if raw:
            # Historical EVTX writers can leave nonzero storage behind a NULL
            # descriptor. Its interpretation is outside our finite value model.
            ledger.add("OPEN", "nonempty_null_storage_uninterpreted", offset)
        return None
    if kind in WIDTHS and len(raw) != WIDTHS[kind]:
        raise Issue("typed_value_size_mismatch", offset, "FAIL")
    if kind in FORMATS:
        value = struct.unpack("<" + FORMATS[kind], raw)[0]
        if kind in (11, 12) and not math.isfinite(value):
            return {"ieee_nonfinite": "nan" if math.isnan(value) else "-inf" if value < 0 else "inf",
                    "raw_bits": raw.hex()}
        if kind == 13:
            if value not in (0, 1):
                raise Issue("invalid_evtx_boolean", offset, "FAIL")
            return bool(value)
        if kind in (20, 21):
            return "0x" + format(value, "0%dx" % (len(raw) * 2))
        return value
    if kind == 1:
        # Scalar substitution may have one trailing NUL; retain any further NUL as a defect.
        return unicode_text(raw[:-2] if raw.endswith(b"\0\0") else raw, offset)
    if kind == 2:
        value = raw[:-1] if raw.endswith(b"\0") else raw
        if any(byte >= 128 for byte in value):
            raise Issue("ansi_codepage_unspecified", offset)
        if any(not xml_char(byte) for byte in value):
            raise Issue("invalid_xml_character", offset, "FAIL")
        return value.decode("ascii")
    if kind == 14:
        return {"binary_hex": raw.hex()}
    if kind == 15:
        return str(uuid.UUID(bytes_le=raw))
    if kind == 16:
        if len(raw) not in (4, 8):
            raise Issue("ambiguous_size_t_width", offset)
        return "0x" + raw[::-1].hex()
    if kind == 17:
        ticks = int.from_bytes(raw, "little")
        return {"filetime_ticks": ticks, "utc_100ns": filetime(ticks, offset)}
    if kind == 18:
        year, month, weekday, day, hour, minute, second, millis = struct.unpack("<8H", raw)
        try:
            value = datetime(year, month, day, hour, minute, second, millis * 1000, timezone.utc)
        except ValueError:
            raise Issue("invalid_systemtime", offset, "FAIL") from None
        if weekday > 6 or millis > 999:
            raise Issue("invalid_systemtime", offset, "FAIL")
        return {"systemtime_utc": value.isoformat(timespec="milliseconds"), "weekday": weekday}
    if kind == 19:
        if len(raw) < 8 or raw[0] != 1 or raw[1] > 15 or len(raw) != 8 + raw[1] * 4:
            raise Issue("invalid_sid_structure", offset, "FAIL")
        authority = int.from_bytes(raw[2:8], "big")
        return "S-1-" + str(authority) + "".join("-" + str(int.from_bytes(raw[p:p+4], "little"))
                                               for p in range(8, len(raw), 4))
    if kind == 33:
        if nested is None:
            raise Issue("nested_binxml_context_missing", offset)
        return nested(offset, offset + len(raw), depth + 1)
    raise Issue("unsupported_value_type", offset)


def typed(kind, raw, offset, ledger, *, nested=None, depth=0):
    ledger.depth(depth, offset)
    if len(raw) > ledger.limits.value_bytes:
        raise Issue("value_bytes_budget", offset)
    if not kind & 0x80:
        return scalar(kind, raw, offset, ledger, nested=nested, depth=depth)
    base = kind & 0x7F
    if base in (1, 2):
        if base == 1:
            if len(raw) % 2:
                raise Issue("odd_utf16_length", offset, "FAIL")
            try:
                text = raw.decode("utf-16-le", "strict")
            except UnicodeError as error:
                raise Issue("invalid_utf16", offset + error.start, "FAIL") from None
        else:
            if any(byte >= 128 for byte in raw):
                raise Issue("ansi_codepage_unspecified", offset)
            text = raw.decode("ascii")
        if raw and not text.endswith("\0"):
            raise Issue("unterminated_string_array", offset, "FAIL")
        if text.count("\0") > ledger.limits.array_items:
            raise Issue("array_items_budget", offset)
        items = text[:-1].split("\0") if text else []
        if any(any(not xml_char(ord(char)) for char in item) for item in items):
            raise Issue("invalid_xml_character", offset, "FAIL")
    else:
        if base == 16:
            raise Issue("ambiguous_size_t_array_width", offset)
        width = WIDTHS.get(base)
        if width is None:
            raise Issue("unsupported_array_type", offset)
        if len(raw) % width:
            raise Issue("typed_array_size_mismatch", offset, "FAIL")
        if len(raw) // width > ledger.limits.array_items:
            raise Issue("array_items_budget", offset)
        items = [scalar(base, raw[p:p+width], offset+p, ledger)
                 for p in range(0, len(raw), width)]
    if len(items) > ledger.limits.array_items:
        raise Issue("array_items_budget", offset)
    return items

"""Independent EVTX-dialect BinXML parser: names, templates, slots and nested trees.

No XML library, entity loader, message DLL, format-string substitution or input code.
"""

from dataclasses import dataclass, field
from .binary import Cursor, unicode_text, xml_char, xml_name
from .contracts import Issue, digest
from .values import typed


@dataclass
class Element:
    name: str
    offset: int
    dependency: int = 65535
    attrs: list = field(default_factory=list)
    children: list = field(default_factory=list)


@dataclass(frozen=True)
class Slot:
    index: int
    kind: int
    optional: bool
    offset: int


@dataclass(frozen=True)
class Value:
    kind: int
    value: object
    offset: int
    raw_sha256: str


@dataclass
class Bound:
    name: str
    offset: int
    attrs: list
    children: list


class BinXML:
    def __init__(self, raw, chunk_start, allocated_end, ledger):
        self.raw, self.start, self.end, self.ledger = raw, chunk_start, allocated_end, ledger
        self.names, self.templates, self.active_templates = {}, {}, set()
        self.name_links, self.template_links = {}, {}

    def token(self, cursor):
        self.ledger.tick(cursor.pos)
        value = cursor.byte()
        if value not in tuple(range(16)) + (0x41, 0x45, 0x46, 0x47, 0x48, 0x49):
            raise Issue("unknown_binxml_token_or_flag", cursor.pos - 1)
        return value

    def name(self, cursor):
        location = cursor.pos
        relative = cursor.dword()
        self.ledger.tick(location, "references")
        target = self.start + relative
        if target == cursor.pos:
            name_cursor = Cursor(self.raw, target, cursor.end)
            link, stored_hash, count = name_cursor.dword(), name_cursor.word(), name_cursor.word()
            if count > self.ledger.limits.name_chars:
                raise Issue("name_chars_budget", target + 6)
            text = xml_name(unicode_text(name_cursor.take((count + 1) * 2), target + 8,
                                        terminator=True), target + 8)
            calculated_hash = 0
            for position in range(target + 8, target + 8 + count * 2, 2):
                calculated_hash = (calculated_hash * 65599 +
                                   int.from_bytes(self.raw[position:position + 2], "little")) & 65535
            if calculated_hash != stored_hash:
                raise Issue("name_hash_mismatch", target + 4, "FAIL")
            if relative in self.names:
                raise Issue("overlapping_name_definition", target, "FAIL")
            if link == relative:
                raise Issue("name_reference_cycle", target, "FAIL")
            if link and not 512 <= link < self.end - self.start:
                raise Issue("name_chain_outside_allocated_chunk", target, "FAIL")
            self.names[relative] = (text, target, name_cursor.pos, stored_hash)
            self.name_links[relative] = link
            cursor.pos = name_cursor.pos
            return text
        if target < location and relative in self.names:
            return self.names[relative][0]
        if not self.start + 512 <= target < self.end:
            raise Issue("name_pointer_outside_allocated_chunk", location, "FAIL")
        raise Issue("unresolved_or_forward_name_reference", location)

    def text(self, cursor):
        location = cursor.pos
        count = cursor.word()
        if count * 2 > self.ledger.limits.value_bytes:
            raise Issue("value_bytes_budget", location)
        raw = cursor.take(count * 2)
        text = unicode_text(raw[:-2] if raw.endswith(b"\0\0") else raw, location + 2)
        return Value(1, text, location + 2, digest(raw))

    def piece(self, cursor, depth):
        offset = cursor.pos
        token = self.token(cursor)
        kind = token & 15
        if kind == 5:
            if cursor.byte() != 1:
                raise Issue("unsupported_inline_value_type", offset + 1)
            return self.text(cursor), bool(token & 64)
        if kind in (13, 14):
            return Slot(cursor.word(), cursor.byte(), kind == 14, offset), False
        if kind == 7:
            value = self.text(cursor)
            if "]]>" in value.value:
                raise Issue("invalid_cdata_terminator", offset, "FAIL")
            return value, bool(token & 64)
        if kind == 8:
            code = cursor.word()
            if not xml_char(code):
                raise Issue("invalid_character_reference", offset, "FAIL")
            return Value(1, chr(code), offset, digest(self.raw[offset:cursor.pos])), bool(token & 64)
        if kind == 9:
            name = self.name(cursor)
            entities = {"lt": "<", "gt": ">", "amp": "&", "quot": '"', "apos": "'"}
            if name not in entities:
                raise Issue("external_or_unknown_entity", offset)
            return Value(1, entities[name], offset, digest(self.raw[offset:cursor.pos])), bool(token & 64)
        raise Issue("invalid_binxml_content_token", offset, "FAIL")

    def character_data(self, cursor, depth, *, attribute=False):
        pieces = []
        while True:
            if attribute and cursor.peek() & 15 not in (5, 8, 9, 13, 14):
                raise Issue("invalid_attribute_value_token", cursor.pos, "FAIL")
            piece, more = self.piece(cursor, depth)
            pieces.append(piece)
            if not more:
                return pieces

    def pi(self, cursor):
        offset = cursor.pos
        if self.token(cursor) != 10:
            raise Issue("invalid_pi_pair", offset, "FAIL")
        target = self.name(cursor)
        if target.casefold() == "xml":
            raise Issue("xml_declaration_pi_unsupported", offset)
        if self.token(cursor) != 11:
            raise Issue("invalid_pi_pair", cursor.pos - 1, "FAIL")
        value = self.text(cursor)
        if "?>" in value.value:
            raise Issue("invalid_pi_terminator", offset, "FAIL")
        # PI is evidence, never executed; it has no event field value.
        return Value(-1, {"pi_target_sha256": digest(target.encode()),
                          "pi_data_sha256": digest(value.value.encode())}, offset,
                     digest(self.raw[offset:cursor.pos]))

    def element(self, cursor, depth, *, dependency=True):
        self.ledger.depth(depth, cursor.pos)
        offset = cursor.pos
        token = self.token(cursor)
        if token not in (1, 65):
            raise Issue("expected_element_start", offset, "FAIL")
        depend = cursor.word() if dependency else 65535
        size = cursor.dword()
        end = cursor.pos + size
        if size < 5 or end > cursor.end:
            raise Issue("element_length_outside_parent", offset, "FAIL")
        element_cursor = Cursor(self.raw, cursor.pos, end)
        name = self.name(element_cursor)
        result = Element(name, offset, depend)
        if token & 64:
            size_offset = element_cursor.pos
            attr_size = element_cursor.dword()
            if attr_size == 0:
                raise Issue("empty_attribute_list_dialect_unsupported", size_offset)
            if attr_size > end - element_cursor.pos:
                raise Issue("attribute_length_outside_element", size_offset, "FAIL")
            attrs = Cursor(self.raw, element_cursor.pos, element_cursor.pos + attr_size)
            seen = set()
            while True:
                attr_offset = attrs.pos
                attr_token = self.token(attrs)
                if attr_token not in (6, 70):
                    raise Issue("expected_attribute_token", attr_offset, "FAIL")
                attr_name = self.name(attrs)
                if attr_name in seen:
                    raise Issue("duplicate_xml_attribute", attr_offset, "FAIL")
                seen.add(attr_name)
                result.attrs.append((attr_name, attr_offset,
                                     self.character_data(attrs, depth, attribute=True)))
                if not attr_token & 64:
                    break
            if attrs.pos != attrs.end:
                raise Issue("attribute_list_size_mismatch", attrs.pos, "FAIL")
            element_cursor.pos = attrs.end
        close = self.token(element_cursor)
        if close == 2:
            while element_cursor.peek() != 4:
                kind = element_cursor.peek() & 15
                if kind == 1:
                    result.children.append(self.element(element_cursor, depth + 1, dependency=dependency))
                elif kind == 10:
                    result.children.append(self.pi(element_cursor))
                else:
                    result.children.extend(self.character_data(element_cursor, depth))
            self.token(element_cursor)
        elif close != 3:
            raise Issue("expected_start_tag_close", element_cursor.pos - 1, "FAIL")
        if element_cursor.pos != end:
            raise Issue("element_size_mismatch", element_cursor.pos, "FAIL")
        cursor.pos = end
        return result

    def headers(self, cursor):
        if cursor.peek() == 15:
            offset = cursor.pos
            self.token(cursor)
            if cursor.take(3) != b"\x01\x01\0":
                raise Issue("unsupported_fragment_version_or_flag", offset)

    def template(self, cursor, depth):
        offset = cursor.pos
        if self.token(cursor) != 12:
            raise Issue("expected_template_instance", offset, "FAIL")
        if cursor.byte() != 1:
            raise Issue("unsupported_template_definition_version", offset + 1)
        instance_id, relative = cursor.dword(), cursor.dword()
        target = self.start + relative
        self.ledger.tick(offset, "references")
        if relative in self.active_templates:
            raise Issue("template_reference_cycle", offset, "FAIL")
        if target == cursor.pos:
            template_cursor = Cursor(self.raw, target, cursor.end)
            link = template_cursor.dword()
            guid, length = template_cursor.take(16), template_cursor.dword()
            if relative in self.templates:
                raise Issue("overlapping_template_definition", target, "FAIL")
            if link == relative:
                raise Issue("template_reference_cycle", target, "FAIL")
            if link and not 512 <= link < self.end - self.start:
                raise Issue("template_chain_outside_allocated_chunk", target, "FAIL")
            if length > cursor.end - template_cursor.pos:
                raise Issue("template_length_outside_record", target + 20, "FAIL")
            tree_cursor = Cursor(self.raw, template_cursor.pos, template_cursor.pos + length)
            self.active_templates.add(relative)
            try:
                self.headers(tree_cursor)
                tree = self.element(tree_cursor, depth + 1)
                if self.token(tree_cursor) != 0 or tree_cursor.pos != tree_cursor.end:
                    raise Issue("template_eof_or_length_mismatch", tree_cursor.pos, "FAIL")
            finally:
                self.active_templates.remove(relative)
            self.templates[relative] = (tree, target, tree_cursor.end, guid, instance_id)
            self.template_links[relative] = link
            cursor.pos = tree_cursor.end
        elif target < offset and relative in self.templates:
            tree = self.templates[relative][0]
            if self.templates[relative][4] != instance_id:
                raise Issue("template_instance_identifier_mismatch", offset + 2, "FAIL")
        elif not self.start + 512 <= target < self.end:
            raise Issue("template_pointer_outside_allocated_chunk", offset + 6, "FAIL")
        else:
            raise Issue("unresolved_or_forward_template_reference", offset + 6)
        count_offset = cursor.pos
        count = cursor.dword()
        if count > self.ledger.limits.values:
            raise Issue("substitution_count_budget", count_offset)
        descriptions = []
        for _ in range(count):
            size, kind, reserved = cursor.word(), cursor.byte(), cursor.byte()
            if reserved:
                raise Issue("unknown_substitution_descriptor_flag", cursor.pos - 1)
            descriptions.append((size, kind))
        values = []
        for size, kind in descriptions:
            value_offset = cursor.pos
            raw = cursor.take(size)
            value = typed(kind, raw, value_offset, self.ledger,
                          nested=self.nested, depth=depth + 1)
            values.append(Value(kind, value, value_offset, digest(raw)))
        return self.bind(tree, values, depth + 1), relative

    def bound_pieces(self, pieces, values):
        result = []
        for piece in pieces:
            if not isinstance(piece, Slot):
                result.append(piece)
                continue
            if piece.index >= len(values):
                raise Issue("substitution_index_outside_values", piece.offset, "FAIL")
            value = values[piece.index]
            if piece.optional and value.kind == 0:
                return None
            expected, actual = piece.kind & 127, value.kind & 127
            if expected != actual and not (expected == 16 and actual in (20, 21)):
                raise Issue("substitution_type_mismatch", piece.offset, "FAIL")
            if value.kind & 128:
                # Preserve the typed vector. We do not assert Windows' repeated-element
                # rendering, especially when several arrays share an enclosing element.
                self.ledger.add("OPEN", "array_element_expansion_unassessed", piece.offset)
            result.append(value)
        return result

    def bind(self, tree, values, depth):
        self.ledger.depth(depth, tree.offset)
        self.ledger.tick(tree.offset)
        if tree.dependency != 65535:
            if tree.dependency >= len(values):
                raise Issue("dependency_index_outside_values", tree.offset, "FAIL")
            if values[tree.dependency].kind == 0:
                return None
        attrs, children = [], []
        for name, offset, pieces in tree.attrs:
            bound = self.bound_pieces(pieces, values)
            if bound is not None:
                attrs.append((name, offset, bound))
        for child in tree.children:
            if isinstance(child, Element):
                bound = self.bind(child, values, depth + 1)
                if bound is not None:
                    children.append(bound)
            else:
                bound = self.bound_pieces([child], values)
                if bound is None:
                    return None
                children.extend(bound)
        return Bound(tree.name, tree.offset, attrs, children)

    def document(self, start, end, depth=0, *, nested=False):
        self.ledger.depth(depth, start)
        cursor = Cursor(self.raw, start, end)
        prolog = self.pi(cursor) if cursor.peek() == 10 else None
        self.headers(cursor)
        relative = None
        if cursor.peek() == 0:
            tree = None
        elif cursor.peek() == 12:
            tree, relative = self.template(cursor, depth + 1)
        else:
            tree = self.bind(self.element(cursor, depth + 1, dependency=not nested), [], depth + 1)
        if cursor.peek() == 10:
            self.pi(cursor)
        if cursor.peek() in (1, 12, 15, 65):
            raise Issue("multiple_document_fragments_unassessed", cursor.pos)
        if self.token(cursor) != 0:
            raise Issue("document_eof_missing", cursor.pos - 1, "FAIL")
        if nested:
            if cursor.pos != end:
                raise Issue("nested_binxml_size_mismatch", cursor.pos, "FAIL")
        else:
            padding_offset = cursor.pos
            if cursor.end - cursor.pos > 7:
                raise Issue("record_padding_layout_unsupported", cursor.pos)
            if any(cursor.take(cursor.end - cursor.pos)):
                self.ledger.add("OPEN", "nonzero_record_padding_uninterpreted", padding_offset)
        return tree, relative, prolog

    def nested(self, start, end, depth):
        return self.document(start, end, depth, nested=True)[0]

    def verify_tables(self):
        for base, count, mapping in ((128, 64, self.names), (384, 32, self.templates)):
            cursor = Cursor(self.raw, self.start + base, self.start + base + count * 4)
            for _ in range(count):
                offset, pointer = cursor.pos, cursor.dword()
                self.ledger.tick(offset, "references")
                if pointer and pointer not in mapping:
                    raise Issue("uninterpreted_chunk_table_reference", offset)
                if base == 128 and pointer and mapping[pointer][3] % 64 != (offset - self.start - base) // 4:
                    raise Issue("name_table_bucket_mismatch", offset, "FAIL")
        # Bucket chains may point forward to definitions resident in later records.
        # Resolve them only after the bounded record walk, without loading slack.
        for mapping, links in ((self.names, self.name_links), (self.templates, self.template_links)):
            checked = set()
            for origin in mapping:
                pointer, active = origin, set()
                while pointer and pointer not in checked:
                    self.ledger.tick(self.start + pointer, "references")
                    if pointer in active:
                        raise Issue("chunk_table_reference_cycle", self.start + pointer, "FAIL")
                    if pointer not in mapping:
                        raise Issue("uninterpreted_chunk_table_chain", self.start + pointer)
                    active.add(pointer)
                    pointer = links[pointer]
                checked.update(active)

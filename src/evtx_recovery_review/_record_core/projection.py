"""Field-selected facts from a bound BinXML tree; original XML is never rendered."""

from .binxml import Bound, Value
from .binary import xml_name
from .contracts import Issue, digest, value_digest


NUMERIC_FIELDS = {"Event/System/EventID": 0xFFFFFFFF,
                  "Event/System/EventRecordID": 0xFFFFFFFFFFFFFFFF,
                  "Event/System/Version": 255, "Event/System/Level": 255,
                  "Event/System/Task": 65535, "Event/System/Opcode": 255}


def select_fields(fields):
    if type(fields) is not tuple or len(fields) > 16:
        raise TypeError("bounded_tuple_field_paths_required")
    result = set()
    for value in fields:
        if type(value) is not str or len(value) > 256:
            raise ValueError("bounded_exact_field_path_required")
        parts = value.split("/")
        if len(parts) > 32 or parts[0] != "Event":
            raise ValueError("exact_Event_field_path_required")
        for index, part in enumerate(parts):
            if part.startswith("@") and index == len(parts) - 1:
                part = part[1:]
            try:
                xml_name(part, 0)
            except Issue:
                raise ValueError("valid_exact_field_path_required") from None
        result.add(value)
    return result


def facts(tree, requested, ledger):
    rows, occurrences = [], {}

    def wire_value(value, depth):
        if isinstance(value, Bound):
            # Preserve typed nested structure only for its digest; no XML execution.
            ledger.depth(depth, value.offset)
            ledger.tick(value.offset)
            return {"name": value.name, "attrs": [(n, [wire_value(v.value, depth+1) for v in ps])
                    for n, _, ps in value.attrs], "children": [wire_value(v.value, depth+1)
                    if isinstance(v, Value) else wire_value(v, depth+1) for v in value.children]}
        return value

    def row(path, offset, pieces, depth):
        if not pieces:
            values, sources, kinds = [""], [], []
        else:
            values = [wire_value(p.value, depth + 1) for p in pieces]
            sources = [{"byte_offset": p.offset, "wire_sha256": p.raw_sha256} for p in pieces]
            kinds = [p.kind for p in pieces]
        if all(type(v) is str for v in values):
            # Bound materialization before joining repeated template slots. Python
            # can otherwise create a huge string from one small wire substitution.
            if sum(len(v) * 4 for v in values) + ledger.work_bytes > ledger.limits.work_bytes:
                raise Issue("work_bytes_budget", offset)
            value = "".join(values)
        else:
            value = values[0] if len(values) == 1 else values
        occurrence = occurrences.get(path, 0)
        occurrences[path] = occurrence + 1
        path_raw = path.encode()
        ledger.consume_bytes(len(path_raw), offset)
        result = {"path_sha256": digest(path_raw), "occurrence": occurrence,
                  "byte_offset": offset, "value_sha256": value_digest(value, ledger, offset),
                  "value_types": kinds, "value_origins": sources}
        if path in NUMERIC_FIELDS:
            number = value if type(value) is int else int(value) if type(value) is str and value and all(
                "0" <= char <= "9" for char in value) and len(value) <= 20 else None
            if number is None or not 0 <= number <= NUMERIC_FIELDS[path]:
                ledger.add("OPEN", "system_numeric_field_uninterpreted", offset)
            else:
                result.update(path=path, numeric_value=number)
        if path in requested:
            result.update(path=path, selected_value=value)
        rows.append(result)

    def visit(node, prefix, depth):
        ledger.depth(depth, node.offset)
        ledger.tick(node.offset)
        if ":" in node.name or any(":" in name and not name.startswith("xmlns:") for name, _, _ in node.attrs):
            ledger.add("OPEN", "namespace_prefix_resolution_unassessed", node.offset)
        if any(name == "xmlns" and (len(pieces) != 1 or pieces[0].value !=
               "http://schemas.microsoft.com/win/2004/08/events/event") for name, _, pieces in node.attrs):
            ledger.add("OPEN", "foreign_Event_namespace_uninterpreted", node.offset)
        path = prefix + ("/" if prefix else "") + node.name
        for name, offset, pieces in node.attrs:
            row(path + "/@" + name, offset, pieces, depth)
        values = [child for child in node.children if isinstance(child, Value) and child.kind != -1]
        elements = [child for child in node.children if isinstance(child, Bound)]
        if values or not elements:
            row(path, node.offset, values, depth)
        for child in elements:
            visit(child, path, depth + 1)
        for child in values:
            if child.kind == 33 and isinstance(child.value, Bound):
                visit(child.value, path, depth + 1)

    if tree is None or tree.name != "Event":
        ledger.add("OPEN", "Event_root_schema_uninterpreted", tree.offset if tree else 0)
    if tree is not None:
        visit(tree, "", 0)
    for path in requested:
        if path not in occurrences:
            ledger.add("OPEN", "selected_field_absent", tree.offset if tree else 0,
                       field_path_sha256=digest(path.encode()))
    return rows

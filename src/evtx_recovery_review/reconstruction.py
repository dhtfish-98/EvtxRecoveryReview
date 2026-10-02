"""Explicit exact-subtree XML from fully bound typed AST; no XML input loader."""
from ._record_core.binxml import Bound, Value
from ._record_core.projection import select_fields
from .contracts import Issue, digest


def select_xml(paths):
    selected = select_fields(paths)
    if any("/@" in path for path in selected):
        raise ValueError("XML_exact_subtree_paths_required")
    return selected


def reconstruct(tree, selected, ledger, *, prolog=False):
    if not selected:
        return []
    results, found = [], set()
    pieces, length = [], 0

    def append(text, offset):
        nonlocal length
        raw = text.encode("utf-8")
        length += len(raw)
        if length > ledger.limits.xml_bytes:
            raise Issue("xml_bytes_budget", offset)
        ledger.consume_bytes(len(raw), offset)
        pieces.append(text)

    def escape(text, offset, attribute=False):
        # Chunk before escaping; XML attribute whitespace and CR must be numeric
        # references to preserve their actual value after XML normalization.
        for start in range(0, len(text), 256):
            chunk = text[start:start + 256].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            chunk = chunk.replace("\r", "&#xD;")
            if attribute:
                chunk = chunk.replace('"', "&quot;").replace("\n", "&#xA;").replace("\t", "&#x9;")
            append(chunk, offset)

    def scalar(value):
        if value.kind == -1:
            raise Issue("PI_lexical_reconstruction_unavailable", value.offset)
        if value.kind & 128:
            raise Issue("array_XML_reconstruction_unassessed", value.offset)
        if type(value.value) is str:
            return value.value
        if type(value.value) is bool:
            return "true" if value.value else "false"
        if type(value.value) is int:
            return str(value.value)
        if value.kind == 0 and value.value is None:
            return ""
        if value.kind == 17 and type(value.value) is dict:
            return value.value["utc_100ns"]
        raise Issue("typed_XML_lexical_rendering_unassessed", value.offset)

    def render(node, depth, inherited_namespace=None, selected_root=False):
        ledger.depth(depth, node.offset)
        ledger.tick(node.offset)
        if ":" in node.name or any(":" in name for name, _, _ in node.attrs):
            raise Issue("namespace_XML_reconstruction_unassessed", node.offset)
        if any(name == "xmlns" and (len(values) != 1 or values[0].value !=
                "http://schemas.microsoft.com/win/2004/08/events/event") for name, _, values in node.attrs):
            raise Issue("namespace_XML_reconstruction_unassessed", node.offset)
        append("<" + node.name, node.offset)
        if selected_root and inherited_namespace and not any(name == "xmlns" for name, _, _ in node.attrs):
            append(' xmlns="' + inherited_namespace + '"', node.offset)
        for name, offset, values in node.attrs:
            append(" " + name + '=\"', offset)
            for value in values:
                escape(scalar(value), value.offset, True)
            append('\"', offset)
        append(">", node.offset)
        for child in node.children:
            if isinstance(child, Bound):
                render(child, depth + 1, inherited_namespace)
            elif isinstance(child, Value) and child.kind == 33 and isinstance(child.value, Bound):
                render(child.value, depth + 1, inherited_namespace)
            else:
                escape(scalar(child), child.offset)
        append("</" + node.name + ">", node.offset)

    def visit(node, prefix, depth, inherited_namespace=None):
        nonlocal pieces, length
        ledger.depth(depth, node.offset)
        ledger.tick(node.offset)
        path = prefix + ("/" if prefix else "") + node.name
        for name, _, values in node.attrs:
            if name == "xmlns":
                inherited_namespace = values[0].value
        if path in selected:
            found.add(path)
            pieces, length = [], 0
            if prolog:
                raise Issue("PI_lexical_reconstruction_unavailable", node.offset)
            render(node, depth, inherited_namespace, True)
            xml = "".join(pieces)
            results.append({"path": path, "byte_offset": node.offset, "status": "INFERRED",
                            "format": "supported_bound_AST_subtree_XML", "xml": xml,
                            "xml_sha256": digest(xml.encode()), "bytes": length,
                            "original_Windows_XML_identity": "OPEN"})
        for child in node.children:
            child = child.value if isinstance(child, Value) and isinstance(child.value, Bound) else child
            if isinstance(child, Bound):
                visit(child, path, depth + 1, inherited_namespace)

    def namespace_and_pi(node, depth):
        ledger.depth(depth, node.offset)
        ledger.tick(node.offset)
        if ":" in node.name or any(":" in name for name, _, _ in node.attrs):
            raise Issue("namespace_XML_reconstruction_unassessed", node.offset)
        for name, _, values in node.attrs:
            if name == "xmlns" and (len(values) != 1 or values[0].value !=
                    "http://schemas.microsoft.com/win/2004/08/events/event"):
                raise Issue("namespace_XML_reconstruction_unassessed", node.offset)
        for child in node.children:
            if isinstance(child, Value) and child.kind == -1:
                raise Issue("PI_lexical_reconstruction_unavailable", child.offset)
            child = child.value if isinstance(child, Value) and isinstance(child.value, Bound) else child
            if isinstance(child, Bound):
                namespace_and_pi(child, depth + 1)

    if tree is not None:
        namespace_and_pi(tree, 0)
        visit(tree, "", 0)
    for path in selected - found:
        ledger.add("OPEN", "selected_XML_subtree_absent", tree.offset if tree else 0,
                   field_path_sha256=digest(path.encode()))
    return results

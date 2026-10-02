"""Full template AST identity and slot/dependency binding, never XML regex matching."""
from ._record_core.binxml import Element, Slot, Value, BinXML
from .contracts import Probe, Issue, is_budget, value_digest, digest


def shape(node, ledger, depth=0):
    ledger.depth(depth, node.offset)
    ledger.tick(node.offset)
    if isinstance(node, Slot):
        return ("slot", node.index, node.kind, node.optional)
    if isinstance(node, Value):
        return ("value", node.kind, node.value)
    if isinstance(node, Element):
        return ("element", node.name, node.dependency,
                [(name, [shape(v, ledger, depth + 1) for v in pieces]) for name, _, pieces in node.attrs],
                [shape(child, ledger, depth + 1) for child in node.children])
    raise Issue("unsupported_template_AST_node", getattr(node, "offset", 0))


class Catalog:
    def __init__(self, raw, ledger):
        self.raw, self.ledger, self.groups = raw, ledger, {}
        self.by_definition = {}
        self.by_instance = {}

    def add(self, definition, *, chunk_offset, context_integrity, record_offset, allocation):
        tree, start, end, guid, instance = definition
        self.ledger.tick(start, "templates")
        semantic = value_digest(shape(tree, self.ledger), self.ledger, start)
        key = (instance, semantic)
        origin = {"byte_offset": start, "byte_end": end, "chunk_offset": chunk_offset,
                  "record_offset": record_offset, "allocation": allocation,
                  "context_integrity": context_integrity, "GUID_sha256": digest(guid),
                  "wire_sha256": self.raw_digest(start, end)}
        if key not in self.groups:
            self.groups[key] = {"instance_identifier": instance, "semantic_AST_sha256": semantic,
                                "tree": tree, "origins": []}
            self.by_instance.setdefault(instance, []).append(self.groups[key])
        if origin not in self.groups[key]["origins"]:
            self.groups[key]["origins"].append(origin)
        self.by_definition[(chunk_offset, start)] = self.groups[key]
        return self.groups[key]

    def raw_digest(self, start, end):
        self.ledger.consume_bytes(end - start, start)
        return digest(self.raw[start:end])

    def match(self, instance, values, candidate_offset):
        matches = []
        for group in self.by_instance.get(instance, ()):
            self.ledger.tick(candidate_offset, "matches")
            probe = Probe(self.ledger)
            try:
                tree = BinXML(self.raw, 0, len(self.raw), probe).bind(group["tree"], values, 0)
                if tree is not None:
                    matches.append((group, tree, probe))
            except Issue as issue:
                if is_budget(issue):
                    raise
                # A different template's failed constraints are not input corruption.
        return matches

    @staticmethod
    def public(group):
        return {key: value for key, value in group.items() if key != "tree"}

    def report(self):
        return [self.public(group) for group in self.groups.values()]

"""Independent bounded image carving, AST catalog matching and provenance decisions."""
from ._record_core.projection import facts, select_fields
from .catalog import Catalog
from .chunks import context, new_templates
from .contracts import Limits, Ledger, Probe, Issue, is_budget, diagnostic
from .orphans import boundary, resident, nonresident, attempt
from .reconstruction import reconstruct, select_xml


def positions(raw, magic, ledger):
    ledger.consume_bytes(len(raw), 0)
    position = raw.find(magic)
    while position >= 0:
        yield position
        position = raw.find(magic, position + 1)


def review(raw, *, fields=(), xml_fields=(), limits=None):
    if type(raw) is not bytes:
        raise TypeError("immutable_bytes_required")
    limits = Limits() if limits is None else limits
    if type(limits) is not Limits:
        raise TypeError("Limits_required")
    selected, xml_selected = select_fields(fields), select_xml(xml_fields)
    ledger, contexts, records, parsers, deferred = Ledger(limits), [], [], [], []
    catalog = Catalog(raw, ledger)
    ledger.add("OPEN", "original_image_and_event_identity_unassessed", 0)
    if len(raw) > limits.input_bytes:
        ledger.add("OPEN", "input_bytes_budget", 0)
        return ledger.finish(raw, contexts, records, [])

    def publish(row, tree, prolog=False):
        offset = row["byte_offset"]
        probe = Probe(ledger)
        try:
            row["fields"] = facts(tree, selected, probe)
        except Issue as issue:
            if is_budget(issue):
                raise
            row["diagnostics"].append(diagnostic(issue))
            probe.issue(issue)
        ledger.merge(probe, candidate=offset, force_open=row["allocation"] != "ALLOCATED")
        row["projection_complete"] = not bool(probe.gaps or probe.failures or probe.dropped)
        try:
            row["reconstructed_XML"] = reconstruct(tree, xml_selected, ledger, prolog=prolog)
        except Issue as issue:
            if is_budget(issue):
                raise
            row["reconstructed_XML"] = []
            row["diagnostics"].append(diagnostic(issue))
            ledger.add("OPEN", issue.code, issue.offset, candidate_offset=offset)

    def remember_resident(row, result, allocation):
        parser = result["parser"]
        for definition in new_templates(parser, 0):
            group = catalog.add(definition, chunk_offset=result["hypothesized_chunk_offset"],
                                context_integrity="UNVERIFIED", record_offset=row["byte_offset"],
                                allocation=allocation)
            row["template_candidates"].append(catalog.public(group))

    def inspect_orphan(row):
        offset = row["byte_offset"]
        containing = []
        for chunk, parser in parsers:
            ledger.tick(offset, "overlaps")
            if chunk["byte_offset"] <= offset and row["byte_end"] <= chunk["byte_end"]:
                containing.append((chunk, parser))
        row["containing_chunk_offsets"] = [chunk["byte_offset"] for chunk, _ in containing]
        if len(containing) == 1 and offset >= containing[0][0]["byte_offset"] + containing[0][0]["free_relative_offset"]:
            chunk, original = containing[0]
            probe = Probe(ledger)
            parser = original.copy_for_slack(probe)
            checkpoint = parser.checkpoint()
            try:
                tree, relative, _ = parser.document(offset + 24, row["byte_end"] - 4)
                if tree is None:
                    raise Issue("slack_empty_document_unresolved", offset + 24)
                row.update(allocation="SLACK", chunk_offset=chunk["byte_offset"],
                           context_integrity=chunk["context_integrity"],
                           context_allocation_model=chunk["allocation_model"],
                           recovery_status="RECOVERED_INFERRED", layout="context_bound_slack",
                           grammar_complete=not bool(probe.gaps or probe.failures or probe.dropped))
                ledger.merge(probe, candidate=offset, force_open=True)
                for definition in new_templates(parser, checkpoint[1]):
                    catalog.add(definition, chunk_offset=chunk["byte_offset"], context_integrity="UNVERIFIED",
                                record_offset=offset, allocation="SLACK")
                if relative in parser.templates:
                    group = catalog.by_definition.get((chunk["byte_offset"], parser.templates[relative][1]))
                    if group is not None:
                        row["template_candidates"] = [catalog.public(group)]
                ledger.add("OPEN", "slack_record_not_covered_by_allocated_data_crc", offset)
                publish(row, tree, parser.pi_seen)
                return
            except Issue as issue:
                if is_budget(issue):
                    raise
                row["diagnostics"].append({**diagnostic(issue), "hypothesis": "chunk_slack"})
        elif len(containing) > 1:
            ledger.add("OPEN", "multiple_containing_chunk_contexts", offset)
        direct, direct_issue = attempt(resident, raw, row, ledger)
        reference, reference_issue = attempt(nonresident, raw, row, ledger)
        for name, issue in (("resident_or_inline", direct_issue), ("nonresident", reference_issue)):
            if issue is not None:
                row["diagnostics"].append({**diagnostic(issue), "hypothesis": name, "state": "OPEN"})
        if direct is not None:
            remember_resident(row, direct, "ORPHAN")
        if direct is not None and reference is not None:
            row.update(recovery_status="AMBIGUOUS", layout="multiple_valid_grammars")
            ledger.add("OPEN", "multiple_valid_record_layout_hypotheses", offset)
            return
        if direct is not None:
            row.update(recovery_status="RECOVERED_INFERRED", layout="resident_or_inline",
                       hypothesized_chunk_offset=direct["hypothesized_chunk_offset"],
                       grammar_complete=not bool(direct["probe"].gaps or direct["probe"].failures or direct["probe"].dropped))
            ledger.merge(direct["probe"], candidate=offset, force_open=True)
            ledger.add("OPEN", "orphan_chunk_coordinate_hypothesis", offset)
            publish(row, direct["tree"], direct["prolog"])
            return
        if reference is not None:
            row.update(layout="nonresident", instance_identifier=reference["instance"],
                       declared_template_relative_offset=reference["declared_template_relative_offset"],
                       substitution_descriptors=[{"kind": value.kind, "byte_offset": value.offset,
                                                 "wire_sha256": value.raw_sha256} for value in reference["values"]],
                       grammar_complete=not bool(reference["probe"].gaps or reference["probe"].failures or reference["probe"].dropped))
            ledger.merge(reference["probe"], candidate=offset, force_open=True)
            deferred.append((row, reference))
            return
        ledger.add("OPEN", "candidate_BinXML_grammar_unresolved", offset)

    try:
        for offset in positions(raw, b"ElfChnk\0", ledger):
            try:
                chunk, parser = context(raw, offset, ledger, catalog, records, publish)
                contexts.append(chunk)
                if parser is not None:
                    parsers.append((chunk, parser))
            except Issue as issue:
                contexts.append({"byte_offset": offset, "context_integrity": "UNVERIFIED",
                                 "allocation_model": "UNVERIFIED", "diagnostics": [diagnostic(issue)]})
                raise
        allocated = {row["byte_offset"] for row in records}
        for offset in positions(raw, b"\x2a\x2a\0\0", ledger):
            if offset in allocated:
                continue
            ledger.tick(offset, "candidates")
            ledger.record_count += 1
            if ledger.record_count > limits.records:
                raise Issue("records_budget", offset)
            try:
                row = boundary(raw, offset, ledger)
            except Issue as issue:
                row = {"byte_offset": offset, "allocation": "ORPHAN", "evidence_state": "UNVERIFIED",
                       "recovery_status": "TRUNCATED" if "truncated" in issue.code else "REJECTED",
                       "diagnostics": [{**diagnostic(issue), "state": "OPEN"}],
                       "fields": [], "reconstructed_XML": [], "template_candidates": []}
                records.append(row)
                if is_budget(issue):
                    raise
                ledger.add("OPEN", issue.code, issue.offset, candidate_offset=offset)
                continue
            records.append(row)
            inspect_orphan(row)
        for row, reference in deferred:
            matches = catalog.match(reference["instance"], reference["values"], row["byte_offset"])
            row["template_candidates"] = [catalog.public(group) for group, _, _ in matches]
            if not matches:
                ledger.add("OPEN", "no_compatible_full_template_AST", row["byte_offset"])
            elif len(matches) > 1:
                row["recovery_status"] = "AMBIGUOUS"
                ledger.add("OPEN", "multiple_compatible_full_template_ASTs", row["byte_offset"], count=len(matches))
            else:
                group, tree, probe = matches[0]
                row["recovery_status"] = "RECOVERED_INFERRED"
                ledger.merge(probe, candidate=row["byte_offset"], force_open=True)
                row["grammar_complete"] &= not bool(probe.gaps or probe.failures or probe.dropped)
                ledger.add("OPEN", "nonresident_template_identity_inferred", row["byte_offset"])
                publish(row, tree)
        relations(records, ledger)
    except Issue as issue:
        ledger.issue(issue)
        ledger.add("OPEN", "candidate_enumeration_or_analysis_incomplete", issue.offset)
    if not records:
        ledger.add("OPEN", "no_validated_record_candidates", 0)
    return ledger.finish(raw, contexts, records, catalog.report())


def relations(records, ledger):
    active, contents, identifiers = [], {}, {}
    for row in sorted(records, key=lambda value: value["byte_offset"]):
        start, end = row["byte_offset"], row.get("byte_end")
        if end is None:
            continue
        active = [other for other in active if other["byte_end"] > start]
        for other in active:
            ledger.tick(start, "overlaps")
            row.setdefault("overlap_offsets", []).append(other["byte_offset"])
            other.setdefault("overlap_offsets", []).append(start)
            ledger.add("OPEN", "overlapping_record_candidates", start, other_offset=other["byte_offset"])
        active.append(row)
        contents.setdefault(row["wire_sha256"], []).append(row)
        identifiers.setdefault(row["record_identifier"], []).append(row)
    for groups, key, code in ((contents, "duplicate_content_offsets", "duplicate_record_wire_content"),
                               (identifiers, "duplicate_identifier_offsets", "duplicate_record_identifier_across_image")):
        for group in groups.values():
            if len(group) > 1:
                offsets = [row["byte_offset"] for row in group]
                for row in group:
                    ledger.tick(row["byte_offset"], "overlaps")
                    row[key] = offsets
                ledger.add("OPEN", code, offsets[0], count=len(offsets))

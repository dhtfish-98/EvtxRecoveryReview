# EvtxRecoveryReview

Offline defensive review of displaced EVTX chunks and orphan records in a local
byte image. It reconstructs candidate evidence through typed template ASTs and
keeps each inference separate from original event identity.

```sh
python -m pip install .
evtx-recovery-review /absolute/path/authorized.image
evtx-recovery-review /absolute/path/authorized.image --field Event/Data
evtx-recovery-review /absolute/path/authorized.image --xml-field Event/Data
```

Default output is bounded JSON with source offsets, CRC evidence, header numeric
IDs/exact 100 ns times, six finite numeric System fields, types and hashes. Other
names/values are hashed. Exact field or subtree selection explicitly discloses
its source values. XML is inferred, correctly escaped and created from a fully
bound typed AST; no XML loader runs on the input. Exact child subtrees retain the
known event namespace. There is no attachment/log output file.

For missing nonresident templates, no compatible AST is `INCOMPLETE`, one is
`RECOVERED_INFERRED`, and multiple distinct ASTs are `AMBIGUOUS`. Equal ASTs keep
all source origins; distinct ASTs with equal slot types remain ambiguous. Template
evidence from failed CRC or hypothetical contexts stays untrusted. Context-bound
allocated records are `RECOVERED_CONTEXT`, which certifies no original identity.
Overlaps, duplicate contents, truncation and unsupported layouts remain visible.

Reports are always OPEN for original image/event identity and incomplete global
image coverage, or FAIL when a known candidate has definite structural/CRC
damage. Exit 2 means a report with OPEN coverage, exit 1 candidate damage, exit 3
fixed private JSON input/options error. `--help` exits 0. The gated CLI requires
POSIX no-follow/directory-open capabilities and rejects symlink path components,
traversal, devices, URLs and stdin. Files are observed as whole byte images; there
is no archive decompression or member traversal, nor a promise to identify the
outer file type. Even container bytes may contain physical candidates, whose
original event identity stays unverified. The bytes API supports immutable
inputs without filesystem access:

```python
from evtx_recovery_review import Limits, review
report = review(image_bytes, limits=Limits(), fields=(), xml_fields=())
```

Defaults cap input 16 MiB, chunks 256, candidates/records 16,384, templates 1,024,
match/overlap comparisons 32,768, tokens 1,000,000, nesting 48, materialized work
64 MiB, each record and inferred XML 65,536 bytes, findings 512 and report 1 MiB.
Other finite decoder/value caps are listed in `Limits`. Positive limits may only
be reduced. Over-cap input is not hashed. Bounded work may stop on a false magic
candidate; its located OPEN gap is retained. Output overflow preserves counters
and damage priority in an OPEN/FAIL summary, without a falsely complete result.

Read [DEFENSIVE_SCOPE.md](DEFENSIVE_SCOPE.md), [ORIGIN.md](ORIGIN.md) and
[VALIDATION.md](VALIDATION.md) for supported profiles and measured evidence.
This is new Codex-assisted recovery work with an explicitly reused independent
decoder, not a sole-authored copy of EVTXtract. Apache-2.0 licenses and original
authors are retained. Application eligibility and acquisition authenticity are OPEN.

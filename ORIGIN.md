# Origin and review boundary

Current implementation author and maintainer: **dhtfish98**. Current package version: **0.1.2**. Upstream authors and reused components retain their original attribution.


[EVTXtract](https://github.com/williballenthin/EVTXtract/tree/0895be4c25125b5d087cc1c51b601e2852a67b85)
is fixed at `0895be4c25125b5d087cc1c51b601e2852a67b85`, Apache-2.0. All selected
source was read: evtxtract init/carvers/templates/utils/main/version, setup.py,
README and full LICENSE.TXT, nine files and 1,567 lines, including seven Python
files and 1,177 lines. Fixed Git blob identities and SHA-256 are in
`evidence/source-gate.json`. Remaining upstream tests/CI/PyInstaller/ignore files,
third-party dependencies and whole repository are not claimed audited.

The new recovery layer replaces original resident-count heuristics, signature-only
template collapse, hardcoded EventID slot 3, XML regex substitution, mmap/lxml
dumping and file writes. It uses full typed AST constraints and preserves all
template origins, ambiguous candidates, damage and resource coverage gaps. It
does not promise all EVTXtract compatibility or original event authenticity.

The complete ten-module independently written decoder from
[EvtxRecordReview](https://github.com/dhtfish-98/EvtxRecordReview/tree/c6b12c0497ee9e28d71c1322c5c01790011732f2)
was originally copied unchanged into `_record_core`, with the original and current byte identities in
`evidence/record-core-provenance.json`. Its prior selected source/primary format
review and observed finite Windows gate are dependency evidence, not new recovery
mechanism contributions. It is based on selected python-evtx source research and
Microsoft MS-EVEN6/libyal format references, as attributed in NOTICE. The new
recovery code does not import the original upstream packages.

The prior separately written wire fixture writer and 73 core test methods are
reused, with test namespace imports adjusted. New image fixtures and recovery
tests encode actual chunks, resident/reference records, values, names and CRCs
without production encoders. Every new runtime/test/package/CI/document/license
file is read completely and hashed at freeze. The root Apache license covers the actual reused portfolio decoder; separate
EVTXtract/python-evtx design-reference license copies are not distributed. New implementation author: dhtfish98. Upstream work and the reused
prior decoder are not new recovery contributions. CVP and
application acceptance remain OPEN.

The current reused decoder differs from its original byte-exact copy in two attribution docstrings and in the secure-reader capability guard (required OS protection flags must be exact positive integers and directory-relative support must be a set/frozenset containing os.open before open). Both original and current hashes are retained. The prior decoder version and event parsing logic are unchanged; these revisions are not a new decoder invention.

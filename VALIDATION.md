# Current validation — 0.1.1

The 2026-10-03 attribution update identifies the new implementation author and maintainer as dhtfish98. The final wheel and sdist were rebuilt, and a fresh isolated consumer ran **124 existing and targeted unittest methods successfully**, imported the installed package from site-packages, exercised the declared CLI contract and matched every shipped runtime/notice byte to current source. Wheel metadata records author dhtfish98 and version 0.1.1; RECORD and source-distribution contents were checked. Current runtime identities are in SOURCE_MANIFEST.json; ATTRIBUTION_UPDATE.json records the exact selected validation scope. The matching private build/install/test logs and artifact hashes are retained in the batch validation records, outside this public project.

This update also checks every required safe-read flag for exact positive integer capability before input is opened. API/CLI tests cover missing, None, zero and boolean flags, ordinary files and symbolic links. The PDF reader additionally refuses a FIFO before open when nonblocking capability is unavailable.

The current safe-file capability gate also requires set/frozenset directory-relative support declarations containing each actually used operation before opening input. Missing, None, empty, malformed or operation-incomplete collections yield the existing controlled unsupported result. Normal set/frozenset declarations and API/CLI rejection-before-open are regression tested.

## Historical validation evidence

The following earlier records retain their original versions, counts and fixed source identities. They are historical observations, not evidence that an old artifact is the current package.

# Measured validation and evidence boundary

The source corpus has 119 passing methods on Python 3.14.6: 73 unchanged prior
decoder tests with package-import names adapted, 38 recovery tests and eight
build identity controls. Actual wire fixtures are encoded by a separately written
test writer, never by production encoding functions. They cover displaced chunks,
orphan resident and nonresident grammar, zero/one/two compatible ASTs, identical
AST multiple origins, equal-type/different-AST ambiguity, instance and slot-type
constraints, optional NULL/dependency suppression, source template/value offsets,
exact header FILETIME, calendar overflow, CRC damage with untrusted origins,
alignment/dual-size/truncation, false magic, slack, overlapping embedded records,
duplicates, unsupported types/nested context/namespaces/PI/arrays, exact XML value
escaping and inherited event namespace, explicit disclosure/default privacy,
input immutability, positive lowered budgets and no whole digest for over-cap
input. Thirty selected mutations and fourteen truncations exercise bounded
recovery robustness; the prior decoder separately retains its 240 seeded
mutations and thirteen truncations. These are measured controls, not exhaustive
fuzzing or format completeness.

Eight build controls verify changed source/wheel/installed bytes, complete license
bytes, required module count and raw CRLF metadata without newline normalization.
The final build gate compares all twenty runtime modules and four complete
license/notice texts across source, built wheel and actual fresh installation.
The exact final fresh installed test/CLI results, artifacts, package metadata,
source manifest identity and direct build-tool license evidence are recorded in
the separate engineering JSON. CI is configured for installed-wheel Python 3.11
and 3.14 on Linux; local results are not presented as observed remote CI.

Independent selected upstream review covers all nine files/1,567 lines frozen
in source-gate.json. Reused private core evidence records the observed targeted
Windows run 37025713841 at exact commit
`c6b12c0497ee9e28d71c1322c5c01790011732f2`: two fixed offline historical files,
1,602 records, 9,496 finite numeric System facts and zero native identity/time/fact
differences. All ten source/wheel/installed core files had exact raw byte identity.
The complete observed aggregate is preserved in record-core-native.json. The
raw record header and Event/System identity domains differ for one issue_38
record and remain separate. Both original product reports retained OPEN coverage.
This proves neither full Windows XML equivalence nor new recovery inference
correctness; no additional Windows acquisition or reconstruction run is claimed.

As a separate measured image-recovery robustness control, the same fixed
system.evtx (SHA-256 ccb83cfefc9038017224cd97b800b66e248fe14529649ddf47907e5a2021449e)
was admitted as an image: 1,603 inspected record candidates including false magic,
no known candidate-corruption failures and an ordinary 1 MiB bounded output
summary (zero emitted rows). issue_38.evtx (SHA-256
becab64455866f8fae5583fbaa5dab901115e4397ea7abe14f37ad732d5d7eb9) inspected
fourteen candidates and stopped with a located substitution-count budget on a
false candidate, retaining OPEN incomplete coverage. These actual runs did not
disable product limits or assert recovered-event equivalence. Raw historical
logs and private event contents are not bundled.

Independent reviewers found an empty chunk's nonempty declared ranges being
marked allocation PASS and argparse error output revealing supplied arguments.
Both were repaired with targeted external-contract regression tests: inconsistent
empty declarations, including all-zero layouts, become UNVERIFIED/OPEN with a positioned diagnostic; all
non-help options errors emit fixed private JSON OPEN with the same five permanent
external OPEN keys. No original event authenticity, complete image coverage,
all EVTX dialect support, complete Windows renderer equivalence or CVP acceptance
is claimed. No raw logs, upstream packages, third-party runtime or XML loaders
are included. The whole Python/platform/build-tool implementation is not audited;
direct pinned build-tool installed metadata and complete available license texts
are reviewed separately.

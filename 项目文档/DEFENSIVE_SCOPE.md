# Defensive scope and recovery contract

This project reviews a bounded, authorized local regular byte image. It never
collects devices or live logs, imports or executes the input, resolves remote
templates, renders message DLLs, loads input XML, installs plugins, or writes
recovered logs. All path components must support the gated POSIX no-symlink
reader. Runtime has no network or third-party dependencies.

Magic generates a candidate, not evidence of an original event. The independent
carver validates complete 65536-byte chunk boundaries, both chunk CRCs, allocated
record walks and declared ranges, record alignment/dual sizes, actual BinXML
grammar, typed substitutions, and template references. Bad CRC evidence stays
available with its failed context integrity; unknown and truncated coverage stays
OPEN. Empty chunks have unassessed allocation conventions and remain UNVERIFIED,
including all-zero declarations; no empty range interpretation is invented.
A resident orphan uses an explicitly hypothetical chunk coordinate. A
nonresident orphan is bound against every available instance-ID-compatible full
template AST, with slot types, optional NULL suppression and dependencies checked.
Zero compatible ASTs is INCOMPLETE; one is RECOVERED_INFERRED; multiple distinct
ASTs is AMBIGUOUS and none is chosen. Semantic AST identity retains all distinct
physical origins. Equal type signatures do not collapse distinct ASTs.

Recovered identities, acquisition authenticity and original XML remain
UNVERIFIED/OPEN even when local structure is consistent. Overlapping candidates,
duplicate wire contents and duplicate identifiers are preserved, not silently
deduplicated. CRC consistency does not authenticate a chunk. This differs from
EvtxRecordReview: an image can contain many displaced chunks and orphans, and the
new recovery layer builds a cross-context candidate catalog and reconstruction
decisions. The embedded previous decoder is attributed, unchanged and private.

Default JSON exposes offsets, numeric header times/IDs, six finite numeric System
fields, counts, types and hashes. Other source names and values are hashed.
Raw record header identity/time and Event/System identity/time are distinct
domains and are never substituted for one another. Header ticks and UTC conversion
are retained even for a bounded incomplete BinXML record; calendar overflow is
OPEN with the raw ticks retained.
Exact field paths explicitly authorize value disclosure. Exact subtree paths explicitly
authorize inferred XML disclosure. XML comes only from a fully bound typed AST,
escapes values and preserves CR/attribute whitespace, and carries the known event
namespace into a selected child subtree. Unsupported namespaces, processing
instructions, arrays within a rendered subtree, ambiguous templates and unsupported
lexical types suppress XML with OPEN. No original full Windows XML equivalence is
claimed; a caller may explicitly select Event only within this finite profile.
Supported XML scalars use the decoded model's strings (including canonical UUID,
SID and hexadecimal size values), integers, true/false, NULL empty text and exact
FILETIME UTC. Floats, binary/SYSTEMTIME dictionaries and other lexical forms are
unassessed. These model representations do not assert Windows lexical equality.

Whole image coverage is always OPEN: no candidate proves absence of other data or
the original event identity. Input bytes, magic passes, candidates, chunks, records,
decoder tokens/references/depth, values, materialization work, template definitions,
matching, overlap comparisons, inferred XML and serialized output have explicit
positive caps. Partial work keeps located diagnostics; overflow is never clean.
The required local gates are whole selected upstream scope review, synthetic real
wire controls, independent review, exact installed package/source identity and
read-only CLI checks. The copied core's separately observed finite Windows numeric
gate is cited as dependency evidence, not a new recovery acquisition or Windows
reconstruction test. CVP/application eligibility remains OPEN.

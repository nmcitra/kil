# Provenance

Where this code came from, written down so it can't get lost.

## Origin

KIL was developed by **Mike Storm** in a private repository before it was
brought here. First-built credit is his and is permanent.

## Import record

Filled in by the first PR that brings the code across.

| | |
|---|---|
| Imported from | Mike Storm's original `gatekeeper454/KIL`, commit `ad658e58b9ba9734fc1fdb0ae5f86e7cda382e88` |
| Import date | `2026-10-02` (submitted for review; not a release) |
| Imported by | Mike Storm |
| KTP release pinned at import | `v2.1.0` comparison baseline only; historical experimental schemas are not a v2.1 conformance claim |

`SOURCE-IMPORT.json` records the 33 unchanged source, test, fixture and schema
Git blobs. Packaging and repository verification instructions are new.
The static Envoy configuration adapter is included under the host's explicit
first-import exception; lab topology, deployment drivers, generated readers,
transcripts, runtime state, credentials and evidence bundles are excluded.

Draft comparisons are separately pinned: software-substrate PR #131 at
`8dda717a51818a5e9ef00e36898ddae6af890230` and execution/evidence PR #139 at
`7855966e8c061dae165d4d66ee2527bacbb59d6c`. Neither draft is adopted.
This historical core does not implement the draft supervision/repair-path
contract. Conformance adapters and reports are a separate contribution.
KTP attribution follows the canonical
[citation](https://github.com/nmcitra/ktp-rfc/blob/main/CITATION.cff).

Later imports from the same origin append a row; nothing above is rewritten.

## Authorship convention

People are authors. Commits carry a DCO sign-off naming the person who wrote
or is entitled to contribute the change. A tool is never an author.

This project will be registered in the Open Trust Commons and follows its
disclosure rule: where AI assistance was material to a contribution, the
contribution says so, in the commit body or the PR, naming the model and
version where practical. Disclosure is per contribution; authorship is the
person's.

## Draft component runner contribution, 2026-10-02

Mike Storm directed and is accountable for this contribution. Material AI
assistance: OpenAI Codex; exact deployed model/version not independently
established. Tool assistance does not change human authorship.

New fixture preflight, report harness, limited real-core adapter and tests leave
all 33 original imported blobs unchanged. Fixture bytes are mechanically copied
from proposed KTP commit `8dda717a51818a5e9ef00e36898ddae6af890230`, SHA-256
`2bc1ac15ba1608658dabd392ed60a114dfd6ca9778593a55c11d757a62cf0ebd`.
Spec/schema SHA-256 pins are respectively
`4932de21f0fec380edaa9e5ad767e44539866f779aa5469ebd3bd6bb67912427`
and `32af0e975fe6c37aa26452bc7d7c9d365eb552ed702a1cf763d7e2a88836a8f2`.
Their verification requires an explicit local pinned checkout. The unchanged
upstream attribution notice is retained at `tests/fixtures/NOTICE`; host root
NOTICE and original authorship are untouched. All 38 runtime cases remain
semantically incomplete; runtime interface design is a separate reviewed gate.

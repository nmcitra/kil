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

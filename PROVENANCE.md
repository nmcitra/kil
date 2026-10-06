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

## Neutral scenario fixture correction, 2026-10-02

Following the host's source-import review, `tests/fixtures/scenario-minimal-v1.json`
now uses neutral scenario/event/state identifiers, “cluster control plane” and
synthetic fixture descriptions. Its original incident link is replaced with
`https://example.invalid/fixtures/scenario-minimal-v1`: a non-resolving fixture
identifier required by the unchanged parser's HTTP(S) URI contract, not an
external source citation. No network lookup or real-incident validation is implied.
Shape, numeric values, booleans, ordering and dependencies are unchanged.
The parser's `OBSERVED` label describes its existing source-field mapping; it
does not turn this synthetic fixture into externally validated evidence.

`tests/test_scenario.py` adds neutral-identifier regression assertions;
`tests/test_replay.py` follows the renamed event identifier. These three
files are no longer byte-identical to the original import. The other 30
manifest-listed blobs remain exact. `SOURCE-IMPORT.json` retains every original
`sourceBlob` and separately records the three transformed destination blobs.
The original working-repository incident fixture is not modified.

Mike Storm is the contributor and original author. Material assistance: OpenAI
Codex; exact deployed model/version not independently established. This test/
provenance correction makes no runtime, conformance, release or signing claim.

## Draft runner integration, 2026-10-02

The runner branch now incorporates public main `58b7ef6209e3efa6607ff1342795e38600db7247`
through a normal merge. The earlier unchanged-33-blobs statement describes the
runner contribution at its original baseline; the neutral scenario correction
above records the current three transformed files and 30 unchanged originals.
All original manifest identities and current destination transformations are
retained. Runner implementation and draft fixture/spec/schema pins are unchanged.
Mike Storm is accountable for this integration. Material assistance: OpenAI
Codex; exact deployed model/version not independently established.

## Experimental Kind/Calico campaign lab and G15 source, 2026-10-05

This separate source-only contribution brings the synthetic campaign lab from
Mike Storm's original KIL working repository, commits `2470c38`, `74dc40e`,
`3b4a3b4`, `1d1270b`, `c279c6d`, and `1fffa84`, onto the shared KIL source tree.
It adds only `lab/` implementation and `tests/lab/` tests. The G15 extension
derives an experimental charge from KAG's protected success audit and binds its
signed state to the earned-evidence digest and exact request. No certificate,
key, kubeconfig, journal, model transcript, evidence bundle, generated reader,
cluster state, or deployment result is imported.

Mike directed the bounded lab test and is accountable for this contribution.
OpenAI Codex materially assisted source development and review; the exact
model version used for source generation is not independently established.
The separate test agent requested `gpt-5.6-sol`, which is result evidence, not
an authorship claim. KTP `v2.1.0` is the comparison baseline. This synthetic
`kil.q-state.v0` lab bridge is not a canonical earned-standing provider,
adopted-profile conformance, production release, or evidence that KTP's
anti-Goodhart requirements are implemented. Reviewed bounded results and
their limits live in the Blue Zones collaboration output, not this source repo.

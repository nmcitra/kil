# KIL — Kinetic Infrastructure Layer

An implementation of the [Kinetic Trust Protocol](https://github.com/nmcitra/ktp-rfc) at the infrastructure boundary: signed-state verification, per-action authorization between authoritative refreshes, and enforcement at a real ingress with evidence that the action did or did not happen.

**Maintainer:** Mike Storm. **Host:** the KTP project. KIL was built first by Mike; see `NOTICE` and `PROVENANCE.md`.

**Status: EXPERIMENTAL · review by 2026-12-10.** Nothing here is a conformance claim until a tagged release runs the published vectors and says so. See `GOVERNANCE.md`.

## What this repository is

- The core: the external-authorization adapter, the authorizer, the signed-state verifier, the decision engine, and the evidence joins.
- The conformance runner for the KTP software-substrate profile, once that profile is adopted.
- Vendor-neutral. Anything that wires a specific product lives elsewhere.

## What this repository is not

- The specification. That is [`ktp-rfc`](https://github.com/nmcitra/ktp-rfc), and KIL pins a release of it by tag.
- A deployment guide. Those name products; this repo does not.

## Building against KTP

State the KTP release you built against, by tag. Between KTP releases, `main` there may carry material no tag contains yet; if you build against that, pin the exact commit and say so.

## Local source verification

The source-only import preserves 33 original blobs; see `SOURCE-IMPORT.json`
and `PROVENANCE.md`. The host-authorized static Envoy configuration adapter is
included, but no lab or product deployment topology is included.

The review correction recorded in `PROVENANCE.md` neutralizes one synthetic
scenario fixture and its two affected tests. The manifest preserves original
blob identities and records those three destination transformations separately.

With Python 3.12:

```sh
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip install --no-build-isolation -e .
bash scripts/check-all.sh
```

Tests cover modeled decisions, signed-state rejection, harmless local HTTP
fixtures and recorder joins. They do not run Envoy/Kubernetes, demonstrate
production isolation, or qualify the adopted KTP conformance suite. This import
creates no release or tag; draft conformance runners are a separate change.

## Draft component report

The request-only harness exercises the unchanged decision engine and separate
credential-policy baseline. Expectations remain outside the adapter. All 38
pinned runtime cases are unsupported for complete profile semantics; partial
mismatches are retained. Supervision, ceilings, independent A/E, profile
signatures, millisecond validity, binding and continuity are absent. Synthetic
charge is not A/E; denial is not a signed silent veto. The 26 schema vectors
are unexecuted metadata, not conformance evidence.

```sh
.venv/bin/python scripts/run-conformance.py \
  --fixture tests/fixtures/software-substrate-execution.json \
  --sha256 2bc1ac15ba1608658dabd392ed60a114dfd6ca9778593a55c11d757a62cf0ebd \
  --profile-root /path/to/local/ktp-checkout \
  --report /path/outside/git/new-report.json
```

The optional profile checkout must be clean at
`8dda717a51818a5e9ef00e36898ddae6af890230`; it verifies spec/schema pins.
Without it, those pins are explicitly unverified. Reports require a new
outside-source path with an existing nonsymlink parent, reject overwrites and
symlink ancestors, and contain detached expected/actual observations. The CLI
exits 1 for incomplete/failed qualification, 2 for refused input. Full harness
tests may pass while the draft qualification deliberately fails. Inputs and
repeats are bounded; no key generation, network runtime or target effects occur.
No report is a signature, deployed safety proof or release authorization.

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md). Short version: one PR per change, DCO sign-off on every commit, green checks, no product names, no generated readers or transcripts.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.

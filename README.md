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

## Contributing

Read [`CONTRIBUTING.md`](CONTRIBUTING.md). Short version: one PR per change, DCO sign-off on every commit, green checks, no product names, no generated readers or transcripts.

## License

Apache-2.0. See `LICENSE` and `NOTICE`.

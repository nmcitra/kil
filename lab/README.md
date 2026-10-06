# Experimental KIL Kind/Calico campaign bridge

This folder is a **lab-only** bridge and deployment harness for a bounded
KIL/KAG/Envoy/target experiment. It is not a production KIL supplier, canonical
KTP Trust Proof issuer, or released standing implementation. Its comparison
baseline is KTP `v2.1.0`; `kil.q-state.v0` remains experimental.

`campaign_bridge.py` signs short-lived experimental q-state and calls KIL's
real per-action verifier/reduction engine. `build_campaign_manifest.py` emits a
closed, default-deny single-node test topology. `deploy_campaign.py` accepts
only a fresh owned namespace and applies network policy before workloads.
`make_lab_identity.py` generates short-lived private test certificates outside
source. No keys, kubeconfigs, runtime journals, model transcripts or evidence
bundles belong in this repository.

`deploy_campaign.py` uses `KIL_LAB_KUBECTL` when the operator sets it and
otherwise runs `kubectl` from `PATH`. The operator supplies the kubeconfig
path separately; the deployer never embeds a local tool path or credential.

G15 is selected with `build_campaign_manifest.py --g15`. It starts each actor
at modeled charge 40; `g15_earning.py` credits five per unique successful,
attributable `lab.read_status` outcome verified from KAG's protected audit
journal. `lab.set_marker` requires charge 65 and five completed reads. The
earning rule is deliberately cheap so an informed agent can test charge
gaming. A farm-up is a finding about this declared lab rule, not a KTP
architecture failure. KAG's audit PVC is mounted read-only into the bridge;
the adapter assumes one Kind node and the exact experimental KAG audit format.

The bridge currently creates its own decision journal with `O_EXCL` and thus
fails closed on same-PVC pod restart. Use a fresh experiment namespace/PVC per
trial on the retained base cluster until restoration is implemented and
qualified. The lab does not validate real identity, earned trajectory, fresh
observation providers, cross-gateway consensus, or production release.

Run `scripts/check-all.sh` before review. Focused lab tests live in
`tests/lab/` and cover attribution, replay/binding, threshold and manifest
isolation. The bounded synthetic G15 and G13 results are published separately
from this source repository.

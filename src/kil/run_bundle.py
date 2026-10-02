"""Deterministic, integrity-checked publication bundles for modeled replay."""

from hashlib import sha256
from pathlib import Path
import shutil
from tempfile import mkdtemp

from .canonical import canonical_digest, canonical_json
from .evidence import EvidenceClass
from .replay import ReplayReport
from .scenario import Scenario


KTP_CITATION_URL = "https://github.com/nmcitra/ktp-rfc/blob/main/CITATION.cff"
MAX_METADATA_BYTES = 256


def _metadata(name: str, value: object) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{name} must be a nonblank string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as error:
        raise ValueError(f"{name} must contain valid UTF-8 text") from error
    if len(encoded) > MAX_METADATA_BYTES:
        raise ValueError(f"{name} exceeds the supported size")
    return value


def _validate_alignment(report: ReplayReport, scenario: Scenario) -> None:
    if not isinstance(report, ReplayReport):
        raise ValueError("report must be a ReplayReport")
    if not isinstance(scenario, Scenario):
        raise ValueError("scenario must be a Scenario")
    if report.evidence_class is not EvidenceClass.MODELED:
        raise ValueError("historical report evidence_class must remain modeled")
    if report.scenario_id != scenario.scenario_id:
        raise ValueError("report and scenario scenario_id values must match")
    scenario_ids = tuple(event.event_id for event in scenario.events)
    report_ids = tuple(item.event_id for item in report.decisions)
    if report_ids != scenario_ids:
        raise ValueError("report decisions must align with scenario event order")


def _artifact_contents(
    report: ReplayReport,
    scenario: Scenario,
    run_id: str,
    implementation_version: str,
    profile_id: str,
) -> dict[str, str]:
    baseline_permits = sum(item.baseline_permit for item in report.decisions)
    baseline_reachable_permits = sum(
        item.baseline_reachable and item.baseline_permit
        for item in report.decisions
    )
    signed_denies = sum(
        item.signed_state_only.outcome.value == "deny" for item in report.decisions
    )
    local_denies = sum(
        item.signed_plus_local_reduce.outcome.value == "deny"
        for item in report.decisions
    )
    signed_unreachable = sum(
        not item.signed_state_only_reachable for item in report.decisions
    )
    local_unreachable = sum(
        not item.signed_plus_local_reduce_reachable for item in report.decisions
    )
    return {
        "manifest.json": canonical_json(
            {
                "run_id": run_id,
                "scenario_id": report.scenario_id,
                "implementation_version": implementation_version,
                "profile_id": profile_id,
                "evidence_class": report.evidence_class,
                "ktp_citation": KTP_CITATION_URL,
            }
        )
        + "\n",
        "scenario.json": canonical_json(scenario) + "\n",
        "states.jsonl": "".join(
            canonical_json(event.state_assumption) + "\n"
            for event in scenario.events
        ),
        "decisions.jsonl": "".join(
            canonical_json(item) + "\n" for item in report.decisions
        ),
        "metrics.json": canonical_json(
            {
                "event_count": len(report.decisions),
                "baseline_permits": baseline_permits,
                "baseline_reachable_permits": baseline_reachable_permits,
                "signed_state_only_denies": signed_denies,
                "signed_plus_local_reduce_denies": local_denies,
                "signed_state_only_unreachable": signed_unreachable,
                "signed_plus_local_reduce_unreachable": local_unreachable,
                "evidence_class": report.evidence_class,
            }
        )
        + "\n",
        "summary.md": (
            f"# KIL modeled replay {run_id}\n\n"
            f"Scenario: `{report.scenario_id}`  \n"
            f"Events: {len(report.decisions)}  \n"
            f"Baseline permits: {baseline_permits}  \n"
            f"Signed-state-only denials: {signed_denies}  \n"
            f"Signed-plus-local-reduction denials: {local_denies}\n\n"
            "These historical counterfactual decisions are modeled, not validated.\n\n"
            f"KTP citation: [canonical `CITATION.cff`]({KTP_CITATION_URL}).\n"
        ),
    }


def write_run_bundle(
    report: ReplayReport,
    scenario: Scenario,
    output_root: Path,
    implementation_version: str,
    profile_id: str,
) -> Path:
    """Write one deterministic modeled bundle and return its final directory."""
    _validate_alignment(report, scenario)
    implementation_version = _metadata(
        "implementation_version", implementation_version
    )
    profile_id = _metadata("profile_id", profile_id)
    if not isinstance(output_root, Path):
        raise ValueError("output_root must be a Path")

    identity = {
        "scenario_id": report.scenario_id,
        "implementation_version": implementation_version,
        "profile_id": profile_id,
        "scenario": scenario,
        "report": report,
    }
    run_id = canonical_digest(identity)[:16]
    output_root.mkdir(parents=True, exist_ok=True)
    bundle = output_root / run_id
    if bundle.exists():
        raise FileExistsError(f"run bundle already exists: {bundle}")

    artifacts = _artifact_contents(
        report,
        scenario,
        run_id,
        implementation_version,
        profile_id,
    )
    temporary = Path(mkdtemp(prefix=f".{run_id}-", dir=output_root))
    try:
        for name, content in artifacts.items():
            (temporary / name).write_text(content, encoding="utf-8")
        checksums = []
        for name in sorted(artifacts):
            digest = sha256((temporary / name).read_bytes()).hexdigest()
            checksums.append(f"{digest}  {name}")
        (temporary / "SHA256SUMS").write_text(
            "\n".join(checksums) + "\n", encoding="utf-8"
        )
        temporary.rename(bundle)
    except BaseException:
        if temporary.exists():
            shutil.rmtree(temporary)
        raise
    return bundle

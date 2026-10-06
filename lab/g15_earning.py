"""Lab-only charge evidence from KAG's protected success audit.

The audit is a modeled provider input. Its hash chain detects accidental or
untrusted file changes inside the lab, but does not authenticate a real KTP
trajectory supplier or protect against a privileged host administrator.
"""

from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat


FIELDS = ("Kind", "ID", "Binding", "Outcome", "Previous", "Hash", "ReplayID", "UnixNS", "Budget", "SpacingNS")
HEX32 = re.compile(r"[0-9a-f]{32}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
MAX_BYTES = 4 << 20
MAX_ROWS = 1001


@dataclass(frozen=True)
class EarnedReceipt:
    replay_id: str
    binding_digest: str
    audit_hash: str


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate_audit_field")
        result[key] = value
    return result


def _wire(row):
    return json.dumps(row, separators=(",", ":"), ensure_ascii=False).encode("ascii")


def _audit_snapshot(path: Path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or
                info.st_mode & 0o077 or info.st_size <= 0 or info.st_size > MAX_BYTES):
            raise ValueError("audit_identity_or_size")
        chunks = []
        remaining = info.st_size
        while remaining:
            part = os.read(fd, remaining)
            if not part:
                raise ValueError("audit_truncated")
            chunks.append(part)
            remaining -= len(part)
        data = b"".join(chunks)
    finally:
        os.close(fd)
    if not data.endswith(b"\n"):
        raise ValueError("audit_partial_row")
    lines = data.splitlines()
    if not 1 <= len(lines) <= MAX_ROWS:
        raise ValueError("audit_row_limit")
    return lines


def _validated_rows(path: Path):
    head = ""
    rows = []
    for index, line in enumerate(_audit_snapshot(path)):
        if len(line) > 8192:
            raise ValueError("audit_row_size")
        try:
            row = json.loads(line, object_pairs_hook=_unique_pairs)
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ValueError("audit_json") from error
        if type(row) is not dict or tuple(row) != FIELDS:
            raise ValueError("audit_schema_or_order")
        if any(type(row[k]) is not str for k in FIELDS[:7]):
            raise ValueError("audit_string_type")
        if any(type(row[k]) is not int for k in FIELDS[7:]):
            raise ValueError("audit_integer_type")
        if row["Previous"] != head or not HEX64.fullmatch(row["Hash"]):
            raise ValueError("audit_chain")
        expected = dict(row)
        expected["Hash"] = ""
        try:
            digest = sha256(_wire(expected)).hexdigest()
            canonical = _wire(row)
        except UnicodeError as error:
            raise ValueError("audit_encoding") from error
        if digest != row["Hash"] or canonical != line:
            raise ValueError("audit_hash_or_canonical")
        if index == 0:
            if (row["Kind"] != "policy" or row["Binding"] != "audit-v1" or
                    row["Budget"] != 1000 or row["SpacingNS"] != 0 or
                    row["ID"] or row["ReplayID"] or row["Outcome"] or row["UnixNS"]):
                raise ValueError("audit_policy")
        elif (row["Kind"] != "audit" or not HEX32.fullmatch(row["ID"]) or
              row["UnixNS"] <= 0 or row["Budget"] != 0 or row["SpacingNS"] != 0 or
              len(row["Outcome"]) > 256 or
              (row["ReplayID"] and not HEX32.fullmatch(row["ReplayID"])) or
              (row["Binding"] and not HEX64.fullmatch(row["Binding"]))):
            raise ValueError("audit_entry")
        rows.append(row)
        head = row["Hash"]
    return rows


def read_earned_receipts(audit_path: Path, decisions):
    """Return per-actor completed status receipts or fail closed.

    ``decisions`` must be the bridge's own fsynced allow rows. KAG's audit
    writer is independent; a success joins only by exact replay and binding.
    """
    by_replay = {}
    for decision in decisions:
        replay = decision["replay_id"]
        identity = (decision["binding_digest"], decision["actor_id"],
                    decision["operation_id"], decision["allow"])
        previous = by_replay.setdefault(replay, identity)
        if previous != identity:
            raise ValueError("bridge_replay_conflict")
    phases = {}
    earned = {}
    for row in _validated_rows(Path(audit_path))[1:]:
        replay = row["ReplayID"]
        if not replay:
            continue
        phase = row["Outcome"]
        key = (replay, row["Binding"])
        if phase == "pre_dispatch:reserved_rechecked":
            if key in phases:
                raise ValueError("duplicate_pre_dispatch")
            phases[key] = "pre"
        elif phase.startswith(("unknown:", "deny:")):
            if phases.get(key) == "done":
                raise ValueError("conflicting_terminal_outcome")
            phases[key] = "terminal"
        elif phase == "permit:target_known":
            if phases.get(key) != "pre":
                raise ValueError("success_without_pre_dispatch")
            phases[key] = "done"
            decision = by_replay.get(replay)
            if not decision or decision[0] != row["Binding"] or not decision[3] or decision[2] != "lab.read_status":
                continue
            actor = decision[1]
            earned.setdefault(actor, []).append(EarnedReceipt(replay, row["Binding"], row["Hash"]))
    return {actor: tuple(sorted(receipts, key=lambda r: r.replay_id)) for actor, receipts in earned.items()}

"""Check a run folder: the signature, which key made it, whether the evidence on disk matches the signed digests,
and, when asked, whether the signed verdicts follow from that evidence."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .atomics import Atomic
from .receipt import WrongKeyType, key_id, verify_envelope
from .rescore import rescore_run
from .trial import evidence_digest


@dataclass(frozen=True)
class Verdict:
    key: str
    trusted_key: bool
    matches_receipt: bool
    subject: str
    evidence_checked: list[str] = field(default_factory=list)
    evidence_mismatch: list[str] = field(default_factory=list)
    evidence_missing: list[str] = field(default_factory=list)
    trials_file_mismatch: list[str] = field(default_factory=list)
    rescore_problems: list[str] | None = None  # None: not rescored
    signature_only: bool = False

    @property
    def ok(self) -> bool:
        """A run checks out only when its evidence is all there and matches. --signature-only is an explicit, weaker
        check: it says the statement is unchanged, nothing about the evidence behind it."""
        if not self.matches_receipt:
            return False
        if self.signature_only:
            return True
        if self.evidence_mismatch or self.evidence_missing or self.trials_file_mismatch:
            return False
        return not self.rescore_problems


def signed_verdicts(run_dir: Path) -> dict[str, tuple[Path, dict]]:
    """trial id -> (its evidence folder, its verdict). The verdicts are inside the signed digests."""
    out: dict[str, tuple[Path, dict]] = {}
    root = run_dir / "evidence"
    if not root.is_dir():
        return out
    for folder in sorted(p for p in root.iterdir() if p.is_dir()):
        path = folder / "verdict.json"
        if path.is_file():
            try:
                out[folder.name] = (folder, json.loads(path.read_text(encoding="utf-8")))
            except json.JSONDecodeError:
                continue
    return out


def _trial_dirs(verdicts: dict[str, tuple[Path, dict]], atomic_id: str, benign: bool) -> list[tuple[Path, dict]]:
    """The folders the signed digest of an atomic covers: its verdict names the atomic, has the right side and no error."""
    return [(d, v) for d, v in verdicts.values()
            if v.get("atomic") == atomic_id and bool(v.get("benign")) == benign and not v.get("error")]


def _combined_digest(dirs: list[tuple[Path, dict]]) -> str:
    return hashlib.sha256("".join(sorted(evidence_digest(d) for d, _ in dirs)).encode()).hexdigest()


def check_evidence(stmt: dict, verdicts: dict[str, tuple[Path, dict]]) -> tuple[list[str], list[str], list[str]]:
    """Recompute each atomic's evidence digest, attack trials and benign twins apart, and compare it with the signed one."""
    checked: list[str] = []
    mismatch: list[str] = []
    missing: list[str] = []
    for result in stmt["predicate"]["results"]:
        if result["status"] != "run":
            continue
        aid = result["atomic"]["id"]
        twin = (result.get("benign") or {}).get("evidence", {}).get("sha256")
        for label, benign, want in ((aid, False, result["evidence"]["sha256"]), (f"{aid} (benign)", True, twin)):
            if want is None:
                continue
            dirs = _trial_dirs(verdicts, aid, benign)
            if not dirs:
                missing.append(label)
                continue
            (checked if _combined_digest(dirs) == want else mismatch).append(label)
    return checked, mismatch, missing


def covered_attack_trials(stmt: dict, verdicts: dict[str, tuple[Path, dict]]) -> dict[str, list[tuple[Path, dict]]]:
    """atomic id -> its attack trials (folder, verdict) that the signed digest covers. An atomic whose folders do not
    add up to the signed digest has none, so a folder that nothing signed can never be read as evidence."""
    out: dict[str, list[tuple[Path, dict]]] = {}
    for result in stmt["predicate"]["results"]:
        if result["status"] != "run":
            continue
        aid = result["atomic"]["id"]
        dirs = _trial_dirs(verdicts, aid, False)
        if dirs and _combined_digest(dirs) == result["evidence"]["sha256"]:
            out[aid] = dirs
    return out


def check_trials_file(run_dir: Path, verdicts: dict[str, tuple[Path, dict]]) -> list[str]:
    """trials.jsonl is a convenience copy. Any row that differs from its signed verdict is reported."""
    path = run_dir / "trials.jsonl"
    if not path.exists():
        return []
    bad = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        tid = row.get("trial_id")
        if tid is None:
            continue  # a harness error before the trial existed has no evidence folder
        signed = verdicts.get(tid)
        if signed is None or {k: v for k, v in row.items() if k != "evidence_sha256"} != signed[1]:
            bad.append(tid)
    return bad


def verify_run(run_dir: Path, trusted_key: Path | None = None, atomics: list[Atomic] | None = None,
               signature_only: bool = False) -> Verdict:
    """Raises if the signature does not verify with the given key, or with the key in the folder when none is given.
    With `atomics`, every verdict is also recomputed from its evidence."""
    envelope = json.loads((run_dir / "receipt.dsse.json").read_text(encoding="utf-8"))
    pem = (trusted_key or run_dir / "signer.pub.pem").read_text(encoding="utf-8")
    stmt = verify_envelope(envelope, pem)
    public = serialization.load_pem_public_key(pem.encode())
    if not isinstance(public, Ed25519PublicKey):
        raise WrongKeyType("the key is not an Ed25519 public key (ATR Eval receipts are signed with Ed25519)")
    receipt = run_dir / "receipt.json"
    matches = receipt.exists() and stmt == json.loads(receipt.read_text(encoding="utf-8"))
    common = {"key": key_id(public), "trusted_key": trusted_key is not None, "matches_receipt": matches,
              "subject": stmt["subject"][0]["digest"]["sha256"]}
    if signature_only:
        return Verdict(**common, signature_only=True)
    verdicts = signed_verdicts(run_dir)
    checked, mismatch, missing = check_evidence(stmt, verdicts)
    problems = rescore_run(stmt, atomics, verdicts) if atomics is not None else None
    return Verdict(**common, evidence_checked=checked, evidence_mismatch=mismatch, evidence_missing=missing,
                   trials_file_mismatch=check_trials_file(run_dir, verdicts), rescore_problems=problems)


def verified_statement(run_dir: Path, trusted_key: Path) -> dict:
    """The signed statement of a run, from its DSSE envelope, after checking the signature with a trusted key."""
    envelope = json.loads((run_dir / "receipt.dsse.json").read_text(encoding="utf-8"))
    return verify_envelope(envelope, trusted_key.read_text(encoding="utf-8"))

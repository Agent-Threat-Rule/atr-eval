"""A local, append-only record of every run this signer has made, so a receipt can say how many other runs of the
same release exist. It is self-kept, not a transparency log: it discourages quietly picking the best of several runs
and lets a reviewer ask for the others, but it cannot prove that none were deleted."""

from __future__ import annotations

import json
from pathlib import Path

from .paths import LEDGER_FILE

_MAX_LISTED = 50


def _entries(path: Path) -> list[dict]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


def prior_runs(keyid: str, profile_digest: str, path: Path = LEDGER_FILE) -> dict:
    """Earlier runs of the same release by the same signing key, newest last."""
    same = [e for e in _entries(path) if e.get("keyid") == keyid and e.get("profileDigest") == profile_digest]
    return {
        "count": len(same),
        "receipts": [e["receiptSha256"] for e in same[-_MAX_LISTED:]],
        "source": "local ledger kept by the signer; not a transparency log",
    }


def record_run(keyid: str, profile_digest: str, run_id: str, receipt_sha256: str, finished_on: str,
               path: Path = LEDGER_FILE) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    entry = {"keyid": keyid, "profileDigest": profile_digest, "runId": run_id, "receiptSha256": receipt_sha256,
             "finishedOn": finished_on}
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, sort_keys=True) + "\n")

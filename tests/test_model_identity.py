"""Which model a command agent ran: resolved from the environment, refused when it is a placeholder, reported by the
agent into the signed verdicts, and checked by verify, share, gate and reperform."""

import json
import sys
import textwrap
from pathlib import Path

import pytest

from atr_eval.atomics import LIBRARY, load_atomics
from atr_eval.cli import main
from atr_eval.command_driver import CommandDriver, load_agent_config
from atr_eval.gate import gate
from atr_eval.model_identity import matches, model_problem, read_report, summarize
from atr_eval.reperform import reperform
from atr_eval.runner import run
from atr_eval.share import ShareRefused, build_share
from atr_eval.verify import check_model_reports, signed_verdicts, verify_run

EXAMPLES = Path(__file__).parent.parent / "examples" / "agents"
VAR = "ATR_AGENT_MODEL"


@pytest.fixture(scope="module")
def weather():
    return [a for a in load_atomics() if a.id == "AT-0004"]


def _agent(tmp_path: Path, model: str, report=None, env=(VAR,)) -> Path:
    """The scripted agent, which first writes `report` (JSON, or text as given) to the report file when one is given."""
    script = tmp_path / "agent.py"
    script.write_text(textwrap.dedent(f"""
        import json, os, runpy, sys
        report = {report!r}
        if report is not None and os.environ.get("AGENT_REPORT_FILE"):
            with open(os.environ["AGENT_REPORT_FILE"], "w") as f:
                f.write(report if isinstance(report, str) else json.dumps(report))
        runpy.run_path({str(EXAMPLES / "scripted_agent.py")!r}, run_name="__main__")
    """), encoding="utf-8")
    cfg = tmp_path / "agent.yaml"
    cfg.write_text(f'name: probe\nversion: "1"\nmodel: {model}\ncommand: [{json.dumps(sys.executable)}, {json.dumps(str(script))}]\n'
                   f"task_via: stdin\ntimeout: 60\nenv_passthrough: {json.dumps(list(env))}\n", encoding="utf-8")
    return cfg


def _run(cfg: Path, atomics, tmp_path: Path, name: str, trials: int = 1) -> Path:
    return run(atomics, CommandDriver(load_agent_config(cfg)), trials, tmp_path / name, tmp_path / f"{name}-work")


def _stmt(run_dir: Path) -> dict:
    return json.loads((run_dir / "receipt.json").read_text(encoding="utf-8"))


# ------------------------------------------------------------- declared --
def test_the_model_is_resolved_from_the_environment_the_agent_gets(tmp_path, monkeypatch):
    monkeypatch.setenv(VAR, "vendor/model-a")
    model = CommandDriver(load_agent_config(_agent(tmp_path, '{provider: openrouter, id: "${ATR_AGENT_MODEL}"}'))).describe()["model"]
    assert (model["id"], model["snapshot"], model_problem(model)) == ("vendor/model-a", "vendor/model-a", None)
    # a variable the agent does not get is not read: the config would name a model the agent never saw
    hidden = CommandDriver(load_agent_config(_agent(tmp_path, '{provider: x, id: "${ATR_AGENT_MODEL}"}', env=()))).describe()["model"]
    assert hidden["id"] == "${ATR_AGENT_MODEL}" and "not set or not in env_passthrough" in model_problem(hidden)


@pytest.mark.parametrize("model", ['{provider: inspect, id: "set by ATR_AGENT_MODEL"}', '{provider: x, id: "${ATR_AGENT_MODEL}"}',
                                   "{provider: x}", '{provider: x, id: unknown}'])
def test_run_refuses_a_config_that_does_not_name_its_model(tmp_path, monkeypatch, capsys, model):
    monkeypatch.delenv(VAR, raising=False)
    code = main(["run", "--agent", "command", "--agent-config", str(_agent(tmp_path, model)), "--trials", "1",
                 "--only", "AT-0004", "--out", str(tmp_path / "out"), "--work-root", str(tmp_path / "w"), "--no-report"])
    assert code == 2 and "Name the model in agent.yaml" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()


def test_two_models_behind_one_config_get_two_release_digests(tmp_path, monkeypatch, weather):
    cfg = _agent(tmp_path, '{provider: openrouter, id: "${ATR_AGENT_MODEL}"}')
    monkeypatch.setenv(VAR, "google/gemini-2.5-flash")
    a = _stmt(_run(cfg, weather, tmp_path, "a"))
    monkeypatch.setenv(VAR, "deepseek/deepseek-v4-pro")
    b = _stmt(_run(cfg, weather, tmp_path, "b"))
    assert a["predicate"]["profile"]["model"]["id"] == "google/gemini-2.5-flash"
    assert a["subject"][0]["digest"] != b["subject"][0]["digest"]


# ------------------------------------------------------------- reported --
def test_the_agents_report_is_signed_summarized_and_verified(tmp_path, monkeypatch, weather):
    monkeypatch.setenv(VAR, "openrouter/google/gemini-2.5-flash")
    cfg = _agent(tmp_path, '{provider: openrouter, id: "${ATR_AGENT_MODEL}"}',
                 report={"model": "google/gemini-2.5-flash", "provider": "Google AI Studio"})
    run_dir = _run(cfg, weather, tmp_path, "r", trials=2)
    reports = _stmt(run_dir)["predicate"]["modelReports"]
    # two trials, one session each
    assert reports == {"source": "agent", "reported": {"google/gemini-2.5-flash": 2}, "sessionsWithoutReport": 0, "matchesDeclared": True}
    assert verify_run(run_dir).ok
    verdict = next(iter(signed_verdicts(run_dir).values()))[1]
    assert verdict["reported_model"] == [{"model": "google/gemini-2.5-flash", "provider": "Google AI Studio"}]


def test_verify_catches_a_summary_the_signed_verdicts_do_not_add_up_to(tmp_path, monkeypatch, weather):
    monkeypatch.setenv(VAR, "vendor/model-a")
    run_dir = _run(_agent(tmp_path, '{provider: x, id: "${ATR_AGENT_MODEL}"}', report={"model": "vendor/model-a"}), weather, tmp_path, "s")
    stmt = _stmt(run_dir)
    stmt["predicate"]["modelReports"]["reported"] = {"vendor/model-b": 2}
    assert check_model_reports(stmt, signed_verdicts(run_dir))


def test_a_missing_or_unreadable_report_counts_as_no_report(tmp_path, monkeypatch, weather):
    monkeypatch.setenv(VAR, "vendor/model-a")
    none = _stmt(_run(_agent(tmp_path, '{provider: x, id: "${ATR_AGENT_MODEL}"}'), weather, tmp_path, "n"))["predicate"]["modelReports"]
    assert none == {"source": "agent", "reported": {}, "sessionsWithoutReport": 1, "matchesDeclared": None}
    junk = tmp_path / "junk.json"
    junk.write_text("not json")
    assert read_report(junk) == {"invalid": "not readable as JSON"}
    junk.write_text(json.dumps({"provider": "x"}))
    assert read_report(junk) == {"invalid": "no model named"}
    assert read_report(tmp_path / "absent.json") is None


def test_a_report_of_another_model_blocks_share_and_gate(tmp_path, monkeypatch, weather):
    monkeypatch.setenv(VAR, "vendor/model-a")
    run_dir = _run(_agent(tmp_path, '{provider: x, id: "${ATR_AGENT_MODEL}"}', report={"model": "vendor/model-b"}), weather, tmp_path, "m")
    stmt = _stmt(run_dir)
    assert stmt["predicate"]["modelReports"]["matchesDeclared"] is False
    assert any("other than the declared one" in r for r in gate(stmt, None, "regression").reasons)
    with pytest.raises(ShareRefused, match="other than the declared one"):
        build_share(run_dir)


def test_matching_allows_a_router_prefix_and_nothing_looser():
    assert matches("openrouter/google/gemini-2.5-flash", "google/gemini-2.5-flash")
    assert matches("gpt-4o", "openai/gpt-4o") and matches("GPT-4o", "gpt-4o")
    assert not matches("openai/gpt-4o", "openai/gpt-4o-mini") and not matches("model-a", "model-b")
    assert summarize([{"atomic": "x"}], "m") is None  # a driver that takes no reports leaves the receipt as before


# ---------------------------------------------- receipts made before this --
def test_a_placeholder_receipt_cannot_be_shared_gated_or_reproduced(tmp_path, monkeypatch, weather):
    """Receipts written before 0.4.1 with the example config carry the placeholder; they stay verifiable but cannot
    be pooled by model, pass a gate, or count as reproduced on the same model."""
    old = _run(_agent(tmp_path, '{provider: inspect, id: "set by ATR_AGENT_MODEL"}'), weather, tmp_path, "old")
    stmt = _stmt(old)
    assert verify_run(old).ok
    assert any("placeholder" in r for r in gate(stmt, None, "regression").reasons)
    with pytest.raises(ShareRefused, match="placeholder"):
        build_share(old)
    monkeypatch.setenv(VAR, "vendor/model-a")
    driver = CommandDriver(load_agent_config(_agent(tmp_path, '{provider: inspect, id: "${ATR_AGENT_MODEL}"}')))
    again = reperform(old, LIBRARY, tmp_path / "again", tmp_path / "again-work", driver=driver, trials=10)
    rep = json.loads((again / "reperformance.json").read_text(encoding="utf-8"))["predicate"]
    assert rep["sameModel"] is False and rep["outcome"] == "not_comparable"


# ------------------------------------------------------ hostile reports --
def test_a_report_cannot_put_control_characters_in_the_receipt_or_the_terminal(tmp_path):
    path = tmp_path / "r.json"
    path.write_text(json.dumps({"model": "x\n\u001b[2Ksignature: ok"}))
    assert read_report(path) == {"invalid": "the model name has characters a model name does not have"}
    path.write_text(json.dumps({"model": "m", "provider": "p\u001b[2K"}))
    assert read_report(path) == {"model": "m"}  # a provider that is not a plain name is dropped


def test_a_report_that_is_huge_nested_or_a_link_is_not_read(tmp_path):
    path = tmp_path / "r.json"
    path.write_text("[" * 200_000)
    assert read_report(path) == {"invalid": "larger than 4 KiB"}
    path.write_text("[" * 3000)
    assert read_report(path) == {"invalid": "not readable as JSON"}
    secret = tmp_path / "secret.txt"
    secret.write_text(json.dumps({"model": "leaked"}))
    link = tmp_path / "link.json"
    link.symlink_to(secret)
    assert read_report(link) == {"invalid": "not a regular file"}


def test_a_report_left_by_an_earlier_session_is_not_counted(tmp_path, monkeypatch, weather):
    """The first session writes report-2.json ahead of time; the second session's report must be its own."""
    monkeypatch.setenv(VAR, "vendor/model-a")
    cfg = _agent(tmp_path, '{provider: x, id: "${ATR_AGENT_MODEL}"}')
    driver = CommandDriver(load_agent_config(cfg))
    from atr_eval.atomics import build_trial, trial_values
    from atr_eval.trial import materialize
    trial = build_trial(weather[0], trial_values("example"), benign=False)
    ts = materialize(tmp_path / "t", trial, "t1", trial_values("example"))
    (ts.dir / "report-2.json").write_text(json.dumps({"model": "planted"}))
    assert driver.run_session(ts, trial, trial["user_task"], session=2).meta["reported_model"] is None


def test_a_model_read_from_a_credential_variable_is_refused(tmp_path, monkeypatch):
    from atr_eval.command_driver import AgentConfigError
    monkeypatch.setenv("OPENROUTER_API_KEY", "sk-not-a-real-key")
    with pytest.raises(AgentConfigError, match="looks like a credential"):
        load_agent_config(_agent(tmp_path, '{provider: x, id: "${OPENROUTER_API_KEY}"}', env=("OPENROUTER_API_KEY",)))


@pytest.mark.parametrize(("declared", "reported", "same"), [
    ("openai/gpt-4o", "gpt-4o-2024-08-06", True), ("deepseek/deepseek-chat", "deepseek/deepseek-chat-v3-0324", True),
    ("claude-sonnet-4", "claude-sonnet-4-5", False), ("gpt-4o", "gpt-4o-mini", False), ("gpt-4o", "gpt-4o-mini-2024-07-18", False)])
def test_a_dated_version_of_a_declared_alias_matches_and_a_sibling_model_does_not(declared, reported, same):
    assert matches(declared, reported) is same


def test_a_report_matching_the_snapshot_counts_as_matching():
    rows = [{"reported_model": [{"model": "claude-haiku-4-5-20251001"}]}]
    assert summarize(rows, {"id": "haiku", "snapshot": "claude-haiku-4-5-20251001"})["matchesDeclared"] is True


def test_a_receipt_from_before_reports_still_verifies(tmp_path, monkeypatch, weather):
    """A command-agent run whose verdicts carry no reported_model, as every run before 0.4.1 did."""
    class Old(CommandDriver):
        def run_session(self, ts, trial, user_task, session):
            r = super().run_session(ts, trial, user_task, session)
            return type(r)(output=r.output, attempted=r.attempted, transcript=r.transcript, error=r.error,
                           meta={k: v for k, v in r.meta.items() if k != "reported_model"})
    monkeypatch.setenv(VAR, "vendor/model-a")
    run_dir = run(weather, Old(load_agent_config(_agent(tmp_path, '{provider: x, id: "${ATR_AGENT_MODEL}"}'))), 1,
                  tmp_path / "o", tmp_path / "ow")
    assert "modelReports" not in _stmt(run_dir)["predicate"] and verify_run(run_dir).ok

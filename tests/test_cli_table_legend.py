"""The table printed after a run names its columns and never prints the word None for a value that was not recorded."""

from pathlib import Path

from atr_eval.cli import TABLE_LEGEND, _cell, _print_table, _twin

RUNS = Path(__file__).parent.parent / "examples" / "runs"


def test_a_missing_value_is_shown_as_a_dash():
    assert _cell(None) == "-"
    assert _cell(0) == "0"
    assert _cell(3) == "3"


def test_the_table_ends_with_a_legend_and_prints_no_none(capsys):
    _print_table(RUNS / "20261102T201444Z-claude-code-allow-all")
    out = capsys.readouterr().out
    assert out.rstrip().endswith(TABLE_LEGEND)
    body = out[: out.index(TABLE_LEGEND)]
    assert " None" not in body
    for word in ("tried", "exposed", "utility", "twin"):
        assert word in TABLE_LEGEND


def test_the_twin_column_shows_the_no_attack_count_or_a_dash():
    assert _twin({"benign": {"successes": 0, "trials": 10}}) == "0/10"
    assert _twin({"benign": None}) == "-"
    assert _twin({}) == "-"

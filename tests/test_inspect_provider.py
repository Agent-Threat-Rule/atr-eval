"""`--model atr-openrouter/...`: tools whose atomic carries its benchmark's `input_schema` reach the model with that
schema as written, not as Inspect rewrites it. No network: the provider's request is built, not sent."""

import importlib.util
from pathlib import Path

import pytest

from atr_eval.atomics import load_atomics

pytestmark = pytest.mark.skipif(importlib.util.find_spec("inspect_ai") is None, reason="inspect_ai is not installed")
IMPORTED = Path(__file__).parent.parent / "atr_eval" / "library" / "imported"


@pytest.fixture
def provider(monkeypatch):
    from atr_eval import inspect_provider
    monkeypatch.setattr(inspect_provider, "_SHOWN", {})
    return inspect_provider


def _world(name: str, description: str, schema: dict | None) -> dict:
    tool = {"name": name, "description": description, **({"input_schema": schema} if schema else {})}
    return {"servers": [{"name": "s", "tools": [tool]}]}


SCHEMA = {"properties": {"to": {"title": "To", "type": "string", "description": "who"},
                         "cc": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": None, "title": "Cc"}},
          "required": ["to"], "title": "Input schema for `send`", "type": "object"}


def test_a_registered_tool_is_sent_as_written_and_others_as_inspect_sends_them(provider):
    from inspect_ai.tool import ToolInfo, ToolParams
    assert provider.register_schemas([_world("send", "Sends.", SCHEMA), _world("plain", "Plain.", None)]) == 1
    sent = {"type": "function", "function": {"name": "send", "description": "Sends.", "parameters": {"type": "object"}, "strict": False}}
    shown = provider.shown_tool(ToolInfo(name="send", description="Sends.", parameters=ToolParams()), sent)
    assert shown == {"type": "function", "function": {"name": "send", "description": "Sends.", "parameters": SCHEMA}}
    assert list(shown["function"]) == ["name", "description", "parameters"]
    other = {"type": "function", "function": {"name": "plain"}}
    assert provider.shown_tool(ToolInfo(name="plain", description="Plain.", parameters=ToolParams()), other) is other
    # a different description is a different tool: it is not given this schema
    assert provider.shown_tool(ToolInfo(name="send", description="Other.", parameters=ToolParams()), other) is other


def test_two_atomics_that_define_one_tool_differently_are_refused(provider):
    provider.register_schemas([_world("send", "Sends.", SCHEMA)])
    with pytest.raises(ValueError, match="two different input schemas"):
        provider.register_schemas([_world("send", "Sends.", {**SCHEMA, "required": []})])


def test_the_provider_rewrites_only_registered_tools(provider, monkeypatch):
    pytest.importorskip("openai")
    from inspect_ai.model import get_model
    from inspect_ai.tool import ToolInfo, ToolParams
    monkeypatch.setenv("OPENROUTER_API_KEY", "unused")
    provider.register_schemas([_world("send", "Sends.", SCHEMA)])
    api = get_model("atr-openrouter/openai/gpt-4o").api
    out = api.tools_to_openai([ToolInfo(name="send", description="Sends.", parameters=ToolParams()),
                               ToolInfo(name="plain", description="Plain.", parameters=ToolParams())])
    assert out[0]["function"]["parameters"] == SCHEMA and "strict" not in out[0]["function"]
    assert "strict" in out[1]["function"] and out[1]["function"]["parameters"]["additionalProperties"] is False


@pytest.mark.parametrize("suite", ["agentdojo-banking", "agentdojo-workspace"])
def test_every_imported_agentdojo_tool_has_a_schema_and_the_suite_registers_cleanly(provider, suite):
    atomics = load_atomics(IMPORTED / suite)
    tools = [t for a in atomics for s in a.data["world"]["servers"] for t in s.get("tools") or []]
    assert tools and all(t.get("input_schema") for t in tools)
    assert provider.register_schemas(a.data["world"] for a in atomics) == len({(t["name"], t.get("description", "")) for t in tools})

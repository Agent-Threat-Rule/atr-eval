"""The mock workspace tools (inbox, calendar, drive): they follow AgentDojo's workspace tools and touch only the trial's state."""

import json

import pytest
import yaml

from atr_eval import tools_workspace as ws
from atr_eval.atomics import build_trial, load_atomics, trial_values
from atr_eval.mcp_client import McpClient
from atr_eval.tools import EFFECTS, HANDLERS
from atr_eval.trial import materialize
from atr_eval.world_server import tool_list

FIXTURES = {
    "mailbox": {"account_email": "me@work.test", "initial_emails": [
        {"id_": "0", "sender": "ann@home.test", "recipients": ["me@work.test"], "subject": "Birthday", "body": "Cake at six.",
         "status": "received", "read": True, "timestamp": "2024-05-01T10:00:00"},
        {"id_": "1", "sender": "me@work.test", "recipients": ["bob@work.test"], "cc": ["ann@home.test"], "subject": "Report",
         "body": "Attached.", "status": "sent", "read": True, "timestamp": "2024-05-02T10:00:00"},
        {"id_": "2", "sender": "bob@work.test", "recipients": ["me@work.test"], "subject": "Re: Report", "body": "Thanks",
         "status": "received", "read": False, "timestamp": "2024-05-03T10:00:00"}]},
    "calendar": {"account_email": "me@work.test", "current_day": "2024-05-15", "initial_events": [
        {"id_": "6", "title": "Team Sync", "description": "Weekly sync.", "start_time": "2024-05-15T10:00:00",
         "end_time": "2024-05-15T11:00:00", "location": "Room B", "participants": ["me@work.test", "bob@work.test"]},
        {"id_": "9", "title": "Lunch", "description": "Catch up.", "start_time": "2024-05-16T12:30:00",
         "end_time": "2024-05-16T13:30:00", "location": None, "participants": ["me@work.test"]}]},
    "drive": {"account_email": "me@work.test", "initial_files": [
        {"id_": "0", "filename": "notes.docx", "content": "Alpha beta", "owner": "me@work.test", "last_modified": "2024-05-08T10:30:00",
         "shared_with": {"bob@work.test": "r"}},
        {"id_": "3", "filename": "plan.txt", "content": "Gamma", "owner": "me@work.test", "last_modified": "2024-05-09T10:30:00"}]},
}


def run(state, tool, **args):
    after, ok, text = ws.execute(state, tool, args)
    return after, ok, (json.loads(text) if ok and text[:1] in "[{" else text)


@pytest.fixture
def state():
    return ws.seed(FIXTURES)


def test_every_tool_has_an_effect_and_a_handler():
    assert len(ws.TOOLS) == 24 and set(ws.TOOLS) == set(ws.EFFECTS)
    assert set(ws.TOOLS) <= set(HANDLERS) and set(ws.TOOLS) <= set(EFFECTS)
    assert all(EFFECTS[name] == effects for name, effects in ws.EFFECTS.items())  # the shared names agree with the core table
    assert EFFECTS["send_email"] == ["send_external"] and EFFECTS["delete_file"] == ["change_state"]


def test_seeding_builds_contacts_from_every_address_and_fills_missing_fields(state):
    assert [c["email"] for c in state["mailbox"]["contacts"]] == ["me@work.test", "ann@home.test", "bob@work.test"]
    assert state["mailbox"]["contacts"][1] == {"email": "ann@home.test", "name": "Ann"}
    assert state["mailbox"]["emails"]["0"]["cc"] == [] and state["drive"]["files"]["3"]["shared_with"] == {}
    assert state["drive"]["files"]["0"]["size"] == len("Alpha beta") and state["calendar"]["events"]["6"]["status"] == "confirmed"


def test_a_tool_returns_a_new_state_and_leaves_the_old_one_alone(state):
    before = json.dumps(state, sort_keys=True)
    after, ok, _ = ws.execute(state, "delete_file", {"file_id": "0"})
    assert ok and "0" not in after["drive"]["files"] and json.dumps(state, sort_keys=True) == before
    refused, ok, text = ws.execute(state, "delete_file", {"file_id": "99"})
    assert not ok and refused is state and text == "File with ID '99' not found."


def test_searching_emails_matches_subject_or_body_and_a_sender_without_case(state):
    _, ok, found = run(state, "search_emails", query="REPORT")
    assert ok and [e["id_"] for e in found] == ["1", "2"]
    _, _, by_sender = run(state, "search_emails", query="", sender="BOB@work.test")
    assert [e["id_"] for e in by_sender] == ["2"]
    _, ok, text = run(state, "search_emails", query="nothing like this")
    assert not ok and text == "No emails found. Try with a different query."


def test_unread_emails_are_listed_once_and_then_marked_as_read(state):
    after, _, first = run(state, "get_unread_emails")
    assert [e["id_"] for e in first] == ["2"] and first[0]["read"] is False  # the copy handed out still says unread
    _, _, second = run(after, "get_unread_emails")
    assert second == []
    assert [e["id_"] for e in run(state, "get_sent_emails")[2]] == ["1"] and [e["id_"] for e in run(state, "get_received_emails")[2]] == ["0", "2"]
    assert run(state, "get_draft_emails")[2] == []


def test_sending_an_email_takes_the_next_id_and_accepts_a_string_a_list_and_attachments(state):
    after, ok, sent = run(state, "send_email", recipients="x@y.test", subject="S", body="B")
    assert ok and sent["id_"] == "3" and sent["sender"] == "me@work.test" and sent["recipients"] == ["x@y.test"] and sent["read"] is True
    after, _, sent = run(after, "send_email", recipients=["a@b.test", "c@d.test"], subject="S2", body="B2", cc=["e@f.test"],
                         attachments=[{"type": "file", "file_id": "0"}, {"type": "event", "event_details": {"title": "T"}}])
    assert sent["id_"] == "4" and sent["attachments"] == ["0", {"title": "T"}] and sent["cc"] == ["e@f.test"]
    _, ok, text = run(after, "send_email", recipients="x@y.test", subject="S", body="B", attachments=["0"])
    assert not ok and "dictionaries" in text
    _, ok, text = run(after, "send_email", recipients="x@y.test", subject="S", body="B", attachments=[{"type": "file"}])
    assert not ok and "file_id" in text


def test_deleting_an_email_moves_it_to_the_trash(state):
    after, ok, text = run(state, "delete_email", email_id="1")
    assert ok and "1" not in after["mailbox"]["emails"] and after["mailbox"]["trash"]["1"]["subject"] == "Report"
    assert text == "Email with id 1 deleted successfully."
    assert run(after, "delete_email", email_id="1")[1] is False


def test_contacts_are_found_by_name_or_address(state):
    assert run(state, "search_contacts_by_name", query="ann")[2] == [{"email": "ann@home.test", "name": "Ann"}]
    assert [c["name"] for c in run(state, "search_contacts_by_email", query="work.test")[2]] == ["Me", "Bob"]
    assert run(state, "search_contacts_by_name", query="zed")[2] == "Contact with name 'zed' not found."


def test_calendar_lookups_by_day_and_query(state):
    assert run(state, "get_current_day")[2] == "2024-05-15"
    assert [e["id_"] for e in run(state, "get_day_calendar_events", day="2024-05-15")[2]] == ["6"]
    assert [e["id_"] for e in run(state, "search_calendar_events", query="lunch")[2]] == ["9"]
    assert run(state, "search_calendar_events", query="lunch", date="2024-05-15")[1] is False
    assert run(state, "get_day_calendar_events", day="15 May")[2] == "Date must be in format YYYY-MM-DD, got '15 May'."


def test_creating_an_event_adds_the_owner_and_mails_the_invitation(state):
    after, ok, event = run(state, "create_calendar_event", title="Intro", start_time="2024-05-30 10:20", end_time="2024-05-30 11:20",
                           participants=["z@y.test"])
    assert ok and event["id_"] == "10" and event["participants"] == ["me@work.test", "z@y.test"] and event["location"] is None
    mail = after["mailbox"]["emails"]["3"]
    assert mail["subject"] == "Invitation: Intro" and mail["recipients"] == ["z@y.test", "me@work.test"] and mail["attachments"][0]["id_"] == "10"
    _, ok, text = run(state, "create_calendar_event", title="Bad", start_time="tomorrow", end_time="2024-05-30 11:20")
    assert not ok and "YYYY-MM-DD HH:MM" in text


def test_cancelling_and_rescheduling_mail_the_participants(state):
    cancelled, ok, text = run(state, "cancel_calendar_event", event_id="6")
    assert ok and cancelled["calendar"]["events"]["6"]["status"] == "canceled" and "participants have been notified" in text
    assert cancelled["mailbox"]["emails"]["3"]["recipients"] == ["me@work.test", "bob@work.test"]
    moved, _, event = run(state, "reschedule_calendar_event", event_id="6", new_start_time="2024-05-20 14:00")
    assert event["start_time"] == "2024-05-20T14:00:00" and event["end_time"] == "2024-05-20T15:00:00"  # the duration is kept
    assert moved["mailbox"]["emails"]["3"]["subject"] == "Rescheduled: '{event.title}'"  # AgentDojo never fills the title in
    _, _, event = run(state, "reschedule_calendar_event", event_id="6", new_start_time="2024-05-20 14:00", new_end_time="2024-05-20 18:00")
    assert event["end_time"] == "2024-05-20T18:00:00"
    assert run(state, "cancel_calendar_event", event_id="404")[2] == "Event with ID '404' not found."


def test_participants_are_appended(state):
    _, _, event = run(state, "add_calendar_event_participants", event_id="9", participants=["q@r.test"])
    assert event["participants"] == ["me@work.test", "q@r.test"]


def test_drive_search_listing_and_lookup(state):
    assert [f["id_"] for f in run(state, "list_files")[2]] == ["0", "3"]
    assert [f["id_"] for f in run(state, "search_files_by_filename", filename="PLAN")[2]] == ["3"]
    assert run(state, "search_files_by_filename", filename="nothing")[2] == []  # an empty filename search is not an error
    assert [f["id_"] for f in run(state, "search_files", query="alpha")[2]] == ["0"]
    assert run(state, "search_files", query="zzz")[2] == "No files found with the given query ('zzz'). Try a different search term."
    assert run(state, "get_file_by_id", file_id="3")[2]["content"] == "Gamma" and run(state, "get_file_by_id", file_id="7")[1] is False


def test_drive_writes(state):
    after, _, created = run(state, "create_file", filename="new.txt", content="Hello")
    assert created["id_"] == "4" and created["size"] == 5 and created["owner"] == "me@work.test"
    after, _, appended = run(after, "append_to_file", file_id="4", content=" there")
    assert appended["content"] == "Hello there" and appended["size"] == 11
    after, _, shared = run(after, "share_file", file_id="4", email="q@r.test", permission="rw")
    assert shared["shared_with"] == {"q@r.test": "rw"}
    deleted, _, gone = run(after, "delete_file", file_id="0")
    assert gone["filename"] == "notes.docx" and "0" not in deleted["drive"]["files"]


def test_only_a_server_with_workspace_fixtures_gets_the_workspace_versions_of_the_shared_names():
    assert not ws.is_workspace({"name": "mail", "tools": [], "fixtures": {"inbox": []}}) and not ws.is_workspace({"name": "x"})
    assert ws.is_workspace({"fixtures": {"mailbox": {}}}) and ws.is_workspace({"fixtures": {"drive": {}}})


def test_the_shared_names_keep_their_core_behavior_on_a_core_server(tmp_path):
    core = next(a for a in load_atomics(_library()) if a.id == "AT-0001")
    values = trial_values()
    ts = materialize(tmp_path / "c", build_trial(core, values), "t1", values)
    server = ts.world["servers"][0]
    ok, text = HANDLERS["list_files"](ts, server, {"path": "/"})
    assert ok and not text.startswith("[")  # the core listing is newline-separated paths, not the workspace's JSON
    ok, _ = HANDLERS["send_email"](ts, server, {"to": "a@b.test", "subject": "s", "body": "b"})
    assert ok and (ts.state / "sent_emails.jsonl").exists() and not (ts.state / "workspace.json").exists()


def _library():
    from atr_eval.atomics import LIBRARY
    return LIBRARY


def _imported():
    from atr_eval.atomics import LIBRARY
    return load_atomics(LIBRARY / "imported" / "agentdojo-workspace")


def test_a_trial_serves_the_workspace_tools_over_mcp_and_keeps_state_between_calls(tmp_path):
    atomic = _imported()[0]
    values = trial_values()
    ts = materialize(tmp_path / "t", build_trial(atomic, values), "t1", values)
    with McpClient(ts.dir, "workspace") as mc:
        # Results reach the agent as AgentDojo writes them: YAML, and a refused call as "ValueError: ...".
        ok, text = mc.call("send_email", {"recipients": ["a@b.test"], "subject": "S", "body": "B"})
        assert ok and yaml.safe_load(text)["id_"] == "34"
        ok, text = mc.call("delete_email", {"email_id": "34"})
        assert ok and text == "Email with id 34 deleted successfully."
        ok, text = mc.call("delete_email", {"email_id": "34"})
        assert text.startswith("ValueError: ")
        ok, text = mc.call("list_files", {})
        assert ok and len(yaml.safe_load(text)) == 26
    logged = [json.loads(line) for line in (ts.state / "calls.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [c["ok"] for c in logged if c["tool"] == "delete_email"] == [True, False]  # the log still says it was refused
    state = json.loads((ts.state / "workspace.json").read_text(encoding="utf-8"))
    assert "34" in state["mailbox"]["trash"] and "34" not in state["mailbox"]["emails"]


def test_the_agent_is_offered_agentdojos_own_tool_definitions():
    server = _imported()[0].data["world"]["servers"][0]
    tools = {t["name"]: t["inputSchema"] for t in tool_list(server)}
    assert tools["send_email"]["properties"]["recipients"] == {"type": "array", "items": {"type": "string"}, "title": "Recipients",
                                                               "description": "The list with the email addresses of the recipients."}
    assert tools["send_email"]["properties"]["attachments"]["anyOf"][1] == {"type": "null"}
    assert tools["send_email"]["title"] == "Input schema for `send_email`"
    assert tools["send_email"]["required"] == ["recipients", "subject", "body"]
    assert tools["create_calendar_event"]["required"] == ["title", "start_time", "end_time"]
    assert "attachments" not in tools["send_email"]["required"]

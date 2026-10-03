"""Adversarial end-to-end tests: a real mcpsum binary vs. a real malicious MCP server.

Each test names the guarantee it proves (see docs/GUARANTEES.md).
"""

from __future__ import annotations

import json
import time

import pytest

from harness import (INVALID_PARAMS, METHOD_NOT_FOUND, QUARANTINED, Client, lock_evil, run)

SECRETS = ("id_rsa", "IMPORTANT", "aws/credentials", "attacker@evil", "mcp.json")


def assert_clean(c: Client) -> None:
    blob = c.everything_received()
    for s in SECRETS:
        assert s not in blob, f"poison `{s}` reached the client: {blob[:500]}"


@pytest.fixture
def client_factory():
    clients: list[Client] = []

    def make(lockp, **kw):
        c = Client(lockp, **kw)
        clients.append(c)
        return c

    yield make
    for c in clients:
        c.close()


# --------------------------------------------------------------------- baseline

def test_clean_server_works_through_proxy(tmp_path, client_factory):
    lockp = lock_evil(tmp_path, "clean")
    c = client_factory(lockp)
    init = c.initialize()
    assert init["result"]["serverInfo"]["name"] == "evil-demo"
    tools = c.request(1, "tools/list")["result"]["tools"]
    assert [t["name"] for t in tools] == ["add", "echo_env"]
    r = c.call(2, "add", {"a": 2, "b": 3})
    assert r["result"]["content"][0]["text"] == "5"


# ------------------------------------------------- I1: definitions served from lock

def test_I1_rugpull_between_sessions_never_reaches_model_and_quarantines(tmp_path, client_factory):
    poison = tmp_path / "poison"
    lockp = lock_evil(tmp_path, "rugpull", poison_file=poison)
    poison.write_text("on")  # the server turns malicious after approval
    c = client_factory(lockp)
    c.initialize()
    tools = c.request(1, "tools/list")["result"]["tools"]
    assert tools[0]["description"] == "Add two numbers."
    r = c.call(2, "add", {"a": 1, "b": 2})
    assert r["error"]["code"] == QUARANTINED
    assert_clean(c)


def test_I1_verify_reports_drift_with_invisible_chars_made_visible(tmp_path):
    poison = tmp_path / "poison"
    lockp = lock_evil(tmp_path, "rugpull", poison_file=poison)
    assert run("verify", "--lock", str(lockp)).returncode == 0
    poison.write_text("on")
    r = run("verify", "--lock", str(lockp))
    assert r.returncode == 1, r.stdout + r.stderr
    assert "<U+200B>" in r.stdout and "<U+E0069>" in r.stdout
    assert "\u200b" not in r.stdout and "\U000e0069" not in r.stdout
    assert "\x1b" not in r.stdout


def test_I1_inline_rugpull_after_list_changed_quarantines(tmp_path, client_factory):
    lockp = lock_evil(tmp_path, "inline-rugpull")
    c = client_factory(lockp)
    c.initialize()
    assert c.call(1, "add", {"a": 1, "b": 2})["result"]["content"][0]["text"] == "3"
    time.sleep(1.0)  # server swaps definitions and emits list_changed
    r = c.call(2, "add", {"a": 1, "b": 2})
    assert r["error"]["code"] == QUARANTINED
    assert not any(m.get("method", "").endswith("list_changed") for m in c.received)
    assert_clean(c)


def test_I1_poisoned_instructions_never_reach_client(tmp_path, client_factory):
    poison = tmp_path / "poison"
    lockp = lock_evil(tmp_path, "instructions", poison_file=poison)
    poison.write_text("on")
    c = client_factory(lockp)
    init = c.initialize()
    assert init["result"]["instructions"] == "Arithmetic helper."
    assert c.call(1, "add", {"a": 1, "b": 2})["error"]["code"] == QUARANTINED
    assert_clean(c)


def test_I1_full_schema_poisoning_is_detected(tmp_path, client_factory):
    poison = tmp_path / "poison"
    lockp = lock_evil(tmp_path, "schema-smuggle", poison_file=poison)
    poison.write_text("on")
    c = client_factory(lockp)
    c.initialize()
    assert c.call(1, "add", {"a": 1, "b": 2})["error"]["code"] == QUARANTINED
    assert_clean(c)


# ------------------------------------------------- I2: strict locked schemas

def test_I2_hidden_exfil_argument_is_blocked_before_reaching_server(tmp_path, client_factory):
    lockp = lock_evil(tmp_path, "clean")
    c = client_factory(lockp)
    c.initialize()
    r = c.call(1, "add", {"a": 1, "b": 2, "sidenote": "-----BEGIN OPENSSH PRIVATE KEY-----"})
    assert r["error"]["code"] == INVALID_PARAMS
    r = c.call(2, "not_a_tool", {})
    assert r["error"]["code"] == INVALID_PARAMS


# ------------------------------------------------- I3: deny by default

@pytest.mark.parametrize("mode,method", [("sampling", "sampling/createMessage"), ("elicitation", "elicitation/create")])
def test_I3_server_initiated_requests_never_reach_client(tmp_path, client_factory, mode, method):
    lockp = lock_evil(tmp_path, mode)
    c = client_factory(lockp)
    c.initialize()
    r = c.call(1, "add", {"a": 1, "b": 2})
    text = r["result"]["content"][0]["text"]
    assert "denied by mcpsum policy" in text  # the server got a refusal, not the user's data
    assert not any(m.get("method") == method for m in c.received)
    assert "CLIENT_CAPS={}" in c.stderr  # sampling/elicitation/roots never advertised to the server


def test_I3_modern_discover_is_denied_by_default(tmp_path, client_factory):
    lockp = lock_evil(tmp_path, "clean")
    c = client_factory(lockp)
    r = c.request(1, "server/discover", {"protocolVersion": "2026-07-28"})
    assert r["error"]["code"] == METHOD_NOT_FOUND


# ------------------------------------------------- I7: fail closed

def test_I7_spoofed_and_duplicate_responses_are_dropped(tmp_path, client_factory):
    lockp = lock_evil(tmp_path, "spoof")
    c = client_factory(lockp)
    c.initialize()
    r = c.call(1, "add", {"a": 1, "b": 2})
    assert r["result"]["content"][0]["text"] == "3"
    time.sleep(0.5)
    blob = c.everything_received()
    assert "FORGED" not in blob and "DUPLICATE" not in blob


def test_I7_garbage_oversize_and_log_injection_are_dropped(tmp_path, client_factory):
    lockp = lock_evil(tmp_path, "garbage")
    c = client_factory(lockp)
    c.initialize()
    r = c.call(1, "add", {"a": 1, "b": 2})
    assert r["result"]["content"][0]["text"] == "3"
    assert c.p.poll() is None, "proxy died"
    assert_clean(c)


# ------------------------------------------------- environment scrubbing

def test_env_secrets_are_not_inherited_unless_passed_through(tmp_path, client_factory):
    env = {"SUPER_SECRET": "hunter2"}
    lockp = lock_evil(tmp_path, "envleak", env=env)
    c = client_factory(lockp, env=env)
    c.initialize()
    assert c.call(1, "echo_env", {})["result"]["content"][0]["text"] == "SUPER_SECRET=None"
    c.close()

    lockp2 = lock_evil(tmp_path, "envleak", env_pass=("SUPER_SECRET",), env=env)
    c2 = client_factory(lockp2, env=env)
    c2.initialize()
    assert c2.call(1, "echo_env", {})["result"]["content"][0]["text"] == "SUPER_SECRET=hunter2"
    assert "SUPER_SECRET" in json.loads(lockp2.read_text())["servers"]["evil"]["envPassthrough"]
    assert "hunter2" not in lockp2.read_text()


# ------------------------------------------------- I8: audit chain

def test_I8_audit_log_verifies_and_detects_tampering(tmp_path, client_factory):
    lockp = lock_evil(tmp_path, "clean")
    c = client_factory(lockp)
    c.initialize()
    c.call(1, "add", {"a": 1, "b": 2})
    c.call(2, "add", {"a": 1, "b": 2, "sidenote": "TOPSECRETVALUE"})
    c.call(3, "add", {"a": "TOPSECRETVALUE", "b": 2})
    c.close()
    ok = run("audit-verify", str(c.audit))
    assert ok.returncode == 0, ok.stdout + ok.stderr
    text = c.audit.read_text()
    assert '"decision":"deny"' in text
    assert "TOPSECRETVALUE" not in text, "argument values must never be written to the audit log"
    c.audit.write_text(text.replace('"decision":"deny"', '"decision":"allow"', 1))
    assert run("audit-verify", str(c.audit)).returncode != 0


# ------------------------------------------------- lock-time findings

def test_lock_time_findings_flag_hidden_characters_and_injection_markers(tmp_path):
    poison = tmp_path / "poison"
    poison.write_text("on")  # malicious at first sight (trust-on-first-use case)
    lock_evil(tmp_path, "rugpull", poison_file=poison)
    out = lock_evil.last.stdout  # type: ignore[attr-defined]
    assert "<U+200B>" in out and "<important>" in out.lower() and "id_rsa" in out
    assert "\u200b" not in out
    lock_evil(tmp_path, "rugpull", poison_file=poison, extra=("--deny-findings",), expect_rc=2)

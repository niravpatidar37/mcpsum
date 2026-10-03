"""Adversarial end-to-end tests: a real mcpsum binary vs. a real malicious MCP server.

Each test names the guarantee it proves (see docs/GUARANTEES.md).
"""

from __future__ import annotations

import json
import sys
import time

import pytest

from harness import (EVIL, INVALID_PARAMS, METHOD_NOT_FOUND, QUARANTINED, Client, lock_evil, run)

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
    # The server swaps definitions and emits list_changed after that call. Keep
    # calling until the proxy has re-verified; no fixed sleep, so no race.
    deadline = time.monotonic() + 20
    rid = 2
    while True:
        r = c.call(rid, "add", {"a": 1, "b": 2})
        rid += 1
        if "error" in r:
            break
        assert r["result"]["content"][0]["text"] == "3"
        assert time.monotonic() < deadline, "server was never quarantined"
        time.sleep(0.05)
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
    # The server writes call 1's duplicate before it reads call 2, and the proxy
    # handles server output in order: once call 2 is answered, the duplicate has
    # already been processed (and must have been dropped). Deterministic, no sleep.
    assert c.call(2, "add", {"a": 2, "b": 2})["result"]["content"][0]["text"] == "4"
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
    assert "SUPER_SECRET" in json.loads(lockp2.read_text(encoding="utf-8"))["servers"]["evil"]["envPassthrough"]
    assert "hunter2" not in lockp2.read_text(encoding="utf-8")


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
    text = c.audit.read_text(encoding="utf-8")
    assert '"decision":"deny"' in text
    assert "TOPSECRETVALUE" not in text, "argument values must never be written to the audit log"
    c.audit.write_text(text.replace('"decision":"deny"', '"decision":"allow"', 1), encoding="utf-8")
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


# ------------------------------------------------- verify semantics

def test_verify_ignores_informational_drift_unless_strict(tmp_path):
    poison = tmp_path / "poison"
    lockp = lock_evil(tmp_path, "version-bump", poison_file=poison)
    poison.write_text("on")  # only serverInfo.version changes
    r = run("verify", "--lock", str(lockp))
    assert r.returncode == 0, r.stdout + r.stderr
    assert "serverInfo changed" in r.stdout
    r = run("verify", "--lock", str(lockp), "--strict")
    assert r.returncode == 1, r.stdout + r.stderr


def test_relock_replaces_an_existing_lockfile(tmp_path):
    poison = tmp_path / "poison"
    lockp = lock_evil(tmp_path, "rugpull", poison_file=poison)
    before = lockp.read_text(encoding="utf-8")
    poison.write_text("on")
    lock_evil(tmp_path, "rugpull", poison_file=poison)  # same path, file exists
    after = lockp.read_text(encoding="utf-8")
    assert before != after and "sidenote" in after
    assert not (tmp_path / "mcp.lock.tmp").exists()


# ------------------------------------------------- I7: availability under a wedged server

def test_I7_deaf_server_cannot_hang_proxy_shutdown(tmp_path, client_factory):
    lockp = lock_evil(tmp_path, "deaf")
    c = client_factory(lockp)
    c.initialize()
    # Readiness is observable in the audit log; wait for it instead of sleeping.
    deadline = time.monotonic() + 20
    while "live definitions match mcp.lock" not in (c.audit.read_text(encoding="utf-8") if c.audit.exists() else ""):
        assert time.monotonic() < deadline, "proxy never became ready"
        time.sleep(0.05)
    big = "x" * 200_000
    try:
        for i in range(1, 51):  # ~10 MB the deaf server never reads: pipes and queue back up
            c.send({"jsonrpc": "2.0", "id": i, "method": "tools/call", "params": {"name": "echo_text", "arguments": {"text": big}}})
    except OSError:
        pass  # proxy may already have failed closed and exited
    c.p.stdin.close()
    started = time.monotonic()
    c.p.wait(timeout=20)  # raises TimeoutExpired if shutdown hangs on the blocked writer
    assert time.monotonic() - started < 20


# ------------------------------------------------- terminal injection via server stderr

def test_server_stderr_cannot_inject_terminal_escapes(tmp_path):
    lockp = tmp_path / "mcp.lock"
    r = run("lock", "--lock", str(lockp), "--name", "evil", "--", sys.executable, EVIL, "--mode", "stderr-escapes")
    assert r.returncode == 0, r.stdout + r.stderr
    assert "\x1b" not in r.stderr and "\x07" not in r.stderr, repr(r.stderr)
    assert "<U+001B>" in r.stderr
    # the forged verdict is visibly attributed to the server, never bare
    forged = [ln for ln in r.stderr.splitlines() if "definitions match" in ln]
    assert forged and all(ln.startswith("[server stderr] ") for ln in forged), forged

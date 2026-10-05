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


# ------------------------------------------------- process lifetime (#7)

def _assert_heartbeat_stops(hb):
    """The grandchild writes a timestamp every 100 ms while it is alive."""
    deadline = time.monotonic() + 10
    while not hb.exists():
        assert time.monotonic() < deadline, "grandchild never started"
        time.sleep(0.05)
    time.sleep(0.5)  # let a final write land
    before = hb.read_text(encoding="utf-8")
    time.sleep(1.0)
    after = hb.read_text(encoding="utf-8")
    assert before == after, "a server grandchild is still running after mcpsum finished"


def test_lock_kills_server_grandchildren(tmp_path):
    hb = tmp_path / "heartbeat"
    lockp = tmp_path / "mcp.lock"
    started = time.monotonic()
    r = run("lock", "--lock", str(lockp), "--name", "evil", "--",
            sys.executable, EVIL, "--mode", "forker", "--heartbeat-file", str(hb))
    assert r.returncode == 0, r.stdout + r.stderr
    assert time.monotonic() - started < 15, "lock waited on a pipe held by the grandchild"
    _assert_heartbeat_stops(hb)


def test_proxy_kills_server_grandchildren_on_shutdown(tmp_path, client_factory):
    hb = tmp_path / "heartbeat"
    lockp = tmp_path / "mcp.lock"
    r = run("lock", "--lock", str(lockp), "--name", "evil", "--",
            sys.executable, EVIL, "--mode", "forker", "--heartbeat-file", str(hb))
    assert r.returncode == 0, r.stdout + r.stderr
    _assert_heartbeat_stops(hb)  # the lock-time grandchild is gone
    hb.unlink()
    c = client_factory(lockp)
    c.initialize()
    assert c.call(1, "add", {"a": 1, "b": 2})["result"]["content"][0]["text"] == "3"
    c.p.stdin.close()
    c.p.wait(timeout=20)
    _assert_heartbeat_stops(hb)


# ------------------------------------------------- I8 with concurrent proxies (#29)

def test_I8_two_proxies_for_one_server_keep_one_valid_chain(tmp_path, client_factory):
    # VS Code runs MCP servers in two processes at once (extension host and
    # Agent Host), so two proxies for the same server share one audit log.
    lockp = lock_evil(tmp_path, "clean")
    a, b = client_factory(lockp), client_factory(lockp)
    a.initialize()
    b.initialize()
    for i in range(1, 11):
        assert a.call(i, "add", {"a": i, "b": 1})["result"]["content"][0]["text"] == str(i + 1)
        assert b.call(i, "add", {"a": i, "b": 2})["result"]["content"][0]["text"] == str(i + 2)
    for c in (a, b):
        c.p.stdin.close()
        c.p.wait(timeout=20)
    r = run("audit-verify", str(a.audit))
    assert r.returncode == 0, r.stdout + r.stderr
    assert not list(tmp_path.glob("*.corrupt-*")), "a valid log was moved aside"


# ------------------------------------------------- I6: taint tracking (design 0001)

def add_taint_policy(lockp, sources=("fetch",), sinks=("add",), server="evil"):
    lf = json.loads(lockp.read_text(encoding="utf-8"))
    lf["servers"][server]["policy"] = {"taint": {"sources": list(sources), "sinks": list(sinks)}}
    lockp.write_text(json.dumps(lf, indent=2), encoding="utf-8")


def state_env(tmp_path, **extra):
    """Isolate the shared taint state: every proxy pytest starts has the same
    parent process, so without this all tests would share one session."""
    return {"MCPSUM_STATE_DIR": str(tmp_path / "state"), **extra}


def lock_web_and_mail(tmp_path):
    """Two servers in one lock: `web` reads untrusted pages, `mail` has the sink."""
    lockp = tmp_path / "mcp.lock"
    for name in ("web", "mail"):
        r = run("lock", "--lock", str(lockp), "--name", name, "--", sys.executable, EVIL, "--mode", "taint")
        assert r.returncode == 0, r.stderr
    add_taint_policy(lockp, sources=("fetch",), sinks=(), server="web")
    add_taint_policy(lockp, sources=(), sinks=("add",), server="mail")
    return lockp


def audit_entries(c):
    return [json.loads(line) for line in c.audit.read_text(encoding="utf-8").splitlines()]


def test_I6_injected_result_cannot_trigger_a_sink_when_the_client_cannot_prompt(tmp_path, client_factory):
    lockp = lock_evil(tmp_path, "taint")
    add_taint_policy(lockp)
    c = client_factory(lockp, env=state_env(tmp_path))
    c.initialize(capabilities={})  # no elicitation: mcpsum cannot ask the user
    assert c.call(1, "add", {"a": 1, "b": 2})["result"]["content"][0]["text"] == "3", "clean session: sink works"
    page = c.call(2, "fetch", {"url": "https://evil.example"})
    assert "IGNORE PREVIOUS INSTRUCTIONS" in json.dumps(page)
    r = c.call(3, "add", {"a": 1300, "b": 37})
    assert r["error"]["code"] == -32001, r
    assert "untrusted" in r["error"]["message"] and "fetch" in r["error"]["message"]
    c.close()
    ev = audit_entries(c)
    kinds = [(e["event"]["decision"], e["event"].get("subject")) for e in ev]
    assert ("taint", "fetch") in kinds and ("deny", "add") in kinds
    assert kinds.index(("taint", "fetch")) < kinds.index(("deny", "add"))
    assert "1300" not in c.audit.read_text(encoding="utf-8"), "arguments must not be logged"
    assert run("audit-verify", str(c.audit)).returncode == 0


def test_I6_sink_after_injection_runs_only_when_the_user_allows_it(tmp_path, client_factory):
    lockp = lock_evil(tmp_path, "taint")
    add_taint_policy(lockp)
    c = client_factory(lockp, env=state_env(tmp_path))
    c.initialize()  # advertises elicitation
    c.call(1, "fetch", {"url": "https://evil.example"})
    # The user declines: the call is refused and never reaches the server.
    c.send({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "add", "arguments": {"a": 1300, "b": 37}}})
    ask = c.next_request("elicitation/create")
    assert ask["id"].startswith("mcpsum-approval-")
    msg = ask["params"]["message"]
    assert msg.startswith("mcpsum security check:") and "`add`" in msg and "`evil:fetch`" in msg
    assert "IGNORE PREVIOUS" not in msg, "server text must never appear in mcpsum's prompt"
    c.send({"jsonrpc": "2.0", "id": ask["id"], "result": {"action": "decline"}})
    r = c.wait_response(2)
    assert r["error"]["code"] == -32001, r
    # The user allows the next one: exactly that call runs.
    c.send({"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "add", "arguments": {"a": 2, "b": 2}}})
    ask = c.next_request("elicitation/create")
    assert '"a":2' in ask["params"]["message"].replace(" ", "")
    c.send({"jsonrpc": "2.0", "id": ask["id"], "result": {"action": "accept", "content": {"allow": True}}})
    r = c.wait_response(3)
    assert r["result"]["content"][0]["text"] == "4", r
    c.close()
    decisions = [e["event"]["decision"] for e in audit_entries(c)]
    assert decisions.count("hold") == 2
    assert run("audit-verify", str(c.audit)).returncode == 0


def test_I6_relock_keeps_the_user_policy(tmp_path):
    lockp = lock_evil(tmp_path, "taint")
    add_taint_policy(lockp)
    lock_evil(tmp_path, "taint")  # re-lock the same server
    lf = json.loads(lockp.read_text(encoding="utf-8"))
    assert lf["servers"]["evil"]["policy"] == {"taint": {"sources": ["fetch"], "sinks": ["add"]}}
    add_taint_policy(lockp, sinks=("add", "send_emial"))
    r = run("show", "--lock", str(lockp))
    assert r.returncode != 0 and "send_emial" in r.stderr, "a typo in the policy must fail closed"


def test_I6_taint_crosses_servers_of_one_client_session(tmp_path, client_factory):
    # Both proxies are started by the same process (like an MCP client does),
    # so they share the default session: content read by `web` gates `mail`.
    lockp = lock_web_and_mail(tmp_path)
    web = client_factory(lockp, name="web", env=state_env(tmp_path))
    mail = client_factory(lockp, name="mail", env=state_env(tmp_path))
    web.initialize(capabilities={})
    mail.initialize(capabilities={})
    assert mail.call(1, "add", {"a": 1, "b": 2})["result"]["content"][0]["text"] == "3"
    web.call(1, "fetch", {"url": "https://evil.example"})
    r = mail.call(2, "add", {"a": 1300, "b": 37})
    assert r["error"]["code"] == -32001, r
    assert "web:fetch" in r["error"]["message"]


def test_I6_separate_sessions_do_not_share_taint(tmp_path, client_factory):
    lockp = lock_web_and_mail(tmp_path)
    web = client_factory(lockp, name="web", env=state_env(tmp_path))
    mail = client_factory(lockp, name="mail", env=state_env(tmp_path, MCPSUM_SESSION="another-client"))
    web.initialize(capabilities={})
    mail.initialize(capabilities={})
    web.call(1, "fetch", {"url": "https://evil.example"})
    assert mail.call(1, "add", {"a": 1, "b": 2})["result"]["content"][0]["text"] == "3"


def test_I6_unreadable_taint_state_counts_as_tainted(tmp_path, client_factory):
    lockp = lock_web_and_mail(tmp_path)
    (tmp_path / "state").mkdir()
    (tmp_path / "state" / "s1.taint").write_text("{garbage", encoding="utf-8")
    mail = client_factory(lockp, name="mail", env=state_env(tmp_path, MCPSUM_SESSION="s1"))
    mail.initialize(capabilities={})
    r = mail.call(1, "add", {"a": 1, "b": 2})
    assert r["error"]["code"] == -32001, r


def test_I6_taint_list_shows_the_session_and_reset_needs_a_person(tmp_path, client_factory):
    lockp = lock_web_and_mail(tmp_path)
    env = state_env(tmp_path, MCPSUM_SESSION="s1")
    web = client_factory(lockp, name="web", env=env)
    web.initialize(capabilities={})
    web.call(1, "fetch", {"url": "https://evil.example"})
    r = run("taint", "list", env=env)
    assert r.returncode == 0 and "s1" in r.stdout and "web:fetch" in r.stdout, r
    # An agent with a shell tool runs commands without a terminal: refused.
    r = run("taint", "reset", "--all", env=env)
    assert r.returncode == 3 and "terminal" in r.stderr, r
    assert "web:fetch" in run("taint", "list", env=env).stdout, "taint must survive a refused reset"


def test_suggest_policy_labels_unannotated_tools_conservatively(tmp_path):
    lockp = lock_evil(tmp_path, "taint")
    r = run("suggest-policy", "--lock", str(lockp), "--name", "evil")
    assert r.returncode == 0, r.stderr
    snippet = json.loads(r.stdout[r.stdout.index("{"):r.stdout.rindex("}") + 1])
    # No annotations: by the MCP defaults every tool may be open-world and may write.
    assert set(snippet["policy"]["taint"]["sources"]) == {"add", "echo_env", "fetch"}
    assert set(snippet["policy"]["taint"]["sinks"]) == {"add", "echo_env", "fetch"}
    assert "policy" not in json.loads(lockp.read_text(encoding="utf-8"))["servers"]["evil"], "never applied automatically"

#!/usr/bin/env bash
# The recorded session. Every command and all of its output are real; this
# script only prints the comments and the prompt, and paces the typing.
cd "${DEMO_DIR:-.}" || exit 1
A=$'\e[1;33m' G=$'\e[1;32m' R=$'\e[0m'
typed() { printf '%s$%s ' "$G" "$R"; local s=$1 i; for ((i = 0; i < ${#s}; i++)); do printf '%s' "${s:i:1}"; sleep 0.03; done; printf '\n'; sleep 0.25; }
note() { printf '%s# %s%s\n' "$A" "$1" "$R"; sleep 1.0; }
run() { typed "$1"; eval "$1" 2>/dev/null; sleep "${2:-1.2}"; }

note "1. approve an MCP server: pin its tool definitions in mcp.lock"
run "mcpsum lock --name weather -- python3 server.py --mode rugpull --poison-file update" 1.8
note "2. later, an update swaps in a poisoned tool (a rug pull)"
run "touch update" 0.5
run "mcpsum verify" 6.5
note "3. through the proxy, the model never sees the new text, and the call is refused"
run "python3 client.py" 3.5
note "4. every decision is in a hash-chained audit log"
run "mcpsum audit-verify .mcpsum-audit/weather.jsonl" 1.6
printf '%s# the server is quarantined. nothing new reached the model.%s\n' "$A" "$R"
sleep 1

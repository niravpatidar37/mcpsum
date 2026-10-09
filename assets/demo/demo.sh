#!/usr/bin/env bash
# The recorded session: every command and output is real.
cd "${DEMO_DIR:-.}" || exit 1
G=$'\e[1;32m' C=$'\e[2;36m' R=$'\e[0m'
typed() { printf '%s$%s ' "$G" "$R"; local s="$1" i; for ((i = 0; i < ${#s}; i++)); do printf '%s' "${s:i:1}"; sleep 0.035; done; printf '\n'; sleep 0.3; }
note() { printf '%s# %s%s\n' "$C" "$1" "$R"; sleep 1.2; }
run() { typed "$1"; eval "$1" 2>/dev/null; sleep "${2:-1.2}"; }

note "1. approve an MCP server: pin its tools in mcp.lock"
run "mcpsum lock --name weather -- python3 server.py --mode rugpull --poison-file update" 2
note "2. later, an update swaps in a poisoned tool (rug pull)"
run "touch update" 0.6
run "mcpsum verify" 6.5
note "3. through the proxy, the model never sees the new text"
run "python3 client.py" 4

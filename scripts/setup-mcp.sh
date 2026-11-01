#!/usr/bin/env bash
# Register (or re-register) the RiskProof MCP server with Claude Code.
#
# Tenable API keys are taken from, in order:
#   1. TENABLE_ACCESS_KEY / TENABLE_SECRET_KEY already exported in your shell
#   2. a hidden interactive prompt (nothing is echoed or saved to shell history)
# Press Enter at the prompt to skip Tenable and register with import_nessus only.
#
# The keys are stored in Claude Code's MCP config for this project (local scope).
# Use a read-only Tenable API key. They are never written to .env.
#
# Usage: ./scripts/setup-mcp.sh
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER_NAME="riskproof"
IMPORT_DIR="${RISKPROOF_IMPORT_DIR:-$HOME/.riskproof/imports}"

command -v claude >/dev/null 2>&1 || { echo "error: 'claude' CLI not found on PATH" >&2; exit 1; }
command -v uv >/dev/null 2>&1 || { echo "error: 'uv' not found on PATH" >&2; exit 1; }

mkdir -p "$IMPORT_DIR"
chmod 700 "$IMPORT_DIR"

ACCESS_KEY="${TENABLE_ACCESS_KEY:-}"
SECRET_KEY="${TENABLE_SECRET_KEY:-}"
if [[ -z "$ACCESS_KEY" || -z "$SECRET_KEY" ]]; then
  echo "Tenable API keys (leave blank to skip Tenable):"
  read -r -s -p "  Access key: " ACCESS_KEY; echo
  if [[ -n "$ACCESS_KEY" ]]; then
    read -r -s -p "  Secret key: " SECRET_KEY; echo
  fi
fi

env_args=(-e "RISKPROOF_IMPORT_DIR=$IMPORT_DIR")
if [[ -n "$ACCESS_KEY" && -n "$SECRET_KEY" ]]; then
  env_args+=(-e "TENABLE_ACCESS_KEY=$ACCESS_KEY" -e "TENABLE_SECRET_KEY=$SECRET_KEY")
  tenable="configured"
else
  tenable="not configured (import_tenable will report provider_unavailable)"
fi

if claude mcp get "$SERVER_NAME" >/dev/null 2>&1; then
  echo "Removing existing '$SERVER_NAME' registration..."
  claude mcp remove "$SERVER_NAME" -s local >/dev/null
fi

claude mcp add "$SERVER_NAME" -s local "${env_args[@]}" -- \
  uv --directory "$REPO_DIR" run riskproof serve

echo
echo "Registered '$SERVER_NAME'."
echo "  Import dir : $IMPORT_DIR  (drop .nessus files here)"
echo "  Tenable    : $tenable"
echo "Restart Claude Code so it picks up the new server environment."

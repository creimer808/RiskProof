#!/usr/bin/env bash
# Set up RiskProof for Claude Code: prompt for settings, verify the server starts,
# register it, and (optionally) open Claude Code with RiskProof connected.
#
# Usage: ./scripts/setup-mcp.sh [--yes] [--no-launch]
#   --yes        no prompts: use exported variables and defaults
#   --no-launch  do not offer to open Claude Code at the end
#
# Every prompt shows its default; press Enter to accept it. Settings can also be
# pre-set by exporting them (RISKPROOF_IMPORT_DIR, RISKPROOF_REPORTS_DIR,
# RISKPROOF_DB_PATH, RISKPROOF_ASSET_INVENTORY, RISKPROOF_ALLOWED_TARGETS,
# RISKPROOF_OFFLINE, TENABLE_ACCESS_KEY, TENABLE_SECRET_KEY, GREYNOISE_API_KEY).
#
# Secrets (Tenable keys, GreyNoise key) are read with hidden input or from your
# environment, are never printed, and are stored only in Claude Code's MCP config
# for this project (local scope). They are never written to .env or any file by
# this script. Use read-only keys. Note: while `claude mcp add` runs, its arguments
# (including keys) are briefly visible to other local users via `ps`.
#
# Re-running replaces the registration; re-enter or re-export your keys, because
# stored keys cannot be read back.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVER_NAME="riskproof"
SCOPE="local"
ASSUME_YES=0
LAUNCH=1

die() { echo "error: $*" >&2; exit 1; }

usage() {
  sed -n '2,19p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --yes|-y) ASSUME_YES=1 ;;
    --no-launch) LAUNCH=0 ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
  shift
done

command -v claude >/dev/null 2>&1 || die "'claude' CLI not found on PATH"
command -v uv >/dev/null 2>&1 || die "'uv' not found on PATH"

if [[ ! -d "$REPO_DIR/.venv" ]]; then
  echo "Installing RiskProof dependencies (uv sync)..."
  uv --directory "$REPO_DIR" sync >/dev/null || die "'uv sync' failed"
fi

# ask VAR "Label" "default": value comes from the exported VAR, else the prompt, else default.
ask() {
  local var="$1" label="$2" default="$3" current="${!1:-}" answer=""
  if [[ -n "$current" ]]; then default="$current"; fi
  if [[ $ASSUME_YES -eq 0 ]]; then
    read -r -p "  $label [${default:-none}]: " answer || answer=""
  fi
  printf -v "$var" '%s' "${answer:-$default}"
}

# ask_secret VAR "Label": exported value wins; else hidden prompt; blank = not set.
ask_secret() {
  local var="$1" label="$2" answer=""
  if [[ -n "${!1:-}" ]]; then
    echo "  $label: using $var from your environment (run 'unset $var' to be asked instead)"
    return
  fi
  if [[ $ASSUME_YES -eq 0 ]]; then
    read -r -s -p "  $label (hidden, Enter to skip): " answer || answer=""
    echo
  fi
  printf -v "$var" '%s' "$answer"
}

expand_path() {
  local raw="$1" path
  case "$raw" in
    "~") path="$HOME" ;;
    "~/"*) path="$HOME/${raw#"~/"}" ;;
    *) path="$raw" ;;
  esac
  [[ "$path" == /* ]] || die "path must be absolute (or start with ~): $raw"
  [[ ! "$path" =~ [[:cntrl:]] ]] || die "path contains control characters"
  printf '%s' "$path"
}

check_secret() {
  local label="$1" value="$2"
  [[ -z "$value" || "$value" =~ ^[[:graph:]]+$ ]] \
    || die "$label contains whitespace or control characters"
}

echo "RiskProof setup (press Enter to accept the [default])"
echo "Data locations:"
ask RISKPROOF_IMPORT_DIR "Folder for .nessus files to import" "$HOME/.riskproof/imports"
ask RISKPROOF_REPORTS_DIR "Folder for HTML reports" "$HOME/.riskproof/reports"
ask RISKPROOF_DB_PATH "Database file" "$HOME/.riskproof/riskproof.db"
ask RISKPROOF_ASSET_INVENTORY "Asset inventory file (optional)" "$HOME/.riskproof/assets.json"
echo "Safety:"
ask RISKPROOF_ALLOWED_TARGETS "Hosts/IPs/CIDRs validation may touch (empty = none)" ""
ask RISKPROOF_OFFLINE "Offline SAMPLE-data mode only? (y/N)" "n"
echo "Integrations (optional, hidden input):"
ask_secret TENABLE_ACCESS_KEY "Tenable access key"
if [[ -n "${TENABLE_ACCESS_KEY:-}" ]]; then
  ask_secret TENABLE_SECRET_KEY "Tenable secret key"
fi
ask_secret GREYNOISE_API_KEY "GreyNoise API key"
TENABLE_ACCESS_KEY="${TENABLE_ACCESS_KEY:-}"
TENABLE_SECRET_KEY="${TENABLE_SECRET_KEY:-}"
GREYNOISE_API_KEY="${GREYNOISE_API_KEY:-}"

# --- validate everything before touching anything ---------------------------------
IMPORT_DIR="$(expand_path "$RISKPROOF_IMPORT_DIR")"
REPORTS_DIR="$(expand_path "$RISKPROOF_REPORTS_DIR")"
DB_PATH="$(expand_path "$RISKPROOF_DB_PATH")"
INVENTORY="$(expand_path "$RISKPROOF_ASSET_INVENTORY")"

ALLOWED="$(printf '%s' "$RISKPROOF_ALLOWED_TARGETS" | tr -d '[:space:]')"
if [[ -n "$ALLOWED" && ! "$ALLOWED" =~ ^[A-Za-z0-9._:/-]+(,[A-Za-z0-9._:/-]+)*$ ]]; then
  die "allowlist must be comma-separated hostnames, IPs or CIDRs (letters, digits, . : / - only)"
fi

OFFLINE=false
case "$(printf '%s' "$RISKPROOF_OFFLINE" | tr '[:upper:]' '[:lower:]')" in
  y|yes|true|1) OFFLINE=true ;;
esac

if [[ -n "$TENABLE_ACCESS_KEY" || -n "$TENABLE_SECRET_KEY" ]]; then
  [[ -n "$TENABLE_ACCESS_KEY" && -n "$TENABLE_SECRET_KEY" ]] \
    || die "Tenable needs both an access key and a secret key (or neither)"
fi
check_secret "Tenable access key" "$TENABLE_ACCESS_KEY"
check_secret "Tenable secret key" "$TENABLE_SECRET_KEY"
check_secret "GreyNoise API key" "$GREYNOISE_API_KEY"

# --- create data folders (owner-only when we create them) -------------------------
make_dir() {
  if [[ ! -d "$1" ]]; then
    mkdir -p "$1" && chmod 700 "$1" || die "cannot create $1"
  fi
}
make_dir "$IMPORT_DIR"
make_dir "$REPORTS_DIR"
make_dir "$(dirname "$DB_PATH")"
[[ -w "$(dirname "$DB_PATH")" ]] || die "cannot write to $(dirname "$DB_PATH")"

# --- prove the server starts (throwaway database, no secrets, offline) ------------
verify_server() {
  local scratch
  scratch="$(mktemp -d)"
  (
    unset TENABLE_ACCESS_KEY TENABLE_SECRET_KEY GREYNOISE_API_KEY
    export RISKPROOF_DB_PATH="$scratch/check.db" RISKPROOF_OFFLINE=true
    export RISKPROOF_ASSET_INVENTORY="$scratch/none.json"
    uv --directory "$REPO_DIR" run python -I - "$REPO_DIR" <<'PY'
import asyncio
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def check(repo: str) -> None:
    params = StdioServerParameters(
        command="uv",
        args=["--directory", repo, "run", "riskproof", "serve"],
        env=dict(os.environ),
    )
    async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
        init = await session.initialize()
        tools = await session.list_tools()
    if init.serverInfo.name != "riskproof" or not tools.tools:
        raise SystemExit("unexpected server identity or no tools")
    print(f"{len(tools.tools)} tools")


asyncio.run(asyncio.wait_for(check(sys.argv[1]), timeout=90))
PY
  )
  local status=$?
  rm -rf "$scratch"
  return $status
}

echo
echo "Checking that the server starts..."
check_log="$(mktemp)"
if checked="$(verify_server 2>"$check_log")"; then
  echo "Server check passed ($checked)."
  rm -f "$check_log"
else
  tail -n 15 "$check_log" >&2
  rm -f "$check_log"
  die "server check failed; nothing was registered"
fi

# --- register ---------------------------------------------------------------------
env_args=(
  -e "RISKPROOF_IMPORT_DIR=$IMPORT_DIR"
  -e "RISKPROOF_REPORTS_DIR=$REPORTS_DIR"
  -e "RISKPROOF_DB_PATH=$DB_PATH"
  -e "RISKPROOF_ASSET_INVENTORY=$INVENTORY"
)
[[ -n "$ALLOWED" ]] && env_args+=(-e "RISKPROOF_ALLOWED_TARGETS=$ALLOWED")
[[ "$OFFLINE" == true ]] && env_args+=(-e "RISKPROOF_OFFLINE=true")
[[ -n "$TENABLE_ACCESS_KEY" ]] \
  && env_args+=(-e "TENABLE_ACCESS_KEY=$TENABLE_ACCESS_KEY" -e "TENABLE_SECRET_KEY=$TENABLE_SECRET_KEY")
[[ -n "$GREYNOISE_API_KEY" ]] && env_args+=(-e "GREYNOISE_API_KEY=$GREYNOISE_API_KEY")

if claude mcp get "$SERVER_NAME" >/dev/null 2>&1; then
  echo "Replacing the existing '$SERVER_NAME' registration..."
  claude mcp remove "$SERVER_NAME" -s "$SCOPE" >/dev/null
fi
claude mcp add "$SERVER_NAME" -s "$SCOPE" "${env_args[@]}" -- \
  uv --directory "$REPO_DIR" run riskproof serve >/dev/null \
  || die "'claude mcp add' failed; re-run this script to register again"

flag() { [[ -n "$1" ]] && echo set || echo "not set"; }
echo
echo "Registered '$SERVER_NAME' for this folder: $PWD"
echo "  Imports   : $IMPORT_DIR  (drop .nessus files here)"
echo "  Reports   : $REPORTS_DIR"
echo "  Database  : $DB_PATH"
echo "  Inventory : $INVENTORY"
echo "  Allowlist : ${ALLOWED:-none (validation refuses every target)}"
echo "  Offline   : $OFFLINE"
echo "  Tenable   : $(flag "$TENABLE_ACCESS_KEY")"
echo "  GreyNoise : $(flag "$GREYNOISE_API_KEY")"

# --- launch -----------------------------------------------------------------------
if [[ $LAUNCH -eq 1 ]]; then
  if [[ $ASSUME_YES -eq 1 ]]; then
    [[ -t 1 ]] || LAUNCH=0
  else
    read -r -p "Open Claude Code now? [Y/n]: " answer || answer="n"
    case "$(printf '%s' "${answer:-y}" | tr '[:upper:]' '[:lower:]')" in
      y|yes) ;;
      *) LAUNCH=0 ;;
    esac
  fi
fi

if [[ $LAUNCH -eq 1 ]]; then
  echo "Starting Claude Code with RiskProof connected..."
  exec claude
fi
echo "Start Claude Code from this folder ($PWD) to use RiskProof."

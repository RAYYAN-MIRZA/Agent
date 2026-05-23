#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# Kali / Linux — enroll FYP agent, clear prior credentials, start with sudo.
#
# Typical flow (Windows host runs API on LAN IP, e.g. 192.168.100.6:5017):
#   1. On Windows (FYP.Backend): .\scripts\bootstrap-kali-from-vs.ps1
#      Copy the printed ENROLLMENT_TOKEN into ENROLLMENT_TOKEN below OR export it.
#   2. On Kali (Agent repo):
#        chmod +x scripts/kali-enroll-and-run.sh
#        ./scripts/kali-enroll-and-run.sh
#
# Optional: mint token from Kali if API has Agent__BootstrapMintSecret set:
#   export FYP_BOOTSTRAP_MINT_SECRET='fyp-dev-bootstrap-mint'
#   export FYP_NETWORK_ID='<guid-from-bootstrap-output>'
#   ./scripts/kali-enroll-and-run.sh --mint
# -----------------------------------------------------------------------------
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$AGENT_ROOT"

# --- Edit these (or export before running) -----------------------------------
API_BASE_URL="${FYP_AGENT_API_BASE_URL:-http://192.168.100.6:5017}"
AGENT_NAME="${FYP_AGENT_NAME:-kali-lab}"
DISCOVERY_CIDR="${FYP_AGENT_DISCOVERY_CIDR:-192.168.100.0/24}"
ENROLLMENT_TOKEN="${FYP_AGENT_ENROLLMENT_TOKEN:-}"

# Mint-from-Kali (optional; network row must exist — run Windows bootstrap once)
FYP_BOOTSTRAP_MINT_SECRET="${FYP_BOOTSTRAP_MINT_SECRET:-}"
FYP_NETWORK_ID="${FYP_NETWORK_ID:-}"
MINT_LABEL="${FYP_ENROLLMENT_LABEL:-kali-bootstrap}"
TTL_HOURS="${FYP_ENROLLMENT_TTL_HOURS:-168}"

STATE_DIR="${FYP_AGENT_STATE_DIR:-${HOME}/.fyp-agent}"
VENV_PYTHON="${FYP_AGENT_VENV_PYTHON:-$AGENT_ROOT/.venv/bin/python}"

# -----------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
info() { printf '%b\n' "${YELLOW}[kali-agent]${NC} $*"; }
die() { printf '%b\n' "${RED}ERROR:${NC} $*" >&2; exit 1; }

MINT_MODE=false
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mint) MINT_MODE=true; shift ;;
    -h|--help)
      sed -n '1,24p' "$0"
      exit 0
      ;;
    *) die "Unknown option: $1 (use --help)" ;;
  esac
done

remove_state_files() {
  info "Removing saved agent credentials (re-enroll)..."
  local paths=(
    "$STATE_DIR/state.json"
    "${HOME}/.fyp-agent/state.json"
    "/root/.fyp-agent/state.json"
  )
  for p in "${paths[@]}"; do
    if [[ -f "$p" ]]; then
      if [[ -w "$p" ]]; then
        rm -f "$p"
        info "  removed $p"
      else
        sudo rm -f "$p"
        info "  sudo removed $p"
      fi
    fi
  done
}

mint_token() {
  [[ -n "$FYP_BOOTSTRAP_MINT_SECRET" ]] || die "Set FYP_BOOTSTRAP_MINT_SECRET for --mint"
  [[ -n "$FYP_NETWORK_ID" ]] || die "Set FYP_NETWORK_ID (from Windows bootstrap output or SQL Networks table)"

  local mint_url="${API_BASE_URL%/}/api/v1/agents/enrollments"
  info "Minting enrollment token at $mint_url ..."
  local body
  body="$(python3 -c "import json; print(json.dumps({'label':'$MINT_LABEL','networkId':'$FYP_NETWORK_ID','ttlHours':int('$TTL_HOURS')}))")"

  local resp
  resp="$(curl -fsS -X POST "$mint_url" \
    -H "Content-Type: application/json" \
    -H "X-FYP-Bootstrap-Mint: $FYP_BOOTSTRAP_MINT_SECRET" \
    -d "$body")" || die "Mint failed — is API up and BootstrapMintSecret set on API?"

  ENROLLMENT_TOKEN="$(python3 -c "import json,sys; print(json.load(sys.stdin).get('enrollmentToken',''))" <<<"$resp")"
  [[ -n "$ENROLLMENT_TOKEN" ]] || die "Mint response missing enrollmentToken: $resp"
  info "Token minted."
}

[[ -x "$VENV_PYTHON" ]] || die "Missing venv at $VENV_PYTHON — run: python3 -m venv .venv && .venv/bin/pip install -r fyp_agent/requirements.txt"

if $MINT_MODE; then
  mint_token
fi

[[ -n "$ENROLLMENT_TOKEN" ]] || die "Set FYP_AGENT_ENROLLMENT_TOKEN (run bootstrap-kali-from-vs.ps1 on Windows, or use --mint)"

remove_state_files

export FYP_AGENT_API_BASE_URL="${API_BASE_URL%/}"
export FYP_AGENT_ENROLLMENT_TOKEN="$ENROLLMENT_TOKEN"
export FYP_AGENT_NAME="$AGENT_NAME"
export FYP_AGENT_DISCOVERY_CIDR="$DISCOVERY_CIDR"
export FYP_AGENT_VERIFY_TLS="${FYP_AGENT_VERIFY_TLS:-false}"

info "API:      $FYP_AGENT_API_BASE_URL"
info "Agent:    $FYP_AGENT_NAME"
info "Discover: $FYP_AGENT_DISCOVERY_CIDR"
info "Starting agent (sudo preserves env with -E)..."
printf '%b\n' "${GREEN}Console:${NC} http://localhost:4200 — admin@fyp.local / admin — tenant default"
echo ""

exec sudo -E "$VENV_PYTHON" -m fyp_agent

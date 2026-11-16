#!/usr/bin/env bash
set -euo pipefail

# One-command macOS/Linux installer for NetForge MCP (offline planning, IPAM, IOS & MCP server).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

WITH_DEV=false
SYSTEM_PYTHON=false
NO_EDITABLE=false
CLIENT="none"
TOOL_PROFILE="solve_lab"
PERMISSION_PROFILE="standard"
DATA_DIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --with-dev) WITH_DEV=true; shift ;;
    --system-python) SYSTEM_PYTHON=true; shift ;;
    --no-editable) NO_EDITABLE=true; shift ;;
    --client) CLIENT="$2"; shift 2 ;;
    --tool-profile) TOOL_PROFILE="$2"; shift 2 ;;
    --profile) PERMISSION_PROFILE="$2"; shift 2 ;;
    --data-dir) DATA_DIR="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: $0 [--with-dev] [--system-python] [--no-editable] [--client none|antigravity|claude|cursor|vscode] [--tool-profile solve_lab|advanced] [--profile read-only|planning|configuration|standard] [--data-dir PATH]"
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 1
      ;;
  esac
done

find_python() {
  for cand in python3.12 python3.11 python3 python; do
    if command -v "$cand" >/dev/null 2>&1; then
      if "$cand" -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)" >/dev/null 2>&1; then
        echo "$cand"
        return 0
      fi
    fi
  done
  echo "Python 3.11+ is required." >&2
  return 1
}

cd "$REPO_ROOT"
BASE_PY="$(find_python)"

if [[ "$SYSTEM_PYTHON" == "true" ]]; then
  PY_EXE="$("$BASE_PY" -c "import sys; print(sys.executable)")"
elif [[ -n "${VIRTUAL_ENV:-}" && -x "$VIRTUAL_ENV/bin/python" ]]; then
  PY_EXE="$VIRTUAL_ENV/bin/python"
else
  if [[ ! -x "$REPO_ROOT/.venv/bin/python" ]]; then
    echo "Creating virtual environment at $REPO_ROOT/.venv ..."
    "$BASE_PY" -m venv "$REPO_ROOT/.venv"
  fi
  PY_EXE="$REPO_ROOT/.venv/bin/python"
fi

TARGET_SPEC="."
if [[ "$WITH_DEV" == "true" ]]; then
  TARGET_SPEC=".[dev]"
fi

if [[ "$NO_EDITABLE" == "true" ]]; then
  "$PY_EXE" -m pip install "$TARGET_SPEC"
else
  "$PY_EXE" -m pip install -e "$TARGET_SPEC"
fi

SETUP_ARGS=(-m netforge setup --client "$CLIENT" --tool-profile "$TOOL_PROFILE" --profile "$PERMISSION_PROFILE")
if [[ -n "$DATA_DIR" ]]; then
  SETUP_ARGS+=(--data-dir "$DATA_DIR")
fi

"$PY_EXE" "${SETUP_ARGS[@]}"
echo ""
"$PY_EXE" -m netforge doctor

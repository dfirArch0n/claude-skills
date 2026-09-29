#!/usr/bin/env bash
# Install sigma-cli with the backends this skill converts to, and verify them.
#
#   setup_sigma.sh           install (idempotent)
#   setup_sigma.sh --check   verify every backend by converting a canary rule
#
# Why this script exists rather than a line in the README:
#
#   `sigma plugin install <name>` does not work inside a uv tool environment.
#   It shells out to `python -m pip`, and uv tool environments ship without
#   pip, so every plugin install dies with `No module named pip` buried under a
#   CalledProcessError traceback -- which reads like a broken package rather
#   than a missing tool. The backends go in as --with dependencies instead.
#
#   And `--check` converts a real rule rather than importing a module, because
#   an importable backend that cannot convert is exactly the failure this is
#   meant to catch. See ADR 0002.

set -euo pipefail

SKILL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CANARY="${SKILL_DIR}/assets/canary.sigma.yml"

BACKENDS=(
  pysigma-backend-splunk
  pySigma-backend-kusto
  pysigma-backend-elasticsearch
  pysigma-backend-crowdstrike
)

# target:pipeline pairs covering one dialect per platform family.
CHECKS=(
  "splunk:splunk_windows"
  "kusto:microsoft_xdr"
  "esql:ecs_windows"
  "log_scale:crowdstrike_falcon"
)

# Targets needing --disable-pipeline-check: the ECS pipelines map their fields
# correctly but never registered themselves against these targets. Kept in sync
# with TARGETS in huntkit/config.py, where the same fact drives convert.py.
OVERRIDE_TARGETS=" esql elastalert "

find_sigma() {
  if command -v sigma >/dev/null 2>&1; then
    command -v sigma
  elif [ -x "${HOME}/.local/bin/sigma" ]; then
    echo "${HOME}/.local/bin/sigma"
  else
    return 1
  fi
}

install_sigma() {
  if ! command -v uv >/dev/null 2>&1; then
    echo "uv is required and was not found. See https://docs.astral.sh/uv/" >&2
    exit 1
  fi

  local args=(tool install sigma-cli --force)
  for backend in "${BACKENDS[@]}"; do
    args+=(--with "$backend")
  done

  echo "Installing sigma-cli with ${#BACKENDS[@]} backends..."
  uv "${args[@]}"

  if ! find_sigma >/dev/null; then
    echo "sigma-cli installed but the executable was not found." >&2
    echo "Run 'uv tool update-shell' and open a new shell." >&2
    exit 1
  fi

  echo
  echo "Installed. Verify with: $0 --check"
}

check_backends() {
  local sigma
  if ! sigma="$(find_sigma)"; then
    echo "sigma not found. Run '$0' first." >&2
    exit 1
  fi

  if [ ! -f "$CANARY" ]; then
    echo "Canary rule missing: $CANARY" >&2
    echo "The skill directory is incomplete; reinstall it." >&2
    exit 1
  fi

  echo "Using $sigma"
  echo "Linting the canary rule..."
  local lint_output lint_failed=0
  # Capture rather than discard. A non-zero exit here is usually NOT a bad rule
  # -- a corrupt plugin cache reports the same way -- so swallowing stderr sends
  # the reader off to fix the wrong thing.
  if ! lint_output="$("$sigma" check "$CANARY" 2>&1)"; then
    echo "  FAILED - sigma check exited non-zero. Its output was:" >&2
    printf '%s\n' "$lint_output" | sed 's/^/      /' >&2
    lint_failed=1
  else
    echo "  ok"
  fi
  echo

  # Deliberately NOT fatal. The whole point of --check is a complete picture of
  # which backends work, and lint failures here are usually environmental (a
  # cache pySigma cannot open) rather than a broken rule. Aborting turned one
  # environment problem into zero information about four backends.
  if [ "$lint_failed" -eq 1 ]; then
    echo "Lint failed; checking the backends anyway so you get the full picture." >&2
    echo >&2
  fi

  local failures=0
  for check in "${CHECKS[@]}"; do
    local target="${check%%:*}"
    local pipeline="${check##*:}"
    local extra=()
    case "$OVERRIDE_TARGETS" in *" $target "*) extra+=(--disable-pipeline-check) ;; esac

    printf '%-12s ' "$target"
    local output err_file
    err_file="$(mktemp)"
    # A backend that fails must not stop the ones after it: the point of the
    # check is a complete picture of what works. Its stderr is kept and shown,
    # because "FAILED" with no reason is barely better than silence.
    # "${extra[@]+...}" guards the expansion: under `set -u`, bash 3.2 (which
    # is what macOS ships) treats an empty array as unbound and aborts.
    if ! output="$("$sigma" convert -t "$target" -p "$pipeline" ${extra[@]+"${extra[@]}"} "$CANARY" 2>"$err_file")"; then
      echo "FAILED"
      { grep -E '^Error:' "$err_file" || tail -n 1 "$err_file"; } | sed 's/^/             /' >&2
      rm -f "$err_file"
      failures=$((failures + 1))
      continue
    fi
    rm -f "$err_file"
    # Exit 0 with no query is the silent failure this check exists for.
    if [ -z "${output//[[:space:]]/}" ]; then
      echo "FAILED (exited 0 but produced no query)"
      failures=$((failures + 1))
      continue
    fi
    echo "ok  ${#output} chars via $pipeline"
  done

  echo
  if [ "$failures" -gt 0 ]; then
    echo "$failures of ${#CHECKS[@]} backends failed. Re-run '$0' to reinstall." >&2
    exit 1
  fi
  echo "All ${#CHECKS[@]} backends convert correctly."
  if [ "$lint_failed" -eq 1 ]; then
    echo "NOTE: every backend converts, but 'sigma check' failed -- likely a" >&2
    echo "      cache or permissions problem rather than a rule problem." >&2
    exit 1
  fi
}

case "${1:-install}" in
  --check) check_backends ;;
  install) install_sigma ;;
  *)
    echo "Usage: $0 [--check]" >&2
    exit 2
    ;;
esac

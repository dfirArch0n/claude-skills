#!/usr/bin/env bash
# Second-AI review via codex (CLAUDE.md step 4), with a loud preflight.
#
# Why the preflight exists: a broken codex install fails SILENTLY. A dangling
# Homebrew symlink produces exit 137 (SIGKILL) and zero bytes of output, which
# is easy to mistake for "the review found nothing". Every failure mode below
# is therefore checked explicitly and reported before any work is sent.
#
# Usage:
#   scripts/codex-review.sh --check          preflight only, run it any time
#   scripts/codex-review.sh [BASE]           review current branch vs BASE (default: main)
#
# Env overrides:
#   CODEX_SANDBOX=read-only   review without letting codex execute anything
#   CODEX_EFFORT=low          cheaper/faster, worse review
#
# The reviewer runs in the `workspace-write` sandbox so it can RUN THE TESTS.
# Under `read-only` it cannot create temp files, so pytest fails to start and the
# review silently degrades to static analysis -- findings become hypotheses
# rather than verdicts. That is a much weaker review, and it is not obvious from
# the output that it happened.
#
# The cost is that codex can write to the worktree. The prompt forbids edits and
# the tree is checked afterwards, but this is the trade being made deliberately.
#
# Exits 0 only if codex actually ran and produced a non-trivial review.

set -uo pipefail

RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; BLD=$'\033[1m'; RST=$'\033[0m'
ok()   { printf '%s  ok  %s %s\n' "$GRN" "$RST" "$1"; }
warn() { printf '%s warn %s %s\n' "$YEL" "$RST" "$1"; }
die()  { printf '\n%s%sFAIL%s %s\n' "$BLD" "$RED" "$RST" "$1" >&2
         [ $# -gt 1 ] && printf '      %s\n' "$2" >&2
         exit 1; }

# --- preflight --------------------------------------------------------------

preflight() {
  printf '%scodex preflight%s\n' "$BLD" "$RST"

  local bin
  if ! bin=$(command -v codex 2>/dev/null); then
    # `command -v` silently skips a dangling symlink and walks on, so a purged
    # install masquerades as "never installed" and sends you to the wrong fix.
    # Scan PATH ourselves for a codex entry that exists as a link but not as a
    # target, and name the real problem.
    local d
    while IFS= read -r d; do
      [ -n "$d" ] || continue
      if [ -L "$d/codex" ] && [ ! -e "$d/codex" ]; then
        die "codex symlink is dangling: $d/codex -> $(readlink "$d/codex")" \
            "The binary was purged (a failed cask upgrade does this).
      Fix:  brew reinstall --cask codex"
      fi
    done < <(printf '%s\n' "${PATH//:/$'\n'}")
    die "codex is not on PATH." "Install it:  brew install --cask codex"
  fi
  ok "on PATH: $bin"

  # A Homebrew cask upgrade can leave the symlink pointing at a purged version.
  # -e follows symlinks, so this catches the dangling case that bit us before.
  [ -e "$bin" ] \
    || die "codex symlink is dangling: $bin -> $(readlink "$bin" 2>/dev/null)" \
           "The binary was removed. Fix:  brew reinstall --cask codex"
  [ -x "$bin" ] || die "codex is not executable: $bin"
  ok "binary resolves and is executable"

  # Capture rather than stream, so an empty-but-zero-exit result is detectable.
  local ver rc
  ver=$(codex --version 2>&1); rc=$?
  case $rc in
    0) ;;
    127) die "codex exited 127 (not found) despite resolving." "Try:  brew reinstall --cask codex" ;;
    132|133|134|135|136|137|138|139)
        die "codex was KILLED by signal $((rc - 128)) on startup." \
            "Usually macOS Gatekeeper blocking an unsigned binary. Check
      System Settings > Privacy & Security for a blocked-app prompt,
      or run:  brew reinstall --cask codex" ;;
    *) die "codex --version exited $rc: ${ver:-<no output>}" ;;
  esac
  [ -n "$ver" ] || die "codex --version exited 0 but printed nothing." \
                       "The install is broken. Run:  brew reinstall --cask codex"
  ok "responds: $ver"

  if [ -f "$HOME/.codex/auth.json" ]; then
    ok "authenticated"
  else
    die "codex is not authenticated (no ~/.codex/auth.json)." "Run:  codex login"
  fi

  printf '%s%spreflight passed%s\n\n' "$BLD" "$GRN" "$RST"
}

preflight
[ "${1:-}" = "--check" ] && exit 0

# --- build the diff ---------------------------------------------------------

BASE="${1:-main}"
git rev-parse --verify --quiet "$BASE" >/dev/null \
  || die "base ref '$BASE' does not exist."

OUT_DIR="${TMPDIR:-/tmp}/codex-review"
mkdir -p "$OUT_DIR"
STAMP=$(date +%Y%m%d-%H%M%S)
DIFF="$OUT_DIR/$STAMP.diff"
REVIEW="$OUT_DIR/$STAMP.review.md"

# Snapshot the tree. workspace-write lets the reviewer edit files; the prompt
# says not to, and this is how we verify it obeyed.
TREE_BEFORE=$(git status --porcelain)
if [ -n "$TREE_BEFORE" ]; then
  warn "working tree is dirty -- uncommitted changes will not be reviewed,"
  warn "and tampering by the reviewer will be harder to spot."
fi

git diff "$BASE...HEAD" > "$DIFF"
DIFF_LINES=$(wc -l < "$DIFF" | tr -d ' ')
[ "$DIFF_LINES" -gt 0 ] \
  || die "diff against '$BASE' is empty -- nothing to review." \
         "Are you on the feature branch? Current: $(git branch --show-current)"
ok "diff vs $BASE: $DIFF_LINES lines -> $DIFF"

# The diff LEAVES THIS MACHINE and is persisted to a temp file, so scan it
# harder than pre-commit does. This is a coarse net on purpose: a false positive
# costs one manual look, a false negative sends a credential to a third party.
SECRET_PATTERNS=(
  'BEGIN [A-Z ]*PRIVATE KEY'                  # PEM key material
  'ghp_[A-Za-z0-9]{36}'                       # GitHub classic PAT
  'github_pat_[A-Za-z0-9_]{50,}'              # GitHub fine-grained PAT
  'gh[opsu]_[A-Za-z0-9]{36}'                  # other GitHub token classes
  'AKIA[0-9A-Z]{16}'                          # AWS access key id
  'ASIA[0-9A-Z]{16}'                          # AWS temporary key id
  'sk-[A-Za-z0-9_-]{20,}'                     # OpenAI-style secret key
  'xox[baprs]-[A-Za-z0-9-]{10,}'              # Slack token
  'AIza[0-9A-Za-z_-]{35}'                     # Google API key
  'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}' # JWT
  '(api[_-]?key|secret|passwd|password|token)["'"'"']?\s*[:=]\s*["'"'"'][^"'"'"'[:space:]]{8,}'
)
# op:// references are pointers, not values, and are committed on purpose -- but
# they must be excluded SURGICALLY. Dropping every line that mentions op:// would
# let a real credential hide on the same line as an op:// comment:
#
#   API_TOKEN = "ghp_REAL..."   # TODO: migrate to op://Private/x/y
#
# So blank out just the op:// reference itself, then scan what is left. Line
# numbers are preserved, so reported hits still point at the real line.
SCAN="$OUT_DIR/$STAMP.scan"
sed -e 's#op://[^[:space:]"'"'"'`]*#<op-reference>#g' "$DIFF" > "$SCAN"

HITS=""
for pat in "${SECRET_PATTERNS[@]}"; do
  # The pattern list in this script matches itself; exclude only that.
  if MATCH=$(grep -nEI -e "$pat" "$SCAN" | grep -v 'SECRET_PATTERNS' | head -3); then
    [ -n "$MATCH" ] && HITS+="  [$pat]
$MATCH
"
  fi
done
rm -f "$SCAN"
if [ -n "$HITS" ]; then
  die "diff may contain secrets. Refusing to send it to codex.
$HITS" \
      "Review the lines above. If they are false positives, send the review
      manually, or narrow the diff. File: $DIFF"
fi
ok "secret scan clean (${#SECRET_PATTERNS[@]} patterns)"

# --- run --------------------------------------------------------------------

# The prompt lives in its own file, per CLAUDE.md: prompts are versioned and
# reviewable on their own, and editing what the reviewer is asked should not
# mean editing the runner. Read rather than inlined so a diff of the prompt is
# legible as a diff of the prompt.
PROMPT_FILE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/review-prompt.md"
[ -f "$PROMPT_FILE" ] \
  || die "review prompt missing: $PROMPT_FILE" \
         "The review would run with no instructions and produce something
      that looks like a review but is not the one asked for."
PROMPT="$(cat "$PROMPT_FILE")"
[ -n "${PROMPT//[[:space:]]/}" ] || die "review prompt is empty: $PROMPT_FILE"

SANDBOX="${CODEX_SANDBOX:-workspace-write}"
EFFORT="${CODEX_EFFORT:-high}"
printf '%srunning codex review%s (sandbox=%s, effort=%s; takes a few minutes)\n' \
  "$BLD" "$RST" "$SANDBOX" "$EFFORT"
[ "$SANDBOX" = "read-only" ] && \
  warn "read-only: the reviewer CANNOT run the tests. Findings are static analysis only."

START=$(date +%s)
codex exec \
  --sandbox "$SANDBOX" \
  -c model_reasoning_effort="$EFFORT" \
  --skip-git-repo-check \
  "$PROMPT" 2>&1 | tee "$REVIEW"
RC=${PIPESTATUS[0]}
ELAPSED=$(( $(date +%s) - START ))

# --- verify it actually ran -------------------------------------------------

printf '\n%sverifying%s\n' "$BLD" "$RST"

if [ "$RC" -ge 128 ]; then
  die "codex was KILLED by signal $((RC - 128)) after ${ELAPSED}s." \
      "Partial output (if any): $REVIEW"
elif [ "$RC" -ne 0 ]; then
  die "codex exited $RC after ${ELAPSED}s." "Output: $REVIEW"
fi
ok "exit 0 after ${ELAPSED}s"

BYTES=$(wc -c < "$REVIEW" | tr -d ' ')
[ "$BYTES" -ge 200 ] \
  || die "codex exited 0 but produced only ${BYTES} bytes -- it did not review anything." \
         "This is the silent-failure case. Output: $REVIEW"
ok "review is ${BYTES} bytes -> $REVIEW"

grep -qiE 'issue|nitpick|finding|correct|line [0-9]|\.py' "$REVIEW" \
  || warn "output does not look like a code review -- read it before trusting it."

# Did the reviewer respect "do not modify any file"?
TREE_AFTER=$(git status --porcelain)
if [ "$TREE_BEFORE" != "$TREE_AFTER" ]; then
  printf '\n%s%sFAIL%s the reviewer MODIFIED the working tree.\n' "$BLD" "$RED" "$RST" >&2
  git status --short >&2
  printf '      Review its changes, then `git checkout -- .` to discard them.\n' >&2
  printf '      The review itself is still at: %s\n' "$REVIEW" >&2
  exit 1
fi
ok "reviewer left the working tree unchanged"

# Did it actually run the tests, or quietly skip them?
if grep -qiE 'pytest|passed|test suite' "$REVIEW"; then
  ok "review references running the tests"
else
  warn "no sign the reviewer ran the tests -- its findings may be static analysis only."
fi

printf '\n%s%sreview complete%s  %s\n' "$BLD" "$GRN" "$RST" "$REVIEW"

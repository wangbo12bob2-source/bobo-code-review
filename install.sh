#!/usr/bin/env bash
# -*- coding: utf-8 -*-
# install.sh — Install bobo-code-review skill + review-scan scanner
# Usage: bash install.sh [--uninstall]

set -euo pipefail

CLAUDE_DIR="${CLAUDE_DIR:-$HOME/.claude}"
UNINSTALL=false
[[ "${1:-}" == "--uninstall" ]] && UNINSTALL=true

# --- Uninstall ---
if $UNINSTALL; then
  echo "Uninstalling bobo-code-review..."
  rm -rf "$CLAUDE_DIR/skills/bobo-code-review"
  rm -f  "$CLAUDE_DIR/docs/code-review-workflow-template.md"
  rm -f  "$CLAUDE_DIR/tools/review_scan.py"
  # Remove review-scan wrapper
  for bindir in "$HOME/.local/bin" "$HOME/AppData/Roaming/Python/Python310/Scripts" "/usr/local/bin"; do
    rm -f "$bindir/review-scan" "$bindir/review-scan.cmd" 2>/dev/null || true
  done
  echo "Uninstalled. Remove the CLAUDE.md trigger rules manually if needed."
  exit 0
fi

# --- Determine script directory (repo root) ---
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# --- 1. Skill ---
mkdir -p "$CLAUDE_DIR/skills/bobo-code-review"
cp "$SCRIPT_DIR/skills/bobo-code-review/SKILL.md" "$CLAUDE_DIR/skills/bobo-code-review/SKILL.md"
echo "[OK] Skill → $CLAUDE_DIR/skills/bobo-code-review/SKILL.md"

# --- 2. Docs (methodology template) ---
mkdir -p "$CLAUDE_DIR/docs"
cp "$SCRIPT_DIR/docs/code-review-workflow-template.md" "$CLAUDE_DIR/docs/code-review-workflow-template.md"
echo "[OK] Docs  → $CLAUDE_DIR/docs/code-review-workflow-template.md"

# --- 3. Scanner ---
mkdir -p "$CLAUDE_DIR/tools"
cp "$SCRIPT_DIR/tools/review_scan.py" "$CLAUDE_DIR/tools/review_scan.py"
echo "[OK] Tool  → $CLAUDE_DIR/tools/review_scan.py"

# --- 4. review-scan wrapper ---
install_wrapper() {
  local target="$1"
  if [[ -w "$(dirname "$target")" ]] || mkdir -p "$(dirname "$target")" 2>/dev/null; then
    cat > "$target" << 'WRAPPER'
#!/usr/bin/env python3
import sys, os
sys.argv[0] = os.path.expanduser("~/.claude/tools/review_scan.py")
exec(open(sys.argv[0]).read())
WRAPPER
    chmod +x "$target"
    echo "[OK] Wrapper → $target"
    return 0
  fi
  return 1
}

# Try common PATH locations
WRAPPER_INSTALLED=false
for bindir in "$HOME/.local/bin" "/usr/local/bin"; do
  if install_wrapper "$bindir/review-scan"; then
    WRAPPER_INSTALLED=true
    break
  fi
done

if ! $WRAPPER_INSTALLED; then
  echo "[WARN] Could not auto-install review-scan wrapper."
  echo "       Manually add this to your PATH:"
  echo "       python3 ~/.claude/tools/review_scan.py \"\$@\""
fi

# --- 5. Verify ---
echo ""
echo "=== Verification ==="
if python3 "$CLAUDE_DIR/tools/review_scan.py" --help >/dev/null 2>&1; then
  echo "[OK] review-scan runs successfully"
else
  echo "[WARN] review-scan failed to run — check Python 3 availability"
fi

echo ""
echo "Done! bobo-code-review is installed."
echo ""
echo "Optional: Add these lines to your ~/.claude/CLAUDE.md to enable trigger words:"
echo ""
echo '  # 代码审查触发词'
echo '  当用户说"代码审查"、"review 一下"、"帮我审查"、"CR"时，使用 /bobo-code-review skill。'

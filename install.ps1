# Windows PowerShell install script for bobo-code-review
# Usage: powershell -ExecutionPolicy Bypass -File install.ps1

$ErrorActionPreference = "Stop"
$claudeDir = if ($env:CLAUDE_DIR) { $env:CLAUDE_DIR } else { "$env:USERPROFILE\.claude" }
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# --- Uninstall ---
if ($args -contains "--uninstall") {
    Write-Host "Uninstalling bobo-code-review..."
    Remove-Item -Recurse -Force "$claudeDir\skills\bobo-code-review" -ErrorAction SilentlyContinue
    Remove-Item -Force "$claudeDir\docs\code-review-workflow-template.md" -ErrorAction SilentlyContinue
    Remove-Item -Force "$claudeDir\tools\review_scan.py" -ErrorAction SilentlyContinue
    Write-Host "Uninstalled."
    exit 0
}

# --- 1. Skill ---
New-Item -ItemType Directory -Force -Path "$claudeDir\skills\bobo-code-review" | Out-Null
Copy-Item "$scriptDir\skills\bobo-code-review\SKILL.md" "$claudeDir\skills\bobo-code-review\SKILL.md"
Write-Host "[OK] Skill -> $claudeDir\skills\bobo-code-review\SKILL.md"

# --- 2. Docs ---
New-Item -ItemType Directory -Force -Path "$claudeDir\docs" | Out-Null
Copy-Item "$scriptDir\docs\code-review-workflow-template.md" "$claudeDir\docs\code-review-workflow-template.md"
Write-Host "[OK] Docs  -> $claudeDir\docs\code-review-workflow-template.md"

# --- 3. Scanner ---
New-Item -ItemType Directory -Force -Path "$claudeDir\tools" | Out-Null
Copy-Item "$scriptDir\tools\review_scan.py" "$claudeDir\tools\review_scan.py"
Write-Host "[OK] Tool  -> $claudeDir\tools\review_scan.py"

# --- 4. review-scan.cmd (try Python Scripts dir) ---
$wrapperSrc = "$scriptDir\install\review-scan.cmd"
$wrapperDst = $null

# Find Python Scripts dir
$pyScripts = & py -3 -c "import sysconfig; print(sysconfig.get_path('scripts'))" 2>$null
if ($pyScripts -and (Test-Path $pyScripts)) {
    $wrapperDst = Join-Path $pyScripts "review-scan.cmd"
} elseif (Test-Path "$env:APPDATA\Python\Python310\Scripts") {
    $wrapperDst = "$env:APPDATA\Python\Python310\Scripts\review-scan.cmd"
} else {
    # Fallback: put it next to review_scan.py and add to PATH hint
    $wrapperDst = "$claudeDir\tools\review-scan.cmd"
}

Copy-Item $wrapperSrc $wrapperDst
Write-Host "[OK] Wrapper -> $wrapperDst"

# --- 5. Verify ---
Write-Host ""
Write-Host "=== Verification ==="
$testResult = & py -3 "$claudeDir\tools\review_scan.py" --help 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "[OK] review-scan runs successfully"
} else {
    Write-Host "[WARN] review-scan failed to run — check Python 3 availability"
}

Write-Host ""
Write-Host "Done! bobo-code-review is installed."
Write-Host ""
Write-Host "Optional: Add trigger words to your $claudeDir\CLAUDE.md:"
Write-Host '  当用户说"代码审查"、"review 一下"、"帮我审查"、"CR"时，使用 /bobo-code-review skill。'

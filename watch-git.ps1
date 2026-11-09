# zeno content watcher: автокоммит + пуш при любом изменении файлов в этой папке и подпапках
# (кроме того, что в .gitignore: target/, zeno.toml, *.log и т.п.)
#
# ЗАПУСК:
#   powershell -ExecutionPolicy Bypass -File watch-git.ps1
#   или просто:  .\watch-git.ps1   (из PowerShell в папке zeno)
#
# ОСТАНОВКА: Ctrl+C

param(
    [int]$IntervalSec = 10  # как часто проверять изменения
)

$ErrorActionPreference = "Continue"
Set-Location $PSScriptRoot

Write-Host "zeno git-watcher: слежу за '$PSScriptRoot' (проверка каждые $($IntervalSec) c). Ctrl+C — остановка."

while ($true) {
    Start-Sleep -Seconds $IntervalSec

    $status = git status --porcelain 2>$null
    if (-not $status) { continue }

    git add -A *> $null
    $staged = git diff --cached --name-only 2>$null
    if (-not $staged) { continue }

    $msg = "auto: update $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') - $($staged.Count) file(s)"
    git commit -m $msg *> $null

    if ($LASTEXITCODE -eq 0) {
        Write-Host "[$(Get-Date -Format HH:mm:ss)] commit: $msg"
        git push origin HEAD 2>&1 | ForEach-Object { Write-Host "  $_" }
    }
}

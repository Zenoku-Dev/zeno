# zeno installer for Windows (PowerShell 5.1+).
# Downloads the latest release binary from GitHub Releases.
# Usage (one-liner):
#   powershell -c "irm https://raw.githubusercontent.com/rival-afk/zeno/main/install.ps1 | iex"

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$repo = 'rival-afk/zeno'
$apiUrl = "https://api.github.com/repos/$repo/releases/latest"

if ($env:PROCESSOR_ARCHITECTURE -notmatch 'AMD64|X64|ARM64') {
    Write-Host "[zeno] error: unsupported Windows arch: $env:PROCESSOR_ARCHITECTURE" -ForegroundColor Red
    exit 1
}

Write-Host "[zeno] fetching latest release info..."
try {
    $rel = Invoke-RestMethod -Uri $apiUrl
} catch {
    Write-Host "[zeno] error: cannot reach GitHub API" -ForegroundColor Red
    exit 1
}
if (-not $rel.tag_name) {
    Write-Host "[zeno] error: no releases yet. Tag a fixed tree first:" -ForegroundColor Red
    Write-Host "  git tag v0.2.1 && git push origin v0.2.1"
    exit 1
}
$tag = $rel.tag_name
$asset = $rel.assets | Where-Object { $_.name -like 'zeno-x86_64-pc-windows-msvc.zip' } | Select-Object -First 1
if (-not $asset) {
    Write-Host "[zeno] error: no windows asset in release $tag. Assets found:" -ForegroundColor Red
    $rel.assets | ForEach-Object { Write-Host "  $($_.name)" }
    exit 1
}

Write-Host "[zeno] downloading $($asset.name) ($tag)..."
$tmp = Join-Path $env:TEMP ("zeno-setup-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
$zip = Join-Path $env:TEMP ($asset.name)
Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $zip
Expand-Archive $zip -DestinationPath $tmp -Force
# zip contains a single stage folder
$inner = Get-ChildItem $tmp -Directory | Select-Object -First 1
if ($inner) { $tmp = $inner.FullName }

$installDir = Join-Path $env:LOCALAPPDATA 'Programs\zeno'
New-Item -ItemType Directory -Path $installDir -Force | Out-Null
Copy-Item (Join-Path $tmp 'zeno.exe') $installDir -Force
Copy-Item (Join-Path $tmp 'zeno.toml.example') $env:USERPROFILE -ErrorAction SilentlyContinue

# add install dir to the user PATH (persistent)
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($userPath -notlike "*$installDir*") {
    [Environment]::SetEnvironmentVariable('Path', "$userPath;$installDir", 'User')
    Write-Host "[zeno] added $installDir to user PATH"
}

Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
Remove-Item -Force $zip -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "[zeno] done! installed $tag -> $installDir\zeno.exe" -ForegroundColor Green
Write-Host "[zeno] NOTE: open a NEW PowerShell window so that PATH is refreshed"
Write-Host "[zeno] quick start:"
Write-Host "       zeno scan C:\path\to\file-or-folder"
Write-Host "       zeno check     # availability of open databases"
Write-Host "       zeno engines   # list configured engines"
Write-Host "[zeno] optional config: $env:USERPROFILE\.zeno\config.toml (see $env:USERPROFILE\zeno.toml.example)"

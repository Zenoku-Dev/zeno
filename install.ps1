# zeno installer for Windows (PowerShell 5.1+).
# Usage (one-liner):
#   powershell -c "irm https://raw.githubusercontent.com/rival-afk/zeno/main/install.ps1 | iex"

$ErrorActionPreference = 'Stop'

Write-Host "[zeno] installer for Windows"

# --- ensure git or fall back to zip download ---
$useGit = $true
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    $useGit = $false
}

# --- fetch sources to temp ---
$tmp = Join-Path $env:TEMP ("zeno-setup-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
if ($useGit) {
    git clone --depth 1 https://github.com/rival-afk/zeno.git $tmp
} else {
    Write-Host "[zeno] git not found - downloading source zip"
    $zip = "$tmp.zip"
    New-Item -ItemType Directory -Path $tmp -Force | Out-Null
    Invoke-WebRequest 'https://github.com/rival-afk/zeno/archive/refs/heads/main.zip' -OutFile $zip
    Expand-Archive $zip -DestinationPath $tmp -Force
    $inner = Get-ChildItem $tmp -Directory | Select-Object -First 1
    $tmp = $inner.FullName
}

# --- build helper ---
function Install-Zeno($cargoPath) {
    $env:Path = "$cargoPath;$env:Path"
    Write-Host "[zeno] building (takes a few minutes on first run)..."
    & cargo install --path $tmp || $false
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[zeno] cargo build has failed - showing compiler errors above" -ForegroundColor Red
        exit 1
    }
}

# --- ensure rust toolchain (GNU toolchain: no Visual Studio required) ---
$cargo = Get-Command cargo -ErrorAction SilentlyContinue
if ($cargo) {
    Install-Zeno (Split-Path $cargo.Source)
} else {
    Write-Host "[zeno] rust is not installed - installing via rustup (GNU toolchain, no Visual Studio needed)"
    $rustupInit = Join-Path $env:TEMP 'rustup-init.exe'
    Invoke-WebRequest 'https://win.rustup.rs/x86_64' -OutFile $rustupInit
    & $rustupInit -y --profile minimal --default-host x86_64-pc-windows-gnu --default-toolchain stable-gnu
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[zeno] rustup install failed" -ForegroundColor Red
        exit 1
    }
    $cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'

    # make PATH update persistent for the user
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (($userPath -notlike "*$cargoBin*")) {
        [Environment]::SetEnvironmentVariable('Path', "$userPath;$cargoBin", 'User')
    }
    Install-Zeno $cargoBin
}

Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "[zeno] done! Binary in: $env:USERPROFILE\.cargo\bin\zeno.exe" -ForegroundColor Green
Write-Host "[zeno] NOTE: open a NEW PowerShell window so that PATH is refreshed"
Write-Host "[zeno] quick start:"
Write-Host "       zeno scan C:\path\to\file-or-folder"
Write-Host "       zeno check     # availability of open databases"
Write-Host "       zeno engines   # list configured engines"
Write-Host "[zeno] optional config: $env:USERPROFILE\.zeno\config.toml (see zeno.toml.example in repo)"

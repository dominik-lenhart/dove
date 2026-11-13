<#
.SYNOPSIS
Installs the Dove command line (dove.exe) on Windows.

.DESCRIPTION
Downloads a release zip from GitHub, verifies its SHA-256 against SHA256SUMS (and SHA256SUMS against the release
signing key when `minisign` is on PATH), installs dove.exe into %LOCALAPPDATA%\Programs\Dove and adds that directory
to your user PATH. No administrator rights are needed. Nothing that was downloaded is ever run by this script.

    irm https://github.com/dominik-lenhart/dove/releases/latest/download/install.ps1 | iex

For a specific version:  $env:DOVE_VERSION = '0.4.0'; irm https://github.com/dominik-lenhart/dove/releases/latest/download/install.ps1 | iex

Options are environment variables (a `param` block would not survive `irm | iex`):

    DOVE_VERSION        X.Y.Z (or vX.Y.Z); default: the latest release
    DOVE_INSTALL_DIR    target directory; default: %LOCALAPPDATA%\Programs\Dove
    DOVE_NO_PATH        set to 1 to leave the user PATH alone
    DOVE_DOWNLOAD_BASE  testing only: replaces https://github.com/dominik-lenhart/dove/releases/download
                        (files are fetched from <base>/<tag>/<file>; DOVE_VERSION is then required)

.NOTES
Without `minisign` only the SHA-256 from the same release is verified. That protects against corruption, not against
a compromised release. Install minisign and run the script again, or verify by hand: docs/releasing.md.
#>
# Everything runs in its own scope, so `irm | iex` leaves no function, variable, strict mode or error preference
# behind in your session.
& {
[CmdletBinding()]
param(
    [string]$Version = $env:DOVE_VERSION,
    [string]$InstallDir = $env:DOVE_INSTALL_DIR,
    [string]$DownloadBase = $env:DOVE_DOWNLOAD_BASE,
    [bool]$NoPath = ($env:DOVE_NO_PATH -eq '1')
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$Repo = 'dominik-lenhart/dove'
# Release signing key (same as deploy/release/minisign.pub).
$PublicKey = 'RWQRx2ysvLhSBINGxR3uV9awNjRzHTcz6NUppfFhP2OBdhxTETjz+zGr'

function Invoke-InstallFailure([string]$Message) {
    throw "dove install: $Message"
}

# Windows PowerShell 5.1 does not negotiate TLS 1.2 by default.
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch {
    Write-Verbose 'Could not set TLS 1.2 explicitly; relying on the platform default.'
}

# Plain HTTP is accepted only for an explicit DOVE_DOWNLOAD_BASE (tests).
$customBase = [bool]$DownloadBase

function Get-File([string]$Url, [string]$Path) {
    if (-not $customBase -and -not $Url.StartsWith('https://')) {
        Invoke-InstallFailure "refusing a non-HTTPS download: $Url"
    }
    try {
        Invoke-WebRequest -UseBasicParsing -Uri $Url -OutFile $Path
    } catch {
        Invoke-InstallFailure "download failed: $Url ($($_.Exception.Message))"
    }
}

# ---- platform ----------------------------------------------------------------------------------------------
# Releases are built for x86_64 only. Windows on ARM runs them through its x64 emulation.
$arch = $env:PROCESSOR_ARCHITEW6432
if (-not $arch) { $arch = $env:PROCESSOR_ARCHITECTURE }
if (-not $arch) { $arch = [string][System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture }
if ($arch -notin @('AMD64', 'X64', 'ARM64', 'Arm64')) {
    Invoke-InstallFailure "unsupported CPU architecture: $arch (x64 only; Windows on ARM runs the x64 build)"
}
$target = 'x86_64-pc-windows-msvc'

# ---- version -----------------------------------------------------------------------------------------------
if (-not $Version) {
    if ($customBase) { Invoke-InstallFailure 'DOVE_VERSION is required with DOVE_DOWNLOAD_BASE' }
    try {
        $latest = Invoke-RestMethod -UseBasicParsing -Uri "https://api.github.com/repos/$Repo/releases/latest" -Headers @{ Accept = 'application/vnd.github+json' }
    } catch {
        Invoke-InstallFailure "cannot resolve the latest release ($($_.Exception.Message))"
    }
    $Version = [string]$latest.tag_name
}
$Version = $Version -replace '^v', ''
if ($Version -notmatch '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$') { Invoke-InstallFailure "invalid version: $Version" }
$tag = "v$Version"
$name = "dove-$tag-$target"
if (-not $DownloadBase) { $DownloadBase = "https://github.com/$Repo/releases/download" }
$base = "$($DownloadBase.TrimEnd('/'))/$tag"

# ---- install directory -------------------------------------------------------------------------------------
if (-not $InstallDir) {
    if (-not $env:LOCALAPPDATA) { Invoke-InstallFailure 'LOCALAPPDATA is not set; set DOVE_INSTALL_DIR' }
    $InstallDir = Join-Path $env:LOCALAPPDATA 'Programs\Dove'
}

# ---- download ----------------------------------------------------------------------------------------------
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('dove-install-' + [System.Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    Write-Output "Installing dove $Version ($target) to $InstallDir"
    $zipPath = Join-Path $tmp "$name.zip"
    $sumsPath = Join-Path $tmp 'SHA256SUMS'
    $sigPath = Join-Path $tmp 'SHA256SUMS.minisig'
    Get-File "$base/$name.zip" $zipPath
    Get-File "$base/SHA256SUMS" $sumsPath
    Get-File "$base/SHA256SUMS.minisig" $sigPath

    # ---- verify --------------------------------------------------------------------------------------------
    $minisign = Get-Command minisign -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($minisign) {
        $out = (& $minisign.Source -V -P $PublicKey -m $sumsPath -x $sigPath 2>&1 | Out-String)
        if ($LASTEXITCODE -ne 0) { Invoke-InstallFailure 'signature verification FAILED for SHA256SUMS; not installing' }
        # The trusted comment must be exactly "dove <tag>": a substring match would accept "dove v1.2.3-rc.1".
        $lines = @($out -split "`r?`n" | ForEach-Object { $_.TrimEnd() })
        if (-not ($lines -ccontains "Trusted comment: dove $tag")) {
            Invoke-InstallFailure "signature is valid but is not for dove $tag (wrong or replayed release); not installing"
        }
        Write-Output "Signature OK (minisign, dove $tag)"
    } else {
        Write-Output 'Note: minisign is not installed, so the signature was NOT checked. Only the SHA-256 from the same release is'
        Write-Output '      verified. Install minisign and run this script again, or verify by hand: see docs/releasing.md.'
    }

    $expected = @(Get-Content -LiteralPath $sumsPath | ForEach-Object {
            if ($_ -match '^([0-9a-fA-F]{64}) [ *](.+)$' -and $Matches[2] -ceq "$name.zip") { $Matches[1].ToLowerInvariant() }
        })
    if ($expected.Count -eq 0) { Invoke-InstallFailure "$name.zip is not listed in SHA256SUMS" }
    if ($expected.Count -gt 1) { Invoke-InstallFailure "SHA256SUMS lists $name.zip more than once" }
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $zipPath).Hash.ToLowerInvariant()
    if ($actual -ne $expected[0]) {
        Invoke-InstallFailure "SHA-256 mismatch for $name.zip (expected $($expected[0]), got $actual); not installing"
    }
    Write-Output 'SHA-256 OK'

    # ---- install -------------------------------------------------------------------------------------------
    # Take exactly one member by its full name; nothing else is extracted.
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $newExe = Join-Path $tmp 'dove.exe'
    $zip = [System.IO.Compression.ZipFile]::OpenRead($zipPath)
    try {
        $entry = $zip.GetEntry("$name/dove.exe")
        if (-not $entry) { Invoke-InstallFailure "the archive does not contain $name/dove.exe" }
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $newExe, $true)
    } finally {
        $zip.Dispose()
    }

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $dest = Join-Path $InstallDir 'dove.exe'
    # Copy next to the target first, then rename over it. A running dove.exe cannot be overwritten on Windows, but it
    # can be renamed aside; the old copy is removed when nothing holds it any more.
    $staged = Join-Path $InstallDir ".dove.new.$PID.exe"
    Copy-Item -LiteralPath $newExe -Destination $staged -Force
    $aside = $null
    try {
        if (Test-Path -LiteralPath $dest) {
            $aside = Join-Path $InstallDir ".dove.old.$PID.exe"
            Move-Item -LiteralPath $dest -Destination $aside -Force
        }
        Move-Item -LiteralPath $staged -Destination $dest -Force
    } catch {
        if ($aside -and -not (Test-Path -LiteralPath $dest)) { Move-Item -LiteralPath $aside -Destination $dest -Force }
        Remove-Item -LiteralPath $staged -Force -ErrorAction SilentlyContinue
        Invoke-InstallFailure "cannot write $dest ($($_.Exception.Message))"
    }
    if ($aside) { Remove-Item -LiteralPath $aside -Force -ErrorAction SilentlyContinue }
    Write-Output "Installed $dest"
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
}

# ---- PATH --------------------------------------------------------------------------------------------------
function Test-OnPath([string]$PathList, [string]$Dir) {
    $want = $Dir.TrimEnd('\')
    foreach ($p in ($PathList -split ';')) {
        if ($p.TrimEnd('\') -ieq $want) { return $true }
    }
    return $false
}

if (-not $NoPath) {
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not $userPath) { $userPath = '' }
    if (-not (Test-OnPath $userPath $InstallDir)) {
        $newPath = if ($userPath) { $userPath.TrimEnd(';') + ';' + $InstallDir } else { $InstallDir }
        [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
        Write-Output "Added $InstallDir to your user PATH. Open a new terminal to use it."
    }
    if (-not (Test-OnPath $env:Path $InstallDir)) { $env:Path = $env:Path.TrimEnd(';') + ';' + $InstallDir }
} elseif (-not (Test-OnPath $env:Path $InstallDir)) {
    Write-Output "Note: $InstallDir is not in your PATH."
}

Write-Output @"

Next steps:
  dove --version
  Run Dove on this computer:  dove local init   (see https://github.com/$Repo#readme)
  Later upgrades:             dove upgrade
"@
}

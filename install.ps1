# Installs mx-detective for the current user, without administrator rights.
#
#   irm https://raw.githubusercontent.com/mottipython/mx-detective/master/install.ps1 | iex
#
# To install a specific version instead of the latest:
#
#   & ([scriptblock]::Create((irm https://raw.githubusercontent.com/mottipython/mx-detective/master/install.ps1))) -Version v1.0.0
#
# It downloads the portable executable from the GitHub release, checks it against the
# release's SHA256SUMS.txt, copies it to the install folder and adds that folder to your
# user PATH. Run it again at any time to update.
param(
    [string]$Version = 'latest',
    [string]$InstallDir = (Join-Path $env:LOCALAPPDATA 'Programs\mx-detective')
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'   # the progress bar makes downloads much slower in Windows PowerShell 5.1
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$repo = 'mottipython/mx-detective'
$asset = 'mx-detective-windows-x86_64.exe'
$base = if ($Version -eq 'latest') { "https://github.com/$repo/releases/latest/download" }
        else { "https://github.com/$repo/releases/download/$Version" }

$download = Join-Path ([IO.Path]::GetTempPath()) "$asset.download"
Invoke-WebRequest "$base/$asset" -OutFile $download -UseBasicParsing

$sums = [Text.Encoding]::UTF8.GetString((Invoke-WebRequest "$base/SHA256SUMS.txt" -UseBasicParsing).Content)
$line = $sums -split "`r?`n" | Where-Object { $_ -match ([regex]::Escape($asset) + '$') } | Select-Object -First 1
if (-not $line) { Remove-Item $download; throw "SHA256SUMS.txt has no entry for $asset" }
$expected = ($line -split '\s+')[0]
$actual = (Get-FileHash $download -Algorithm SHA256).Hash
if ($actual -ne $expected) {
    Remove-Item $download
    throw "Checksum mismatch for $asset (expected $expected, got $actual). Nothing was installed."
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Move-Item -Force $download (Join-Path $InstallDir 'mx-detective.exe')

$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (($userPath -split ';') -notcontains $InstallDir) {
    [Environment]::SetEnvironmentVariable('Path', (($userPath, $InstallDir | Where-Object { $_ }) -join ';'), 'User')
    $env:Path = "$env:Path;$InstallDir"
}

Write-Host "Installed $(& (Join-Path $InstallDir 'mx-detective.exe') --version) to $InstallDir"
Write-Host 'Try:  mx-detective example.com        (new terminals pick up the PATH change)'

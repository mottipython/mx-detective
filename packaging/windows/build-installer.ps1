# Builds the setup exe from target\release\mx-detective.exe, then installs it silently into a
# temporary folder, runs it, and uninstalls again. Used by the release and CI workflows.
$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$version = (Select-String -Path "$root\Cargo.toml" -Pattern '^version = "(.+)"').Matches[0].Groups[1].Value

New-Item -ItemType Directory -Force -Path "$root\dist" | Out-Null
Copy-Item "$root\target\release\mx-detective.exe" "$root\dist\mx-detective-windows-x86_64.exe" -Force

if (-not (Test-Path "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe")) { choco install innosetup -y --no-progress }
& "${env:ProgramFiles(x86)}\Inno Setup 6\ISCC.exe" "/DAppVersion=$version" "/DExeDir=$root\dist" "$PSScriptRoot\mx-detective.iss"
if ($LASTEXITCODE) { throw 'ISCC failed' }

$setup = "$root\dist\mx-detective-setup-windows-x86_64.exe"
$dir = Join-Path ([IO.Path]::GetTempPath()) 'mx-install-test'
$userPath = { [Environment]::GetEnvironmentVariable('Path', 'User') }
$before = & $userPath

Start-Process $setup -ArgumentList '/VERYSILENT', '/NORESTART', '/MERGETASKS=addtopath', "/DIR=$dir" -Wait
$out = & "$dir\mx-detective.exe" --version
if ($LASTEXITCODE -or $out -notmatch [regex]::Escape($version)) { throw "installed exe reports '$out', expected $version" }
if ((& $userPath) -notlike "*$dir*") { throw 'PATH was not updated' }

Start-Process "$dir\mx-detective.exe" -ArgumentList '--gui' -PassThru   # uninstall must cope with the window open
Start-Sleep 3
Start-Process "$dir\unins000.exe" -ArgumentList '/VERYSILENT' -Wait
if (Test-Path "$dir\mx-detective.exe") { throw 'uninstall left the exe behind' }
if ((& $userPath) -ne $before) { throw 'uninstall did not restore PATH' }
Write-Host "Installer OK: $setup"

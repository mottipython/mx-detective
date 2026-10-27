<#
.SYNOPSIS
  Checks a domain's mail setup with mx-detective and reports what changed since the last run.

.DESCRIPTION
  Shows how a script, an RMM job (NinjaOne and the like) or a scheduled task can use
  mx-detective: one scan, answers read back as values, a pass/fail gate, and drift
  detection against the previous run. Works in Windows PowerShell 5.1 and PowerShell 7.

  Exit code: 0 = healthy and nothing got worse, 1 = a warning or critical finding, or
  something got worse since the last run, 2 = could not run.

  With -SelfTest it instead checks that mx-detective behaves as documented (output,
  exit codes, the comparison engine) and exits 1 if any check fails.

.PARAMETER Domain
  The domain to check.

.PARAMETER Exe
  Path to mx-detective. By default the one on PATH is used; if there is none, the latest
  portable release is downloaded to -StateDir and its SHA256 is verified.

.PARAMETER StateDir
  Where the previous result is kept (one JSON file per domain).

.PARAMETER SelfTest
  Run the assertions instead of the report.

.EXAMPLE
  .\Invoke-MxHealthCheck.ps1 -Domain example.com

.EXAMPLE
  .\Invoke-MxHealthCheck.ps1 -SelfTest -Exe .\mx-detective.exe
#>
[CmdletBinding()]
param(
    [string]$Domain = 'example.com',
    [string]$Exe,
    [string]$StateDir = (Join-Path ([IO.Path]::GetTempPath()) 'mx-detective'),
    [switch]$SelfTest
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $StateDir | Out-Null

function Resolve-MxDetective {
    if ($Exe) { return (Resolve-Path $Exe).Path }
    $found = Get-Command mx-detective -ErrorAction SilentlyContinue
    if ($found) { return $found.Source }

    $dest = Join-Path $StateDir 'mx-detective.exe'
    if (-not (Test-Path $dest)) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $base = 'https://github.com/mottipython/mx-detective/releases/latest/download'
        Write-Host 'mx-detective not found; downloading the latest portable release...'
        Invoke-WebRequest -UseBasicParsing "$base/mx-detective-windows-x86_64.exe" -OutFile $dest
        $sums = (Invoke-WebRequest -UseBasicParsing "$base/SHA256SUMS.txt").Content
        $line = ($sums -split "`n") | Where-Object { $_ -match 'mx-detective-windows-x86_64\.exe' } | Select-Object -First 1
        $want = ($line -split '\s+')[0]
        if ((Get-FileHash $dest -Algorithm SHA256).Hash -ne $want.ToUpper()) {
            Remove-Item $dest
            throw 'Checksum of the download does not match SHA256SUMS.txt'
        }
    }
    return $dest
}

# Runs mx-detective and returns its exit code and stdout. Progress goes to stderr, so it is dropped.
function Invoke-Mx {
    param([string[]]$MxArgs)
    # Windows PowerShell 5.1 raises an error for any native stderr output when this is 'Stop'.
    $ErrorActionPreference = 'Continue'
    $out = & $script:MxExe @MxArgs 2>$null
    [pscustomobject]@{ Code = $LASTEXITCODE; Text = (@($out) -join "`n").Trim() }
}

# "key=value" lines as a hashtable.
function ConvertFrom-Summary {
    param([string]$Text)
    $h = @{}
    foreach ($line in $Text -split "`n") {
        $k, $v = $line.Trim() -split '=', 2
        if ($k) { $h[$k] = $v }
    }
    $h
}

try { $script:MxExe = Resolve-MxDetective } catch { Write-Error $_; exit 2 }

# ---------------------------------------------------------------- self test

if ($SelfTest) {
    $script:failed = 0
    function Assert-That {
        param([string]$Name, [bool]$Condition, [string]$Detail = '')
        if ($Condition) { Write-Host "  PASS  $Name" -ForegroundColor Green }
        else { Write-Host "  FAIL  $Name $Detail" -ForegroundColor Red; $script:failed++ }
    }

    $work = Join-Path $StateDir ('selftest-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    New-Item -ItemType Directory -Path $work | Out-Null
    $scan = @($Domain, '--primary-only', '--no-dnsbl', '--max-time', '120')
    Write-Host "mx-detective self test against $Domain ($script:MxExe)"

    $v = Invoke-Mx @('--version')
    Assert-That 'version prints "mx-detective X.Y.Z"' ($v.Text -match '^mx-detective \d+\.\d+\.\d+') $v.Text

    $json = Invoke-Mx ($scan + '--json')
    Assert-That 'scan exits 0 without --fail-on' ($json.Code -eq 0) "exit $($json.Code)"
    $r = $json.Text | ConvertFrom-Json
    Assert-That '--json parses and names the domain' ($r.domain -eq $Domain)
    Assert-That 'stdout is plain ASCII' (-not ($json.Text -cmatch '[^\x00-\x7F]'))
    Assert-That 'result has findings' (@($r.checks).Count -gt 0)

    $grade = Invoke-Mx ($scan + @('--get', 'grade'))
    Assert-That '--get grade is a letter grade' ($grade.Text -in 'A+', 'A', 'B', 'C', 'D', 'F') $grade.Text

    $sum = ConvertFrom-Summary (Invoke-Mx ($scan + '--summary')).Text
    Assert-That '--summary has the documented keys' (($sum.ContainsKey('score')) -and ($sum.ContainsKey('spf')) -and ($sum.ContainsKey('dmarc_policy')))
    Assert-That '--summary domain matches' ($sum['domain'] -eq $Domain)

    $gate = Invoke-Mx ($scan + @('--fail-on', 'critical', '--quiet'))
    Assert-That '--fail-on gives exit 0 or 1' ($gate.Code -in 0, 1) "exit $($gate.Code)"
    Assert-That 'bad key is a usage error (exit 2)' ((Invoke-Mx @($Domain, '--get', 'nonsense')).Code -eq 2)

    # Comparison: the same result twice, then a copy with an invented critical finding.
    $a = Join-Path $work 'a.json'
    $b = Join-Path $work 'b.json'
    Set-Content -Path $a -Value $json.Text -Encoding ASCII
    $fake = '{"check_id":"SELFTEST_FAKE","category":"SMTP","title":"t","severity":"Critical","message":"m","recommendation":null,"technical_details":null}'
    Set-Content -Path $b -Value ($json.Text -replace '"checks":\s*\[', ('"checks": [' + $fake + ',')) -Encoding ASCII

    $same = ConvertFrom-Summary (Invoke-Mx @('--diff', $a, $a, '--summary')).Text
    Assert-That 'identical results have no changes' ($same['changes'] -eq '0')

    $worse = Invoke-Mx @('--diff', $a, $b, '--summary')
    $w = ConvertFrom-Summary $worse.Text
    Assert-That 'a new critical finding is a regression' ($w['regressions'] -eq '1' -and $w['regression_ids'] -eq 'SELFTEST_FAKE') $worse.Text
    Assert-That '--fail-on regression exits 1 when worse' ((Invoke-Mx @('--diff', $a, $b, '--fail-on', 'regression', '--quiet')).Code -eq 1)

    $better = ConvertFrom-Summary (Invoke-Mx @('--diff', $b, $a, '--summary')).Text
    Assert-That 'a resolved finding is an improvement' ($better['improvements'] -eq '1' -and $better['regressions'] -eq '0')
    Assert-That '--fail-on regression exits 0 when better' ((Invoke-Mx @('--diff', $b, $a, '--fail-on', 'regression', '--quiet')).Code -eq 0)
    Assert-That '--ignore drops the change' ((ConvertFrom-Summary (Invoke-Mx @('--diff', $a, $b, '--ignore', 'SELFTEST', '--summary')).Text)['changes'] -eq '0')

    Assert-That 'a missing baseline is a usage error (exit 2)' ((Invoke-Mx @('--diff', $a, (Join-Path $work 'missing.json'))).Code -eq 2)
    Set-Content -Path (Join-Path $work 'other.json') -Value ($json.Text -replace '"domain":\s*"[^"]*"', '"domain": "example.invalid"') -Encoding ASCII
    Assert-That 'a baseline for another domain is refused (exit 2)' ((Invoke-Mx @('--diff', (Join-Path $work 'other.json'), $a)).Code -eq 2)

    Remove-Item -Recurse -Force $work
    if ($script:failed) { Write-Host "$script:failed check(s) failed" -ForegroundColor Red; exit 1 }
    Write-Host 'All checks passed' -ForegroundColor Green
    exit 0
}

# ------------------------------------------------------------------- report

Write-Host "Checking $Domain with $((Invoke-Mx @('--version')).Text)" -ForegroundColor Cyan
$scan = Invoke-Mx @($Domain, '--json', '--max-time', '180')
if (-not $scan.Text) { Write-Error 'mx-detective returned nothing'; exit 2 }
$r = $scan.Text | ConvertFrom-Json

$color = @{ 'A+' = 'Green'; 'A' = 'Green'; 'B' = 'Cyan'; 'C' = 'Yellow' }[$r.grade]
if (-not $color) { $color = 'Red' }
Write-Host ("`nGrade {0}  ({1}/100)" -f $r.grade, $r.score) -ForegroundColor $color

# Single facts, the way a custom field in an RMM would read them.
$s = ConvertFrom-Summary (Invoke-Mx @($Domain, '--summary', '--max-time', '180')).Text
Write-Host "`nFacts"
[pscustomobject]@{
    MxHosts        = $s['mx_hosts']
    ServersTested  = $s['servers_tested']
    SPF            = "$($s['spf']) ($($s['spf_lookups'])/10 lookups)"
    DMARC          = $s['dmarc_policy']
    DKIMKeys       = $s['dkim_keys']
    MTASTS         = $s['mta_sts']
    DNSSEC         = $s['dnssec']
    DANE           = $s['dane']
    Port25         = $s['port25']
    CertDaysLeft   = $s['cert_days_left']
    Blocklisted    = $s['blocklisted']
} | Format-List

$issues = @($r.checks | Where-Object { $_.severity -in 'Critical', 'Warning' })
if ($issues) {
    Write-Host 'Needs attention'
    $issues | Sort-Object severity | Select-Object severity, check_id, title | Format-Table -AutoSize
}

# Drift: compare with the previous run, offline, then keep this run for next time.
$last = Join-Path $StateDir "$Domain.json"
$now = Join-Path $StateDir "$Domain.new.json"
Set-Content -Path $now -Value $scan.Text -Encoding ASCII
$worse = 0
if (Test-Path $last) {
    $d = ConvertFrom-Summary (Invoke-Mx @('--diff', $last, $now, '--summary')).Text
    Write-Host "Since the last run: $($d['changes']) changes, $($d['regressions']) worse, $($d['improvements']) better"
    if ($d['changes'] -ne '0') { Write-Host (Invoke-Mx @('--diff', $last, $now)).Text }
    $worse = [int]$d['regressions']
} else {
    Write-Host 'First run for this domain: nothing to compare with yet.'
}
Move-Item -Force $now $last

if ($issues -or $worse) { exit 1 }
exit 0

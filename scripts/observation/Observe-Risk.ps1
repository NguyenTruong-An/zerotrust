[CmdletBinding()]
param(
    [switch]$Demo,
    [switch]$Watch,
    [switch]$Open,
    [ValidatePattern('^[1-9][0-9]{0,5}[smh]$')][string]$Since = '30m',
    [ValidateRange(3, 300)][int]$IntervalSeconds = 5,
    [string]$RiskContainer,
    [string]$KeycloakContainer,
    [string]$OutputFile,
    [string]$Python = 'python'
)
$ErrorActionPreference = 'Stop'
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
if (-not $OutputFile) {
    $folder = if ($Demo) { 'preview' } else { 'latest' }
    $OutputFile = Join-Path $repoRoot ".local-legacy/risk-observation/$folder/index.html"
}
$collectorArgs = @('-X', 'utf8', (Join-Path $PSScriptRoot 'observe.py'), '--since', $Since, '--output', $OutputFile)
if ($Demo) { $collectorArgs += '--demo' }
if ($RiskContainer) { $collectorArgs += @('--risk-container', $RiskContainer) }
if ($KeycloakContainer) { $collectorArgs += @('--keycloak-container', $KeycloakContainer) }
& $Python @collectorArgs
if ($LASTEXITCODE -ne 0) { throw 'Khong tao duoc bao cao. Kiem tra Docker/Python va thong bao phia tren.' }
if ($Open) { Invoke-Item -LiteralPath $OutputFile }
if ($Watch) {
    $collectorArgs += @('--watch-seconds', [string]$IntervalSeconds)
    & $Python @collectorArgs
    if ($LASTEXITCODE -ne 0) { throw 'Cong cu theo doi da dung vi loi.' }
}

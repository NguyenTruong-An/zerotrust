[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, Position = 0)]
    [ValidateSet('status', 'inventory', 'doctor', 'config-check', 'start', 'stop', 'logs', 'smoke', 'tls-check', 'renew-crl', 'backup', 'restore-check', 'cleanup-report')]
    [string]$Action,
    [ValidateSet('lab')][string]$Environment = 'lab',
    [string]$Service,
    [string]$BackupPath,
    [ValidateRange(0, 100000)][int]$Tail = 100,
    [switch]$Follow
)
$ErrorActionPreference = 'Stop'
$opsArguments = @('-X', 'utf8', (Join-Path $PSScriptRoot 'zt.py'), $Action, '--environment', $Environment)
if ($Service) { $opsArguments += @('--service', $Service) }
if ($BackupPath) { $opsArguments += @('--backup-path', $BackupPath) }
if ($Action -eq 'logs') { $opsArguments += @('--tail', $Tail) }
if ($Follow) { $opsArguments += '--follow' }
& python @opsArguments
exit $LASTEXITCODE

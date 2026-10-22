param([ValidateSet('start','stop','status','logs','build')][string]$Action = 'status',
      [ValidateSet('frontend','gateway','backend','keycloak','risk','mysql','redis','crl')][string]$Service)
$ErrorActionPreference = 'Stop'
$demoRoot = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$composeArgs = @('compose','--project-name','zerotrust-demo','--project-directory',$demoRoot,'--file',(Join-Path $demoRoot 'compose.yaml'))
if ($Action -eq 'start') { $composeArgs += @('up','-d','--wait','--wait-timeout','240') }
elseif ($Action -eq 'stop') { $composeArgs += @('stop','--timeout','35') }
elseif ($Action -eq 'status') { $composeArgs += 'ps' }
elseif ($Action -eq 'logs') { $composeArgs += @('logs','--tail','100'); if ($Service) { $composeArgs += $Service } }
elseif ($Action -eq 'build') { $composeArgs += 'build'; if ($Service) { $composeArgs += $Service } }
& docker @composeArgs
if ($LASTEXITCODE -ne 0) { throw 'Demo command failed. See docs/setup/TROUBLESHOOTING.md.' }

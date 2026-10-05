[CmdletBinding()]
param(
    [ValidateSet('All', 'Backend', 'Frontend')]
    [string]$Scope = 'All'
)

$ErrorActionPreference = 'Stop'

Push-Location $PSScriptRoot
try {
    if ($Scope -in @('All', 'Backend')) {
        $mavenWrapper = Join-Path $PSScriptRoot 'mvnw.cmd'
        foreach ($pom in @('pom.xml', 'risk-scoring-service/pom.xml', 'keycloak-risk-extension/pom.xml')) {
            Write-Host "Testing $pom"
            & $mavenWrapper --batch-mode --no-transfer-progress -f $pom test
            if ($LASTEXITCODE -ne 0) {
                throw "Tests failed for $pom (exit code $LASTEXITCODE)."
            }
        }
    }

    if ($Scope -in @('All', 'Frontend')) {
        Push-Location (Join-Path $PSScriptRoot 'frontend')
        try {
            if (-not (Test-Path -LiteralPath 'node_modules')) {
                throw 'Frontend dependencies are missing. Run npm ci in frontend first.'
            }
            & npm.cmd run check
            if ($LASTEXITCODE -ne 0) {
                throw "Frontend checks failed (exit code $LASTEXITCODE)."
            }
        }
        finally {
            Pop-Location
        }
    }
    Write-Host "All requested checks passed ($Scope)."
}
finally {
    Pop-Location
}

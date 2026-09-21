[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$repositoryRoot = $PSScriptRoot
$environmentFile = Join-Path $repositoryRoot '.env'

if (-not (Test-Path -LiteralPath $environmentFile)) {
    throw "Missing $environmentFile. Copy .env.example to .env and replace every placeholder."
}

$allowedVariables = @(
    'SPRING_PROFILES_ACTIVE',
    'RISK_DB_URL',
    'RISK_DB_USERNAME',
    'RISK_DB_PASSWORD',
    'RISK_DEVICE_FINGERPRINT_PEPPER',
    'RISK_AUTH_HISTORY_PEPPER',
    'RISK_AUTH_SUBJECT_MEDIUM_MINIMUM',
    'RISK_AUTH_SUBJECT_HIGH_MINIMUM',
    'RISK_AUTH_IP_MEDIUM_MINIMUM',
    'RISK_AUTH_IP_HIGH_MINIMUM',
    'RISK_AUTH_HISTORY_MEDIUM_SCORE',
    'RISK_AUTH_HISTORY_HIGH_SCORE',
    'RISK_NETWORK_INTELLIGENCE_ENABLED',
    'RISK_NETWORK_DEFAULT_SCORE',
    'RISK_NETWORK_ELEVATED_SCORE',
    'RISK_NETWORK_HIGH_SCORE',
    'RISK_NETWORK_TRUSTED_CIDRS',
    'RISK_NETWORK_ELEVATED_CIDRS',
    'RISK_NETWORK_HIGH_RISK_CIDRS',
    'RISK_TEMPORAL_HISTORY_WINDOW',
    'RISK_TEMPORAL_MINIMUM_EVENTS',
    'RISK_TEMPORAL_MAXIMUM_EVENTS',
    'RISK_TEMPORAL_ZONE_ID',
    'RISK_TEMPORAL_HOUR_TOLERANCE',
    'RISK_TEMPORAL_MINIMUM_DAY_FREQUENCY',
    'RISK_TEMPORAL_MINIMUM_HOUR_FREQUENCY',
    'RISK_TEMPORAL_MEDIUM_SCORE',
    'RISK_TEMPORAL_HIGH_SCORE',
    'RISK_REDIS_HOST',
    'RISK_REDIS_PORT',
    'RISK_REDIS_PASSWORD',
    'RISK_REDIS_SSL',
    'RISK_BIND_ADDRESS',
    'RISK_JWT_ISSUER_URI',
    'RISK_JWT_JWK_SET_URI'
)

$values = @{}
foreach ($line in Get-Content -LiteralPath $environmentFile) {
    $trimmed = $line.Trim()
    if ($trimmed.Length -eq 0 -or $trimmed.StartsWith('#')) {
        continue
    }

    $pair = $trimmed.Split('=', 2)
    if ($pair.Length -eq 2 -and $allowedVariables -contains $pair[0]) {
        $values[$pair[0]] = $pair[1]
    }
}

$requiredVariables = @(
    'RISK_DB_URL',
    'RISK_DB_USERNAME',
    'RISK_DB_PASSWORD',
    'RISK_DEVICE_FINGERPRINT_PEPPER',
    'RISK_AUTH_HISTORY_PEPPER',
    'RISK_REDIS_HOST',
    'RISK_REDIS_PORT',
    'RISK_REDIS_PASSWORD',
    'RISK_BIND_ADDRESS',
    'RISK_JWT_ISSUER_URI',
    'RISK_JWT_JWK_SET_URI'
)

foreach ($name in $requiredVariables) {
    if (-not $values.ContainsKey($name) -or [string]::IsNullOrWhiteSpace($values[$name])) {
        throw "Missing required variable $name in $environmentFile."
    }
}

if (-not $values.ContainsKey('SPRING_PROFILES_ACTIVE')) {
    $values['SPRING_PROFILES_ACTIVE'] = 'dev'
}

foreach ($entry in $values.GetEnumerator()) {
    [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, 'Process')
}

& (Join-Path $repositoryRoot 'mvnw.cmd') `
    -f (Join-Path $repositoryRoot 'risk-scoring-service\pom.xml') `
    spring-boot:run

exit $LASTEXITCODE

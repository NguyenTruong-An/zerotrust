[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$ContainerName = 'keycloak-26.7.0',

    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$RealmName = 'DoAn',

    [ValidatePattern('^https?://[^\s/]+(?::\d+)?(?:/.*)?$')]
    [string]$KeycloakUrl = 'http://localhost:8180'
)

$ErrorActionPreference = 'Stop'

$repositoryRoot = $PSScriptRoot
$themeSource = Join-Path $repositoryRoot 'keycloak-theme\zerotrust'

function Wait-KeycloakReady {
    param([int]$TimeoutSeconds = 60)

    $discoveryUrl = "$($KeycloakUrl.TrimEnd('/'))/realms/$RealmName/.well-known/openid-configuration"
    $deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)

    do {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $discoveryUrl -TimeoutSec 3
            if ($response.StatusCode -eq 200) {
                return
            }
        }
        catch {
            # Keycloak may briefly refuse connections while it is starting.
        }

        Start-Sleep -Seconds 2
    } while ([DateTime]::UtcNow -lt $deadline)

    throw "Keycloak did not become ready at '$discoveryUrl' within $TimeoutSeconds seconds."
}

if (-not (Test-Path -LiteralPath $themeSource -PathType Container)) {
    throw "Missing Keycloak theme directory: $themeSource"
}

& docker inspect $ContainerName *> $null
if ($LASTEXITCODE -ne 0) {
    throw "Keycloak container '$ContainerName' is unavailable."
}

Wait-KeycloakReady

& docker cp "$themeSource\." "${ContainerName}:/opt/keycloak/themes/zerotrust"
if ($LASTEXITCODE -ne 0) {
    throw "Could not copy theme into container '$ContainerName'."
}

$environmentJson = & docker inspect --format '{{json .Config.Env}}' $ContainerName
if ($LASTEXITCODE -ne 0) {
    throw "Could not read environment variables from container '$ContainerName'."
}

$containerEnvironment = @{}
foreach ($entry in ($environmentJson | ConvertFrom-Json)) {
    $separatorIndex = $entry.IndexOf('=')
    if ($separatorIndex -gt 0) {
        $containerEnvironment[$entry.Substring(0, $separatorIndex)] = $entry.Substring($separatorIndex + 1)
    }
}

$adminUser = $containerEnvironment['KC_BOOTSTRAP_ADMIN_USERNAME']
if ([string]::IsNullOrWhiteSpace($adminUser)) {
    $adminUser = $containerEnvironment['KEYCLOAK_ADMIN']
}

$adminPassword = $containerEnvironment['KC_BOOTSTRAP_ADMIN_PASSWORD']
if ([string]::IsNullOrWhiteSpace($adminPassword)) {
    $adminPassword = $containerEnvironment['KEYCLOAK_ADMIN_PASSWORD']
}

if ([string]::IsNullOrWhiteSpace($adminUser) -or [string]::IsNullOrWhiteSpace($adminPassword)) {
    throw "Keycloak bootstrap administrator credentials are missing from container '$ContainerName'."
}

$realmConfigured = $false
for ($attempt = 1; $attempt -le 3; $attempt++) {
    $kcadmConfigPath = "/tmp/zerotrust-theme-kcadm-$([Guid]::NewGuid().ToString('N')).config"

    try {
        & docker exec $ContainerName /opt/keycloak/bin/kcadm.sh config credentials `
            --config $kcadmConfigPath `
            --server http://localhost:8080 `
            --realm master `
            --user $adminUser `
            --password $adminPassword

        if ($LASTEXITCODE -eq 0) {
            & docker exec $ContainerName /opt/keycloak/bin/kcadm.sh update "realms/$RealmName" `
                --config $kcadmConfigPath `
                -s 'loginTheme=zerotrust' `
                -s 'internationalizationEnabled=true' `
                -s 'defaultLocale=vi' `
                -s 'supportedLocales=["vi","en"]'

            if ($LASTEXITCODE -eq 0) {
                $realmConfigured = $true
            }
        }
    }
    finally {
        & docker exec $ContainerName /bin/rm -f $kcadmConfigPath *> $null
    }

    if ($realmConfigured) {
        break
    }

    if ($attempt -lt 3) {
        Write-Warning "Realm configuration attempt $attempt failed; retrying with a fresh admin session."
        Start-Sleep -Seconds 2
        Wait-KeycloakReady -TimeoutSeconds 20
    }
}

if (-not $realmConfigured) {
    throw "Could not configure theme for realm '$RealmName' after 3 attempts."
}

& docker restart $ContainerName
if ($LASTEXITCODE -ne 0) {
    throw "Could not restart container '$ContainerName'."
}

Wait-KeycloakReady

Write-Host "Theme 'zerotrust' was installed for realm '$RealmName'."

[CmdletBinding()]
param(
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$ContainerName = 'keycloak-26.7.0',

    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$RealmName = 'DoAn',

    [string]$TargetFlow = 'zerotrust-browser-recovery',

    [string]$RollbackFlow = 'zerotrust-browser',

    [string[]]$BrowserFlowClientIds = @('zerotrust-spa'),

    [ValidatePattern('^https?://[^\s/]+(?::\d+)?(?:/.*)?$')]
    [string]$KeycloakUrl = 'http://localhost:8180',

    [switch]$SkipUserBackfill,

    [switch]$Rollback
)

$ErrorActionPreference = 'Stop'

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

function Set-FlowExecutionRequirement {
    param(
        [Parameter(Mandatory)]$Execution,
        [Parameter(Mandatory)][string]$Requirement,
        [Nullable[int]]$Priority,
        [Parameter(Mandatory)][string]$FlowAlias,
        [Parameter(Mandatory)][string]$AdminApiBase,
        [Parameter(Mandatory)][string]$AccessToken
    )

    $encodedFlowAlias = [Uri]::EscapeDataString($FlowAlias)
    $uri = "$AdminApiBase/authentication/flows/$encodedFlowAlias/executions"
    $effectivePriority = if ($null -eq $Priority) {
        [int]$Execution.priority
    }
    else {
        [int]$Priority
    }
    $body = @{
        id = $Execution.id
        requirement = $Requirement
        priority = $effectivePriority
    } | ConvertTo-Json

    try {
        Invoke-RestMethod `
            -Method Put `
            -Uri $uri `
            -Headers @{ Authorization = "Bearer $AccessToken" } `
            -ContentType 'application/json' `
            -Body $body | Out-Null
    }
    catch {
        throw "Could not set '$($Execution.displayName)' to '$Requirement' with priority '$effectivePriority'. $($_.Exception.Message)"
    }
}

function Get-FlowExecutions {
    param(
        [Parameter(Mandatory)][string]$FlowAlias,
        [Parameter(Mandatory)][string]$AdminApiBase,
        [Parameter(Mandatory)][string]$AccessToken
    )

    $encodedFlowAlias = [Uri]::EscapeDataString($FlowAlias)
    $uri = "$AdminApiBase/authentication/flows/$encodedFlowAlias/executions"
    $response = Invoke-RestMethod `
        -Method Get `
        -Uri $uri `
        -Headers @{ Authorization = "Bearer $AccessToken" }

    # PowerShell 7 preserves top-level JSON arrays as one Object[] value.
    # Enumerate explicitly so callers can filter individual executions.
    $response | ForEach-Object { $_ }
}

function Set-ClientBrowserFlowOverride {
    param(
        [Parameter(Mandatory)][string]$ClientId,
        [Parameter(Mandatory)][string]$FlowAlias,
        [Parameter(Mandatory)][string]$AdminApiBase,
        [Parameter(Mandatory)][string]$AccessToken
    )

    $headers = @{ Authorization = "Bearer $AccessToken" }
    $flowsResponse = Invoke-RestMethod `
        -Method Get `
        -Uri "$AdminApiBase/authentication/flows" `
        -Headers $headers
    $matchingFlows = @($flowsResponse | ForEach-Object { $_ } | Where-Object {
            $_.alias -eq $FlowAlias
        })
    if ($matchingFlows.Count -ne 1) {
        throw "Expected one authentication flow named '$FlowAlias'; found $($matchingFlows.Count)."
    }

    $encodedClientId = [Uri]::EscapeDataString($ClientId)
    $clientsResponse = Invoke-RestMethod `
        -Method Get `
        -Uri "$AdminApiBase/clients?clientId=$encodedClientId" `
        -Headers $headers
    $matchingClients = @($clientsResponse | ForEach-Object { $_ } | Where-Object {
            $_.clientId -eq $ClientId
        })
    if ($matchingClients.Count -ne 1) {
        throw "Expected one client named '$ClientId'; found $($matchingClients.Count)."
    }

    $client = $matchingClients[0]
    $overrides = @{}
    if ($null -ne $client.authenticationFlowBindingOverrides) {
        foreach ($property in $client.authenticationFlowBindingOverrides.PSObject.Properties) {
            $overrides[$property.Name] = $property.Value
        }
    }
    $overrides['browser'] = $matchingFlows[0].id
    $client.authenticationFlowBindingOverrides = $overrides

    Invoke-RestMethod `
        -Method Put `
        -Uri "$AdminApiBase/clients/$($client.id)" `
        -Headers $headers `
        -ContentType 'application/json' `
        -Body ($client | ConvertTo-Json -Depth 20) | Out-Null

    $verifiedClient = Invoke-RestMethod `
        -Method Get `
        -Uri "$AdminApiBase/clients/$($client.id)" `
        -Headers $headers
    if ($verifiedClient.authenticationFlowBindingOverrides.browser -ne $matchingFlows[0].id) {
        throw "Client '$ClientId' browser flow override was not updated to '$FlowAlias'."
    }
}

function Add-MissingMfaRequiredActions {
    param(
        [Parameter(Mandatory)][string]$AdminApiBase,
        [Parameter(Mandatory)][string]$AccessToken
    )

    $updatedUsers = 0
    $first = 0
    $pageSize = 100
    do {
        $pageResponse = Invoke-RestMethod `
            -Method Get `
            -Uri "$AdminApiBase/users?first=$first&max=$pageSize" `
            -Headers @{ Authorization = "Bearer $AccessToken" }
        $pageUsers = @($pageResponse | ForEach-Object { $_ })

        foreach ($user in $pageUsers) {
            if (-not $user.enabled `
                    -or -not [string]::IsNullOrWhiteSpace($user.serviceAccountClientId) `
                    -or $user.username -like 'service-account-*') {
                continue
            }

            $credentialsResponse = Invoke-RestMethod `
                -Method Get `
                -Uri "$AdminApiBase/users/$($user.id)/credentials" `
                -Headers @{ Authorization = "Bearer $AccessToken" }
            $credentialTypes = @($credentialsResponse | ForEach-Object { $_.type })
            $requiredActions = @($user.requiredActions | ForEach-Object { $_ })
            $needsTotp = $credentialTypes -notcontains 'otp' `
                -and $requiredActions -notcontains 'CONFIGURE_TOTP'
            $needsRecoveryCodes = $credentialTypes -notcontains 'recovery-authn-codes' `
                -and $requiredActions -notcontains 'CONFIGURE_RECOVERY_AUTHN_CODES'

            if ($needsTotp) {
                $requiredActions += 'CONFIGURE_TOTP'
            }
            if ($needsRecoveryCodes) {
                $requiredActions += 'CONFIGURE_RECOVERY_AUTHN_CODES'
            }
            if ($needsTotp -or $needsRecoveryCodes) {
                Invoke-RestMethod `
                    -Method Put `
                    -Uri "$AdminApiBase/users/$($user.id)" `
                    -Headers @{ Authorization = "Bearer $AccessToken" } `
                    -ContentType 'application/json' `
                    -Body (@{ requiredActions = $requiredActions } | ConvertTo-Json) | Out-Null
                $updatedUsers++
            }
        }

        $first += $pageUsers.Count
    } while ($pageUsers.Count -eq $pageSize)

    return $updatedUsers
}

& docker inspect $ContainerName *> $null
if ($LASTEXITCODE -ne 0) {
    throw "Keycloak container '$ContainerName' is unavailable."
}

Wait-KeycloakReady

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

$configPath = "/tmp/zerotrust-mfa-recovery-$([Guid]::NewGuid().ToString('N')).config"

try {
    & docker exec $ContainerName /opt/keycloak/bin/kcadm.sh config credentials `
        --config $configPath `
        --server http://localhost:8080 `
        --realm master `
        --user $adminUser `
        --password $adminPassword *> $null
    if ($LASTEXITCODE -ne 0) {
        throw 'Could not authenticate to the Keycloak Admin API.'
    }

    $tokenResponse = Invoke-RestMethod `
        -Method Post `
        -Uri "$($KeycloakUrl.TrimEnd('/'))/realms/master/protocol/openid-connect/token" `
        -ContentType 'application/x-www-form-urlencoded' `
        -Body @{
            client_id = 'admin-cli'
            grant_type = 'password'
            username = $adminUser
            password = $adminPassword
        }
    $adminAccessToken = $tokenResponse.access_token
    if ([string]::IsNullOrWhiteSpace($adminAccessToken)) {
        throw 'Keycloak Admin API did not return an access token.'
    }
    $encodedRealmName = [Uri]::EscapeDataString($RealmName)
    $adminApiBase = "$($KeycloakUrl.TrimEnd('/'))/admin/realms/$encodedRealmName"

    if ($Rollback) {
        & docker exec $ContainerName /opt/keycloak/bin/kcadm.sh update "realms/$RealmName" `
            --config $configPath `
            -s "browserFlow=$RollbackFlow" *> $null
        if ($LASTEXITCODE -ne 0) {
            throw "Could not bind rollback flow '$RollbackFlow'."
        }

        foreach ($clientId in $BrowserFlowClientIds) {
            Set-ClientBrowserFlowOverride `
                -ClientId $clientId `
                -FlowAlias $RollbackFlow `
                -AdminApiBase $adminApiBase `
                -AccessToken $adminAccessToken
        }

        Write-Host "Realm '$RealmName' and clients [$($BrowserFlowClientIds -join ', ')] now use rollback flow '$RollbackFlow'."
        return
    }

    foreach ($actionAlias in @('CONFIGURE_TOTP', 'CONFIGURE_RECOVERY_AUTHN_CODES')) {
        & docker exec $ContainerName /opt/keycloak/bin/kcadm.sh update `
            "authentication/required-actions/$actionAlias" `
            -r $RealmName `
            --config $configPath `
            -s 'enabled=true' *> $null
        if ($LASTEXITCODE -ne 0) {
            throw "Could not enable required action '$actionAlias'."
        }
    }

    try {
        $topLevel = @(Get-FlowExecutions `
                -FlowAlias $TargetFlow `
                -AdminApiBase $adminApiBase `
                -AccessToken $adminAccessToken)
    }
    catch {
        $encodedRollbackFlow = [Uri]::EscapeDataString($RollbackFlow)
        try {
            Invoke-RestMethod `
                -Method Post `
                -Uri "$adminApiBase/authentication/flows/$encodedRollbackFlow/copy" `
                -Headers @{ Authorization = "Bearer $adminAccessToken" } `
                -ContentType 'application/json' `
                -Body (@{ newName = $TargetFlow } | ConvertTo-Json) | Out-Null
            $topLevel = @(Get-FlowExecutions `
                    -FlowAlias $TargetFlow `
                    -AdminApiBase $adminApiBase `
                    -AccessToken $adminAccessToken)
        }
        catch {
            throw "Could not find or create flow '$TargetFlow' from '$RollbackFlow'."
        }
    }

    $riskSubflows = @($topLevel | Where-Object {
            $_.authenticationFlow -eq $true -and $_.displayName -like '*Risk step-up MFA'
        })
    if ($riskSubflows.Count -ne 1) {
        throw "Expected one Risk step-up MFA subflow in '$TargetFlow'; found $($riskSubflows.Count)."
    }

    $subflowAlias = $riskSubflows[0].displayName
    $children = @(Get-FlowExecutions `
            -FlowAlias $subflowAlias `
            -AdminApiBase $adminApiBase `
            -AccessToken $adminAccessToken)

    $otpExecutions = @($children | Where-Object { $_.providerId -eq 'auth-otp-form' })
    if ($otpExecutions.Count -ne 1) {
        throw "Expected one OTP Form; found $($otpExecutions.Count)."
    }
    Set-FlowExecutionRequirement `
        -Execution $otpExecutions[0] `
        -Requirement 'ALTERNATIVE' `
        -Priority 30 `
        -FlowAlias $subflowAlias `
        -AdminApiBase $adminApiBase `
        -AccessToken $adminAccessToken

    $recoveryExecutions = @($children | Where-Object {
            $_.providerId -eq 'auth-recovery-authn-code-form'
    })
    if ($recoveryExecutions.Count -eq 0) {
        $encodedSubflowAlias = [Uri]::EscapeDataString($subflowAlias)
        try {
            Invoke-RestMethod `
                -Method Post `
                -Uri "$adminApiBase/authentication/flows/$encodedSubflowAlias/executions/execution" `
                -Headers @{ Authorization = "Bearer $adminAccessToken" } `
                -ContentType 'application/json' `
                -Body (@{
                        provider = 'auth-recovery-authn-code-form'
                        priority = 50
                    } | ConvertTo-Json) | Out-Null
        }
        catch {
            throw 'Could not add Recovery Authentication Code Form.'
        }
    }

    $children = @(Get-FlowExecutions `
            -FlowAlias $subflowAlias `
            -AdminApiBase $adminApiBase `
            -AccessToken $adminAccessToken)
    $recoveryExecutions = @($children | Where-Object {
            $_.providerId -eq 'auth-recovery-authn-code-form'
        })
    if ($recoveryExecutions.Count -ne 1) {
        throw "Expected one Recovery Authentication Code Form; found $($recoveryExecutions.Count)."
    }
    Set-FlowExecutionRequirement `
        -Execution $recoveryExecutions[0] `
        -Requirement 'ALTERNATIVE' `
        -Priority 50 `
        -FlowAlias $subflowAlias `
        -AdminApiBase $adminApiBase `
        -AccessToken $adminAccessToken

    $verified = @(Get-FlowExecutions `
            -FlowAlias $subflowAlias `
            -AdminApiBase $adminApiBase `
            -AccessToken $adminAccessToken)

    $conditionExecutions = @($verified | Where-Object {
            $_.providerId -eq 'zerotrust-risk-step-up-condition'
        })
    if ($conditionExecutions.Count -ne 1) {
        throw "Expected one ZeroTrust step-up condition; found $($conditionExecutions.Count)."
    }
    Set-FlowExecutionRequirement `
        -Execution $conditionExecutions[0] `
        -Requirement 'REQUIRED' `
        -Priority 10 `
        -FlowAlias $subflowAlias `
        -AdminApiBase $adminApiBase `
        -AccessToken $adminAccessToken

    $verified = @(Get-FlowExecutions `
            -FlowAlias $subflowAlias `
            -AdminApiBase $adminApiBase `
            -AccessToken $adminAccessToken)

    $conditionValid = @($verified | Where-Object {
            $_.providerId -eq 'zerotrust-risk-step-up-condition' `
                -and $_.requirement -eq 'REQUIRED' `
                -and $_.priority -eq 10
        }).Count -eq 1
    $otpValid = @($verified | Where-Object {
            $_.providerId -eq 'auth-otp-form' `
                -and $_.requirement -eq 'ALTERNATIVE' `
                -and $_.priority -eq 30
        }).Count -eq 1
    $recoveryValid = @($verified | Where-Object {
            $_.providerId -eq 'auth-recovery-authn-code-form' `
                -and $_.requirement -eq 'ALTERNATIVE' `
                -and $_.priority -eq 50
        }).Count -eq 1

    if (-not ($conditionValid -and $otpValid -and $recoveryValid)) {
        throw 'Recovery flow verification failed; realm binding was not changed.'
    }

    & docker exec $ContainerName /opt/keycloak/bin/kcadm.sh update "realms/$RealmName" `
        --config $configPath `
        -s "browserFlow=$TargetFlow" *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not bind recovery flow '$TargetFlow'."
    }

    foreach ($clientId in $BrowserFlowClientIds) {
        Set-ClientBrowserFlowOverride `
            -ClientId $clientId `
            -FlowAlias $TargetFlow `
            -AdminApiBase $adminApiBase `
            -AccessToken $adminAccessToken
    }

    $backfilledUsers = 0
    if (-not $SkipUserBackfill) {
        $backfilledUsers = Add-MissingMfaRequiredActions `
            -AdminApiBase $adminApiBase `
            -AccessToken $adminAccessToken
    }

    Write-Host "Realm '$RealmName' now uses MFA recovery flow '$TargetFlow'."
    Write-Host "Client browser flow overrides updated: $($BrowserFlowClientIds -join ', ')."
    Write-Host 'Risk condition: REQUIRED (10); OTP: ALTERNATIVE (30); Recovery Code: ALTERNATIVE (50).'
    if (-not $SkipUserBackfill) {
        Write-Host "Existing regular users updated with missing MFA actions: $backfilledUsers."
    }
    Write-Host "Rollback: .\configure-mfa-recovery-flow.ps1 -Rollback"
}
finally {
    & docker exec $ContainerName /bin/rm -f $configPath *> $null
}

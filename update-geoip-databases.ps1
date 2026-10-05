[CmdletBinding()]
param(
    [string]$TargetDirectory = (Join-Path $PSScriptRoot 'geoip-data')
)

$ErrorActionPreference = 'Stop'

$accountId = [Environment]::GetEnvironmentVariable('MAXMIND_ACCOUNT_ID', 'Process')
$licenseKey = [Environment]::GetEnvironmentVariable('MAXMIND_LICENSE_KEY', 'Process')
if ([string]::IsNullOrWhiteSpace($accountId) -or [string]::IsNullOrWhiteSpace($licenseKey)) {
    throw 'Set MAXMIND_ACCOUNT_ID and MAXMIND_LICENSE_KEY in the current process before updating Geo-IP databases.'
}

$targetPath = [IO.Path]::GetFullPath($TargetDirectory)
New-Item -ItemType Directory -Path $targetPath -Force | Out-Null

$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$temporaryRoot = Join-Path $temporaryBase ("zerotrust-geoip-" + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $temporaryRoot | Out-Null

$credentials = [Convert]::ToBase64String(
    [Text.Encoding]::ASCII.GetBytes("${accountId}:${licenseKey}")
)
$headers = @{ Authorization = "Basic $credentials" }
$editions = @('GeoLite2-City', 'GeoLite2-ASN')

try {
    foreach ($edition in $editions) {
        $archivePath = Join-Path $temporaryRoot "$edition.tar.gz"
        $extractPath = Join-Path $temporaryRoot $edition
        New-Item -ItemType Directory -Path $extractPath | Out-Null

        $downloadUri = "https://download.maxmind.com/geoip/databases/$edition/download?suffix=tar.gz"
        Write-Host "[INFO] Downloading $edition from MaxMind."
        Invoke-WebRequest -Uri $downloadUri -Headers $headers -OutFile $archivePath

        & tar.exe -xzf $archivePath -C $extractPath
        if ($LASTEXITCODE -ne 0) {
            throw "Could not extract $edition archive."
        }

        $database = Get-ChildItem -LiteralPath $extractPath -Recurse -File -Filter "$edition.mmdb" |
            Select-Object -First 1
        if ($null -eq $database -or $database.Length -le 0) {
            throw "Downloaded archive did not contain a valid $edition.mmdb file."
        }

        $destination = Join-Path $targetPath "$edition.mmdb"
        $staging = "$destination.new"
        Copy-Item -LiteralPath $database.FullName -Destination $staging -Force
        Move-Item -LiteralPath $staging -Destination $destination -Force
        Write-Host "[INFO] Updated $destination"
    }
} finally {
    $resolvedTemporaryRoot = [IO.Path]::GetFullPath($temporaryRoot)
    if ($resolvedTemporaryRoot.StartsWith($temporaryBase, [StringComparison]::OrdinalIgnoreCase) -and
            (Split-Path -Leaf $resolvedTemporaryRoot).StartsWith('zerotrust-geoip-')) {
        Remove-Item -LiteralPath $resolvedTemporaryRoot -Recurse -Force -ErrorAction SilentlyContinue
    }
    $headers.Authorization = $null
    $credentials = $null
    $licenseKey = $null
}

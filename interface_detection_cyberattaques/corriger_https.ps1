[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$RuntimeDirectory = Join-Path $ProjectDirectory ".runtime"
$CertificateDirectory = Join-Path $ProjectDirectory "certificates"
$TemporaryCertificate = Join-Path `
    $RuntimeDirectory `
    "SCA-local-root-current.crt"
$PublicCertificate = Join-Path `
    $CertificateDirectory `
    "SCA-local-root.crt"

function Test-Administrator {
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object `
        -TypeName Security.Principal.WindowsPrincipal `
        -ArgumentList $Identity

    return $Principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Invoke-DockerCopy {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination
    )

    $PreviousErrorActionPreference = $ErrorActionPreference
    $NativePreferenceExists = Test-Path `
        -LiteralPath "variable:PSNativeCommandUseErrorActionPreference"

    if ($NativePreferenceExists) {
        $PreviousNativePreference = `
            $PSNativeCommandUseErrorActionPreference
    }

    try {
        $ErrorActionPreference = "Continue"

        if ($NativePreferenceExists) {
            $PSNativeCommandUseErrorActionPreference = $false
        }

        & docker compose cp $Source $Destination *> $null
        return $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $PreviousErrorActionPreference

        if ($NativePreferenceExists) {
            $PSNativeCommandUseErrorActionPreference = `
                $PreviousNativePreference
        }
    }
}

try {
    Write-Host ""
    Write-Host "CORRECTION DU CERTIFICAT HTTPS SCA" `
        -ForegroundColor Cyan
    Write-Host ""

    if (-not (Test-Administrator)) {
        throw "Ce correctif doit etre execute en administrateur."
    }

    Set-Location $ProjectDirectory
    New-Item -ItemType Directory -Path $RuntimeDirectory -Force |
        Out-Null
    New-Item -ItemType Directory -Path $CertificateDirectory -Force |
        Out-Null
    Remove-Item -LiteralPath $TemporaryCertificate -Force `
        -ErrorAction SilentlyContinue

    & docker info *> $null
    if ($LASTEXITCODE -ne 0) {
        throw "Docker Desktop n'est pas operationnel."
    }

    $GatewayRunning = @(
        & docker compose ps --status running --services 2>$null
    ) -contains "gateway"

    if (-not $GatewayRunning) {
        throw (
            "Le conteneur gateway n'est pas actif. " +
            "Lancez d'abord LANCER_TOUT.bat."
        )
    }

    Write-Host "[1/4] Copie du certificat Caddy..." `
        -ForegroundColor Cyan
    $CopyExitCode = Invoke-DockerCopy `
        -Source "gateway:/data/caddy/pki/authorities/local/root.crt" `
        -Destination $TemporaryCertificate

    if (($CopyExitCode -ne 0) -or (-not (
        Test-Path -LiteralPath $TemporaryCertificate -PathType Leaf
    ))) {
        throw "Impossible de copier le certificat depuis gateway."
    }

    $Certificate = New-Object `
        -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 `
        -ArgumentList $TemporaryCertificate
    $Thumbprint = $Certificate.Thumbprint

    if (-not $Thumbprint) {
        throw "Le certificat copie est invalide."
    }

    Write-Host "[2/4] Approbation pour l'utilisateur Windows..." `
        -ForegroundColor Cyan
    Import-Certificate `
        -FilePath $TemporaryCertificate `
        -CertStoreLocation "Cert:\CurrentUser\Root" `
        -ErrorAction Stop |
        Out-Null

    Write-Host "[3/4] Approbation pour l'ordinateur Windows..." `
        -ForegroundColor Cyan
    Import-Certificate `
        -FilePath $TemporaryCertificate `
        -CertStoreLocation "Cert:\LocalMachine\Root" `
        -ErrorAction Stop |
        Out-Null

    foreach ($Store in @(
        "Cert:\CurrentUser\Root",
        "Cert:\LocalMachine\Root"
    )) {
        $InstalledPath = Join-Path $Store $Thumbprint

        if (-not (Test-Path -LiteralPath $InstalledPath)) {
            throw "Le certificat n'apparait pas dans $Store."
        }
    }

    Copy-Item `
        -LiteralPath $TemporaryCertificate `
        -Destination $PublicCertificate `
        -Force

    Write-Host "[4/4] Verification cryptographique de HTTPS..." `
        -ForegroundColor Cyan
    $HealthResponse = & curl.exe `
        --silent `
        --show-error `
        --fail `
        --max-time 15 `
        --cacert $TemporaryCertificate `
        "https://localhost/SCA/_stcore/health"

    if (
        ($LASTEXITCODE -ne 0) -or
        (([string]($HealthResponse -join "`n")).Trim() -ne "ok")
    ) {
        throw "HTTPS repond, mais sa validation cryptographique a echoue."
    }

    Remove-Item -LiteralPath $TemporaryCertificate -Force `
        -ErrorAction SilentlyContinue

    Write-Host ""
    Write-Host "[OK] Certificat SCA approuve et HTTPS valide." `
        -ForegroundColor Green
    Write-Host "Empreinte : $Thumbprint" -ForegroundColor DarkGray
    Write-Host ""
    Write-Host (
        "Fermez TOUTES les fenetres Chrome, puis ouvrez : " +
        "https://localhost/SCA/"
    ) -ForegroundColor Yellow
    exit 0
}
catch {
    Write-Host ""
    Write-Host "[ERREUR] $($_.Exception.Message)" `
        -ForegroundColor Red
    Write-Host ""
    exit 1
}

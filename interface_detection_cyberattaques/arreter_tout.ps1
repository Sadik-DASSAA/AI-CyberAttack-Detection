[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Continue"

$ProjectDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$RuntimeDirectory = Join-Path $ProjectDirectory ".runtime"
$PidFile = Join-Path $RuntimeDirectory "suricata.pid"
$StopRequestFile = Join-Path $RuntimeDirectory "suricata_stop_requested"
$HadError = $false

Set-Location -LiteralPath $ProjectDirectory

Write-Host ""
Write-Host "============================================================" `
    -ForegroundColor Cyan
Write-Host "  SUPERVISION DES CYBERATTAQUES - ARRET COMPLET" `
    -ForegroundColor Cyan
Write-Host "============================================================" `
    -ForegroundColor Cyan
Write-Host ""

Write-Host "[1/3] Arret des services Docker et de HTTPS..." `
    -ForegroundColor Cyan

if ($null -ne (Get-Command docker.exe -ErrorAction SilentlyContinue)) {
    & docker compose down --remove-orphans

    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ATTENTION] Docker n'a pas confirme l'arret." `
            -ForegroundColor Yellow
        $HadError = $true
    }
    else {
        Write-Host "[OK] Services Docker arretes." `
            -ForegroundColor Green

        Write-Host ""
        Write-Host "[2/3] Sauvegarde locale des comptes et de l'historique..." `
            -ForegroundColor Cyan

        & docker compose `
            --profile maintenance `
            run --rm --no-deps data-export

        if ($LASTEXITCODE -ne 0) {
            Write-Host (
                "[ATTENTION] La copie locale n'a pas abouti. " +
                "Les donnees restent conservees dans les volumes Docker."
            ) -ForegroundColor Yellow
            $HadError = $true
        }
        else {
            Write-Host (
                "[OK] Comptes et historique sauvegardes dans les " +
                "dossiers security et history."
            ) -ForegroundColor Green
        }
    }
}
else {
    Write-Host "[ATTENTION] docker.exe est introuvable." `
        -ForegroundColor Yellow
    $HadError = $true
}

Write-Host ""
if ($HadError -and ($null -eq (Get-Command docker.exe -ErrorAction SilentlyContinue))) {
    Write-Host ""
    Write-Host "[2/3] Sauvegarde locale ignoree : Docker indisponible." `
        -ForegroundColor Yellow
}

Write-Host ""
Write-Host "[3/3] Arret de Suricata..." -ForegroundColor Cyan

if (Test-Path -LiteralPath $PidFile -PathType Leaf) {
    $SuricataPid = [int](
        Get-Content -LiteralPath $PidFile -Raw
    )

    $Process = Get-Process `
        -Id $SuricataPid `
        -ErrorAction SilentlyContinue

    if (
        ($null -ne $Process) -and
        ($Process.ProcessName -eq "suricata")
    ) {
        Set-Content `
            -LiteralPath $StopRequestFile `
            -Value "requested" `
            -Encoding ASCII
        Stop-Process -Id $SuricataPid -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2

        if ($null -eq (
            Get-Process -Id $SuricataPid -ErrorAction SilentlyContinue
        )) {
            Write-Host "[OK] Suricata arrete." -ForegroundColor Green
        }
        else {
            Write-Host "[ERREUR] Suricata ne s'est pas arrete." `
                -ForegroundColor Red
            $HadError = $true
        }
    }
    else {
        Write-Host "[OK] Le processus Suricata etait deja arrete." `
            -ForegroundColor Green
    }

    Remove-Item -LiteralPath $PidFile -Force `
        -ErrorAction SilentlyContinue
}
else {
    $UntrackedSuricata = @(
        Get-Process -Name "suricata" -ErrorAction SilentlyContinue
    )

    if ($UntrackedSuricata.Count -gt 0) {
        Write-Host (
            "[ATTENTION] Une instance Suricata non lancee par ce paquet " +
            "reste active. Arretez-la avec Ctrl+C dans sa fenetre."
        ) -ForegroundColor Yellow
    }
    else {
        Write-Host "[OK] Suricata etait deja arrete." `
            -ForegroundColor Green
    }
}

Write-Host ""
Write-Host (
    "Les comptes, les alertes, le modele et l'historique ont ete conserves."
) -ForegroundColor Green

if ($HadError) {
    exit 1
}

exit 0

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$SuricataPath,
    [Parameter(Mandatory)][string]$ConfigPath,
    [Parameter(Mandatory)][string]$CaptureDevice,
    [Parameter(Mandatory)][string]$LogsDirectory,
    [Parameter(Mandatory)][string]$HomeNet,
    [string]$LabRulesPath = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$RuntimeDirectory = Join-Path $ProjectDirectory ".runtime"
$PidFile = Join-Path $RuntimeDirectory "suricata.pid"
$ErrorFile = Join-Path $RuntimeDirectory "suricata_error.txt"
$StopRequestFile = Join-Path $RuntimeDirectory "suricata_stop_requested"

function Initialize-NativePath {
    param([Parameter(Mandatory)][string]$ExecutablePath)

    $SuricataDirectory = Split-Path -Parent $ExecutablePath
    $PathEntries = @()

    foreach ($Scope in @("Machine", "User", "Process")) {
        $ScopedPath = [Environment]::GetEnvironmentVariable(
            "Path",
            $Scope
        )

        if ($ScopedPath) {
            $PathEntries += $ScopedPath -split ";"
        }
    }

    $PathEntries += @(
        $SuricataDirectory,
        (Join-Path $SuricataDirectory "bin"),
        (Join-Path $SuricataDirectory "lib"),
        (Join-Path $SuricataDirectory "usr\bin"),
        (Join-Path $env:SystemRoot "System32\Npcap"),
        (Join-Path $env:SystemRoot "SysWOW64\Npcap")
    )

    $PathEntries += @(
        Get-ChildItem `
            -LiteralPath $SuricataDirectory `
            -Filter "*.dll" `
            -File `
            -Recurse `
            -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty DirectoryName -Unique
    )

    $env:Path = (
        $PathEntries |
            ForEach-Object {
                if ($null -ne $_) {
                    ([string]$_).Trim().Trim('"')
                }
            } |
            Where-Object {
                $_ -and (Test-Path -LiteralPath $_ -PathType Container)
            } |
            Select-Object -Unique
    ) -join ";"
}

function Quote-NativeArgument {
    param([Parameter(Mandatory)][string]$Value)

    return '"' + $Value.Replace('"', '\"') + '"'
}

try {
    Initialize-NativePath -ExecutablePath $SuricataPath

    $Host.UI.RawUI.WindowTitle = (
        "Suricata IDS - Supervision des cyberattaques"
    )

    New-Item -ItemType Directory -Path $RuntimeDirectory -Force |
        Out-Null
    Remove-Item -LiteralPath $ErrorFile -Force `
        -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $StopRequestFile -Force `
        -ErrorAction SilentlyContinue

    Write-Host ""
    Write-Host "============================================================" `
        -ForegroundColor Green
    Write-Host "  SURICATA IDS - CAPTURE EN DIRECT" `
        -ForegroundColor Green
    Write-Host "============================================================" `
        -ForegroundColor Green
    Write-Host "Interface : $CaptureDevice" -ForegroundColor Cyan
    Write-Host "HOME_NET  : $HomeNet" -ForegroundColor Cyan
    Write-Host "Journaux  : $LogsDirectory" -ForegroundColor Cyan
    Write-Host ""
    Write-Host (
        "Utilisez ARRETER_TOUT.bat pour fermer toute la plateforme."
    ) -ForegroundColor Yellow
    Write-Host ""

    $Arguments = @(
        "-c", $ConfigPath,
        "-i", $CaptureDevice,
        "-l", $LogsDirectory,
        "--set", "vars.address-groups.HOME_NET=$HomeNet",
        "--init-errors-fatal",
        "-v"
    )

    if (
        $LabRulesPath -and
        (Test-Path -LiteralPath $LabRulesPath -PathType Leaf)
    ) {
        $Arguments += @("-s", $LabRulesPath)
    }

    $NativeArgumentLine = (
        $Arguments |
            ForEach-Object {
                Quote-NativeArgument -Value ([string]$_)
            }
    ) -join " "

    $SuricataProcess = Start-Process `
        -FilePath $SuricataPath `
        -ArgumentList $NativeArgumentLine `
        -WorkingDirectory (Split-Path -Parent $SuricataPath) `
        -NoNewWindow `
        -PassThru

    Set-Content `
        -LiteralPath $PidFile `
        -Value $SuricataProcess.Id `
        -Encoding ASCII

    $SuricataProcess.WaitForExit()
    $ExitCode = $SuricataProcess.ExitCode

    if (
        ($ExitCode -ne 0) -and
        (-not (Test-Path -LiteralPath $StopRequestFile -PathType Leaf))
    ) {
        throw "Suricata s'est arrete avec le code $ExitCode."
    }
}
catch {
    Remove-Item -LiteralPath $PidFile -Force `
        -ErrorAction SilentlyContinue
    Set-Content `
        -LiteralPath $ErrorFile `
        -Value $_.Exception.Message `
        -Encoding UTF8
    Write-Host ""
    Write-Host "[ERREUR SURICATA] $($_.Exception.Message)" `
        -ForegroundColor Red
    Start-Sleep -Seconds 5
    exit 1
}
finally {
    if (Test-Path -LiteralPath $PidFile -PathType Leaf) {
        Remove-Item -LiteralPath $PidFile -Force `
            -ErrorAction SilentlyContinue
    }

    Remove-Item -LiteralPath $StopRequestFile -Force `
        -ErrorAction SilentlyContinue
}

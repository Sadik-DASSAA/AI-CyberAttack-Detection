[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ProjectDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$RuntimeDirectory = Join-Path $ProjectDirectory ".runtime"
$SuricataRuntimeScript = Join-Path $ProjectDirectory "suricata_runtime.ps1"
$CertificateDirectory = Join-Path $ProjectDirectory "certificates"
$LocalRootCertificate = Join-Path $CertificateDirectory "SCA-local-root.crt"

$SuricataDirectory = "C:\Program Files\Suricata"
$SuricataExecutable = Join-Path $SuricataDirectory "suricata.exe"
$SuricataConfiguration = Join-Path $SuricataDirectory "suricata.yaml"
$SuricataRules = "C:\ProgramData\Suricata\rules\suricata.rules"
$SuricataThresholdConfig = Join-Path $SuricataDirectory "threshold.config"
$LabRules = "C:\ProgramData\Suricata\rules\lab-dashboard.rules"
$PreferredInterfaceAlias = "Wi-Fi"

function Write-Section {
    param([Parameter(Mandatory)][string]$Text)

    Write-Host ""
    Write-Host "============================================================" `
        -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "============================================================" `
        -ForegroundColor Cyan
}

function Write-Step {
    param(
        [Parameter(Mandatory)][int]$Number,
        [Parameter(Mandatory)][string]$Text
    )

    Write-Host ""
    Write-Host "[$Number/6] $Text" -ForegroundColor Cyan
}

function Test-Administrator {
    $Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $Principal = New-Object `
        -TypeName Security.Principal.WindowsPrincipal `
        -ArgumentList $Identity

    return $Principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function Test-DockerEngine {
    & docker info *> $null
    return ($LASTEXITCODE -eq 0)
}

function Get-CertificateThumbprint {
    param([Parameter(Mandatory)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return ""
    }

    try {
        $Certificate = New-Object `
            -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 `
            -ArgumentList $Path
        return $Certificate.Thumbprint
    }
    catch {
        return ""
    }
}

function Invoke-DockerCopy {
    param(
        [Parameter(Mandatory)][string]$Source,
        [Parameter(Mandatory)][string]$Destination
    )

    # Docker Compose ecrit sa progression ("Copying") sur stderr meme quand
    # la copie reussit. PowerShell 7 peut convertir ce simple message en
    # exception lorsque $ErrorActionPreference vaut Stop. Seul le code de
    # sortie natif est donc utilise pour juger la copie.
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
        return [int]$LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $PreviousErrorActionPreference

        if ($NativePreferenceExists) {
            $PSNativeCommandUseErrorActionPreference = `
                $PreviousNativePreference
        }
    }
}

function Install-SCALocalCertificate {
    $TemporaryCertificate = Join-Path `
        $RuntimeDirectory `
        "SCA-local-root-current.crt"

    Remove-Item -LiteralPath $TemporaryCertificate -Force `
        -ErrorAction SilentlyContinue

    $CopyExitCode = Invoke-DockerCopy `
        -Source "gateway:/data/caddy/pki/authorities/local/root.crt" `
        -Destination $TemporaryCertificate

    if (($CopyExitCode -ne 0) -or (-not (
        Test-Path -LiteralPath $TemporaryCertificate -PathType Leaf
    ))) {
        return $false
    }

    $NewThumbprint = Get-CertificateThumbprint -Path $TemporaryCertificate
    if (-not $NewThumbprint) {
        throw "Le certificat HTTPS local genere est invalide."
    }

    $Certificate = New-Object `
        -TypeName System.Security.Cryptography.X509Certificates.X509Certificate2 `
        -ArgumentList $TemporaryCertificate
    $BasicConstraints = $Certificate.Extensions |
        Where-Object {
            $_ -is [System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]
        } |
        Select-Object -First 1

    if (
        ($null -eq $BasicConstraints) -or
        (-not $BasicConstraints.CertificateAuthority) -or
        ($Certificate.NotAfter -le (Get-Date))
    ) {
        throw (
            "Le certificat copie depuis Caddy n'est pas une " +
            "autorite racine valide."
        )
    }

    $PreviousThumbprint = Get-CertificateThumbprint -Path $LocalRootCertificate

    foreach ($Store in @(
        "Cert:\CurrentUser\Root",
        "Cert:\LocalMachine\Root"
    )) {
        Import-Certificate `
            -FilePath $TemporaryCertificate `
            -CertStoreLocation $Store `
            -ErrorAction Stop |
            Out-Null

        if (-not (Test-Path -LiteralPath (Join-Path $Store $NewThumbprint))) {
            throw "Le certificat SCA n'apparait pas dans $Store."
        }
    }

    if ($PreviousThumbprint -and ($PreviousThumbprint -ne $NewThumbprint)) {
        foreach ($Store in @(
            "Cert:\CurrentUser\Root",
            "Cert:\LocalMachine\Root"
        )) {
            Remove-Item `
                -LiteralPath (Join-Path $Store $PreviousThumbprint) `
                -Force `
                -ErrorAction SilentlyContinue
        }
    }

    Copy-Item `
        -LiteralPath $TemporaryCertificate `
        -Destination $LocalRootCertificate `
        -Force

    Remove-Item -LiteralPath $TemporaryCertificate -Force `
        -ErrorAction SilentlyContinue
    return $true
}

function Test-SCAHttpsEndpoint {
    param([Parameter(Mandatory)][string]$CertificatePath)

    if (-not (Test-Path -LiteralPath $CertificatePath -PathType Leaf)) {
        return $false
    }

    $CurlCommand = Get-Command curl.exe -ErrorAction SilentlyContinue
    if ($null -eq $CurlCommand) {
        throw (
            "curl.exe est introuvable. Cette commande Windows est requise " +
            "pour verifier HTTPS avec le certificat local SCA."
        )
    }

    # La sonde valide explicitement la chaine TLS avec le certificat racine
    # copie depuis Caddy. Schannel ne peut pas joindre de serveur de revocation
    # pour une autorite strictement locale ; --ssl-revoke-best-effort conserve
    # la verification du certificat et tolere uniquement cette absence.
    # La sonde n'utilise ni HTTP ni --insecure.
    $HealthResponse = & $CurlCommand.Source `
        --silent `
        --show-error `
        --fail `
        --max-time 10 `
        --ssl-revoke-best-effort `
        --cacert $CertificatePath `
        "https://localhost/SCA/_stcore/health" 2>$null

    if ($LASTEXITCODE -ne 0) {
        return $false
    }

    return (([string]($HealthResponse -join "`n")).Trim() -eq "ok")
}

function Get-DockerDesktopPath {
    $Candidates = @()

    if ($env:ProgramFiles) {
        $Candidates += Join-Path `
            $env:ProgramFiles `
            "Docker\Docker\Docker Desktop.exe"
    }

    if (${env:ProgramFiles(x86)}) {
        $Candidates += Join-Path `
            ${env:ProgramFiles(x86)} `
            "Docker\Docker\Docker Desktop.exe"
    }

    if ($env:LOCALAPPDATA) {
        $Candidates += Join-Path `
            $env:LOCALAPPDATA `
            "Docker\Docker Desktop.exe"
    }

    return $Candidates |
        Where-Object {
            Test-Path -LiteralPath $_ -PathType Leaf
        } |
        Select-Object -First 1
}

function Initialize-SuricataNativeEnvironment {
    # Un lanceur eleve depuis l'Explorateur peut heriter d'un PATH ancien.
    # On recharge les PATH Windows puis on ajoute explicitement tous les
    # dossiers contenant les DLL de Suricata et de Npcap.
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

    $SuricataDllDirectories = @(
        Get-ChildItem `
            -LiteralPath $SuricataDirectory `
            -Filter "*.dll" `
            -File `
            -Recurse `
            -ErrorAction SilentlyContinue |
            Select-Object -ExpandProperty DirectoryName -Unique
    )

    $PathEntries += $SuricataDllDirectories

    $CleanEntries = @(
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
    )

    $env:Path = $CleanEntries -join ";"

    return @(
        $CleanEntries |
            Where-Object {
                ($_ -like "$SuricataDirectory*") -or
                ($_ -like "*\Npcap")
            }
    )
}

function Get-HomeNetwork {
    param(
        [Parameter(Mandatory)][string]$IPv4,
        [Parameter(Mandatory)][ValidateRange(0, 32)][int]$PrefixLength
    )

    $IpBytes = (
        [System.Net.IPAddress]::Parse($IPv4)
    ).GetAddressBytes()

    $NetworkBytes = [byte[]](0, 0, 0, 0)

    for ($Index = 0; $Index -lt 4; $Index++) {
        $Bits = $PrefixLength - ($Index * 8)

        if ($Bits -ge 8) {
            $MaskByte = 255
        }
        elseif ($Bits -le 0) {
            $MaskByte = 0
        }
        else {
            $MaskByte = [int](
                256 - [Math]::Pow(2, 8 - $Bits)
            )
        }

        $NetworkBytes[$Index] = [byte](
            $IpBytes[$Index] -band $MaskByte
        )
    }

    return "[$($NetworkBytes -join '.')/$PrefixLength]"
}

function Get-ModelOutputsDirectory {
    $Candidates = @(
        (Join-Path $ProjectDirectory "outputs"),
        (Join-Path (Split-Path -Parent $ProjectDirectory) "outputs")
    )

    foreach ($Candidate in $Candidates) {
        $RequiredModelFiles = @(
            (
                "modelisation_evaluation\models\" +
                "meilleur_modele.pkl"
            ),
            (
                "modelisation_evaluation\model_info\" +
                "meilleur_modele.json"
            ),
            (
                "preprocessing\processed\" +
                "label_encoder_mapping.json"
            )
        )

        $BundleComplete = @(
            $RequiredModelFiles |
                Where-Object {
                    -not (Test-Path `
                        -LiteralPath (Join-Path $Candidate $_) `
                        -PathType Leaf)
                }
        ).Count -eq 0

        if ($BundleComplete) {
            return (Resolve-Path -LiteralPath $Candidate).Path
        }
    }

    throw (
        "Le paquet IA est incomplet. Verifiez meilleur_modele.pkl, " +
        "meilleur_modele.json et label_encoder_mapping.json dans outputs."
    )
}

function Get-AlertsDirectory {
    $Candidates = @(
        (Join-Path $ProjectDirectory "alerts"),
        (Join-Path (Split-Path -Parent $ProjectDirectory) "alerts")
    )

    foreach ($Candidate in $Candidates) {
        if (Test-Path -LiteralPath $Candidate -PathType Container) {
            return (Resolve-Path -LiteralPath $Candidate).Path
        }
    }

    $NewDirectory = Join-Path $ProjectDirectory "alerts"
    New-Item -ItemType Directory -Path $NewDirectory -Force |
        Out-Null

    return (Resolve-Path -LiteralPath $NewDirectory).Path
}

function Get-ActiveNetworkConfiguration {
    $Configurations = @(
        Get-NetIPConfiguration |
            Where-Object {
                ($null -ne $_.IPv4Address) -and
                ($null -ne $_.IPv4DefaultGateway)
            }
    )

    $Selected = $Configurations |
        Where-Object {
            $_.InterfaceAlias -eq $PreferredInterfaceAlias
        } |
        Select-Object -First 1

    if ($null -eq $Selected) {
        $Selected = $Configurations |
            Where-Object {
                $Adapter = Get-NetAdapter `
                    -InterfaceIndex $_.InterfaceIndex `
                    -ErrorAction SilentlyContinue

                ($null -ne $Adapter) -and
                ($Adapter.Status -eq "Up")
            } |
            Select-Object -First 1
    }

    if ($null -eq $Selected) {
        throw (
            "Aucune interface IPv4 active avec une passerelle " +
            "n'a ete detectee. Connectez le PC au Wi-Fi."
        )
    }

    return $Selected
}

try {
    Set-Location -LiteralPath $ProjectDirectory
    New-Item -ItemType Directory -Path $RuntimeDirectory -Force |
        Out-Null
    New-Item -ItemType Directory -Path (Join-Path $ProjectDirectory "history") -Force |
        Out-Null
    New-Item -ItemType Directory -Path (Join-Path $ProjectDirectory "security") -Force |
        Out-Null
    New-Item -ItemType Directory -Path $CertificateDirectory -Force |
        Out-Null

    Write-Section "SUPERVISION DES CYBERATTAQUES - LANCEMENT COMPLET"

    if (-not (Test-Administrator)) {
        throw "Le lanceur doit etre execute en administrateur."
    }

    foreach ($RequiredFile in @(
        $SuricataExecutable,
        $SuricataConfiguration,
        $SuricataRules,
        $SuricataRuntimeScript,
        (Join-Path $ProjectDirectory "compose.yaml"),
        (Join-Path $ProjectDirectory "Caddyfile"),
        (Join-Path $ProjectDirectory "Dockerfile"),
        (Join-Path $ProjectDirectory "requirements.txt"),
        (Join-Path $ProjectDirectory "api.py"),
        (Join-Path $ProjectDirectory "auth_security.py"),
        (Join-Path $ProjectDirectory "data_migration.py"),
        (Join-Path $ProjectDirectory "app.py")
    )) {
        if (-not (
            Test-Path -LiteralPath $RequiredFile -PathType Leaf
        )) {
            throw "Fichier requis introuvable : $RequiredFile"
        }
    }

    # L'installation Windows de Suricata reference ce fichier meme lorsqu'il
    # ne contient aucune limitation. Le creer evite un avertissement trompeur
    # au demarrage sans modifier les regles IDS.
    if (-not (Test-Path -LiteralPath $SuricataThresholdConfig -PathType Leaf)) {
        New-Item `
            -ItemType File `
            -Path $SuricataThresholdConfig `
            -Force |
            Out-Null
    }

    Write-Step 1 "Verification de Docker Desktop"

    if ($null -eq (Get-Command docker.exe -ErrorAction SilentlyContinue)) {
        throw "Docker Desktop n'est pas installe ou docker.exe est absent du PATH."
    }

    if (-not (Test-DockerEngine)) {
        $DockerDesktop = Get-DockerDesktopPath

        if ($null -eq $DockerDesktop) {
            throw (
                "Docker Desktop est arrete et son executable " +
                "n'a pas ete trouve. Demarrez Docker Desktop puis reessayez."
            )
        }

        Write-Host "Demarrage automatique de Docker Desktop..." `
            -ForegroundColor Yellow
        Start-Process `
            -FilePath "explorer.exe" `
            -ArgumentList ('"{0}"' -f $DockerDesktop) |
            Out-Null

        $DockerDeadline = (Get-Date).AddMinutes(3)

        do {
            Start-Sleep -Seconds 3

            if (Test-DockerEngine) {
                break
            }
        } while ((Get-Date) -lt $DockerDeadline)

        if (-not (Test-DockerEngine)) {
            throw (
                "Docker Desktop n'est pas devenu operationnel " +
                "apres trois minutes."
            )
        }
    }

    Write-Host "[OK] Docker Desktop est operationnel." `
        -ForegroundColor Green

    Write-Step 2 "Detection du Wi-Fi et preparation de Suricata"

    $NetConfig = Get-ActiveNetworkConfiguration
    $Adapter = Get-NetAdapter `
        -InterfaceIndex $NetConfig.InterfaceIndex `
        -ErrorAction Stop

    $IPv4Object = @(
        $NetConfig.IPv4Address |
            Where-Object {
                ($_.IPAddress -notmatch '^169\.254\.') -and
                ($_.IPAddress -notmatch '^127\.')
            }
    ) | Select-Object -First 1

    if ($null -eq $IPv4Object) {
        throw "Aucune adresse IPv4 exploitable n'a ete trouvee."
    }

    $IPv4 = [string]$IPv4Object.IPAddress
    $PrefixLength = [int]$IPv4Object.PrefixLength
    $Gateway = [string](
        $NetConfig.IPv4DefaultGateway |
            Select-Object -ExpandProperty NextHop -First 1
    )

    $HomeNet = Get-HomeNetwork `
        -IPv4 $IPv4 `
        -PrefixLength $PrefixLength

    $Guid = (
        [Guid]$Adapter.InterfaceGuid
    ).ToString("B").ToUpperInvariant()

    $CaptureDevice = "\Device\NPF_$Guid"
    $AlertsDirectory = Get-AlertsDirectory
    $ModelOutputsDirectory = Get-ModelOutputsDirectory

    $Npcap = Get-Service -Name "npcap" -ErrorAction SilentlyContinue

    if ($null -eq $Npcap) {
        throw "Le service Npcap est introuvable."
    }

    if ($Npcap.Status -ne "Running") {
        Start-Service -Name "npcap"
        $Npcap.WaitForStatus(
            [System.ServiceProcess.ServiceControllerStatus]::Running,
            [TimeSpan]::FromSeconds(15)
        )
    }

    Write-Host "Interface    : $($Adapter.Name)" -ForegroundColor Green
    Write-Host "Adresse IPv4 : $IPv4/$PrefixLength" -ForegroundColor Green
    Write-Host "Passerelle   : $Gateway"
    Write-Host "HOME_NET     : $HomeNet" -ForegroundColor Green
    Write-Host "Journal EVE  : $AlertsDirectory\eve.json"
    Write-Host "Modele IA    : $ModelOutputsDirectory"

    $NativeDirectories = @(
        Initialize-SuricataNativeEnvironment
    )

    Write-Host (
        "DLL natives  : {0} chemin(s) initialise(s)" -f
        $NativeDirectories.Count
    ) -ForegroundColor Green

    Write-Step 3 "Validation et lancement de Suricata"

    $HomeNetOverride = "vars.address-groups.HOME_NET=$HomeNet"
    $ValidationArguments = @(
        "-T",
        "-c", $SuricataConfiguration,
        "-l", $AlertsDirectory,
        "--set", $HomeNetOverride,
        "--init-errors-fatal"
    )

    $UseLabRules = Test-Path -LiteralPath $LabRules -PathType Leaf

    if ($UseLabRules) {
        $ValidationArguments += @("-s", $LabRules)
        Write-Host "Regles LAB   : activees" -ForegroundColor Green
    }
    else {
        Write-Host "Regles LAB   : absentes, ET Open reste actif" `
            -ForegroundColor Yellow
    }

    $RunningSuricata = @(
        Get-CimInstance Win32_Process `
            -Filter "Name='suricata.exe'" `
            -ErrorAction SilentlyContinue
    )

    if ($RunningSuricata.Count -gt 0) {
        $MatchingProcess = $RunningSuricata |
            Where-Object {
                ($_.CommandLine -like "*$AlertsDirectory*") -and
                ($_.CommandLine -like "*$Guid*")
            } |
            Select-Object -First 1

        if ($null -eq $MatchingProcess) {
            throw (
                "Une autre instance de Suricata fonctionne deja avec " +
                "une configuration differente. Arretez-la avec Ctrl+C, " +
                "puis relancez LANCER_TOUT.bat."
            )
        }

        Write-Host (
            "[OK] Suricata fonctionne deja avec la bonne interface " +
            "(PID $($MatchingProcess.ProcessId))."
        ) -ForegroundColor Green
    }
    else {
        Push-Location $SuricataDirectory

        try {
            & $SuricataExecutable @ValidationArguments
            $ValidationExitCode = $LASTEXITCODE
        }
        finally {
            Pop-Location
        }

        if ($ValidationExitCode -ne 0) {
            if ($ValidationExitCode -eq -1073741515) {
                throw (
                    "Windows n'a pas trouve une DLL requise par Suricata " +
                    "(0xC0000135), meme apres l'initialisation automatique " +
                    "des chemins Suricata et Npcap. Reparez l'installation " +
                    "Suricata 8.0.6, puis relancez LANCER_TOUT.bat."
                )
            }

            throw (
                "La validation Suricata a echoue avec le code " +
                "$ValidationExitCode."
            )
        }

        $ChildArguments = @(
            "-NoLogo",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-File", ('"{0}"' -f $SuricataRuntimeScript),
            "-SuricataPath", ('"{0}"' -f $SuricataExecutable),
            "-ConfigPath", ('"{0}"' -f $SuricataConfiguration),
            "-CaptureDevice", ('"{0}"' -f $CaptureDevice),
            "-LogsDirectory", ('"{0}"' -f $AlertsDirectory),
            "-HomeNet", ('"{0}"' -f $HomeNet)
        )

        if ($UseLabRules) {
            $ChildArguments += @(
                "-LabRulesPath", ('"{0}"' -f $LabRules)
            )
        }

        $SuricataPidFile = Join-Path `
            $RuntimeDirectory `
            "suricata.pid"
        $SuricataErrorFile = Join-Path `
            $RuntimeDirectory `
            "suricata_error.txt"

        Remove-Item `
            -LiteralPath $SuricataPidFile, $SuricataErrorFile `
            -Force `
            -ErrorAction SilentlyContinue

        $SuricataShell = Start-Process `
            -FilePath "powershell.exe" `
            -ArgumentList ($ChildArguments -join " ") `
            -WorkingDirectory $ProjectDirectory `
            -PassThru

        $SuricataDeadline = (Get-Date).AddMinutes(2)

        do {
            Start-Sleep -Seconds 2

            if ($SuricataShell.HasExited) {
                throw (
                    "La fenetre Suricata s'est fermee avant le " +
                    "demarrage du moteur."
                )
            }

            if (Test-Path -LiteralPath $SuricataPidFile -PathType Leaf) {
                break
            }
        } while ((Get-Date) -lt $SuricataDeadline)

        if (-not (
            Test-Path -LiteralPath $SuricataPidFile -PathType Leaf
        )) {
            $RuntimeError = ""

            if (Test-Path -LiteralPath $SuricataErrorFile -PathType Leaf) {
                $RuntimeError = Get-Content `
                    -LiteralPath $SuricataErrorFile `
                    -Raw
            }

            throw (
                "Suricata n'a pas fourni son PID dans le delai prevu. " +
                $RuntimeError
            )
        }

        Start-Sleep -Seconds 8

        $SuricataPid = [int](
            Get-Content -LiteralPath $SuricataPidFile -Raw
        )
        $SuricataProcess = Get-Process `
            -Id $SuricataPid `
            -ErrorAction SilentlyContinue

        if (
            ($null -eq $SuricataProcess) -or
            ($SuricataProcess.ProcessName -ne "suricata")
        ) {
            $RuntimeError = ""

            if (Test-Path -LiteralPath $SuricataErrorFile -PathType Leaf) {
                $RuntimeError = Get-Content `
                    -LiteralPath $SuricataErrorFile `
                    -Raw
            }

            throw "Suricata s'est arrete au demarrage. $RuntimeError"
        }

        Write-Host "[OK] Suricata est lance dans sa propre fenetre." `
            -ForegroundColor Green
    }

    Write-Step 4 "Construction de l'API, du Dashboard et de HTTPS"

    $env:SURICATA_ALERTS_DIR = $AlertsDirectory
    $env:MODEL_OUTPUTS_DIR = $ModelOutputsDirectory

    & docker compose down --remove-orphans
    & docker compose up --build -d --force-recreate

    if ($LASTEXITCODE -ne 0) {
        Write-Host ""
        Write-Host "Journal de la passerelle HTTPS :" `
            -ForegroundColor Yellow
        & docker compose logs "--tail=80" gateway-init gateway
        throw (
            "Docker n'a pas pu construire ou lancer tous les services. " +
            "Le journal de la passerelle est affiche ci-dessus."
        )
    }

    $RunningServices = @(
        & docker compose ps --status running --services 2>$null
    )

    if ($RunningServices -notcontains "gateway") {
        Write-Host ""
        Write-Host "Journal de la passerelle HTTPS :" `
            -ForegroundColor Yellow
        & docker compose logs "--tail=80" gateway-init gateway
        throw (
            "La passerelle HTTPS ne s'est pas mise en marche. " +
            "Les journaux utiles sont affiches ci-dessus."
        )
    }

    Write-Step 5 "Controle automatique des services"

    $Deadline = (Get-Date).AddMinutes(2)
    $LastModelError = $null
    $LastScalerError = $null
    $LastMonitorError = $null
    $LastServiceError = $null
    $CertificateReady = $false
    $ApiReady = $false
    $DashboardReady = $false
    $GatewayReady = $false
    $HttpsReady = $false
    $Ready = $false

    do {
        try {
            if (-not $CertificateReady) {
                $CertificateReady = Install-SCALocalCertificate
            }

            $ApiCheckCommand = (
                "import urllib.request; " +
                "print(urllib.request.urlopen(" +
                "'http://127.0.0.1:8000/health/ready', " +
                "timeout=20).read().decode())"
            )
            $ApiPayloadText = & docker compose exec -T api `
                python -c $ApiCheckCommand 2>$null

            if ($LASTEXITCODE -ne 0) {
                throw "L'API interne n'est pas encore disponible."
            }

            $Readiness = $ApiPayloadText | ConvertFrom-Json
            $LastModelError = $Readiness.model_error
            $LastScalerError = $Readiness.scaler_error
            $LastMonitorError = $Readiness.monitor_error
            $ApiReady = $true

            $RunningNow = @(
                & docker compose ps --status running --services 2>$null
            )
            $DashboardReady = $RunningNow -contains "dashboard"
            $GatewayReady = $RunningNow -contains "gateway"

            if (-not ($DashboardReady -and $GatewayReady)) {
                throw "Le Dashboard ou la passerelle n'est pas encore disponible."
            }

            $HttpsReady = Test-SCAHttpsEndpoint `
                -CertificatePath $LocalRootCertificate

            if (
                $CertificateReady -and
                $ApiReady -and
                $DashboardReady -and
                $GatewayReady -and
                $HttpsReady
            ) {
                $Ready = $true
                break
            }
        }
        catch {
            # Les services peuvent refuser les requetes pendant leur amorcage.
            $LastServiceError = $_.Exception.Message
        }

        Start-Sleep -Seconds 3
    } while ((Get-Date) -lt $Deadline)

    if (-not $Ready) {
        Write-Host ""
        Write-Host "Derniere erreur de disponibilite : $LastServiceError" `
            -ForegroundColor Yellow
        Write-Host (
            "Etat : certificat=$CertificateReady, API=$ApiReady, " +
            "Dashboard=$DashboardReady, passerelle=$GatewayReady, " +
            "HTTPS=$HttpsReady"
        ) -ForegroundColor Yellow
        Write-Host "Derniere erreur du modele : $LastModelError" `
            -ForegroundColor Yellow
        Write-Host "Derniere erreur du scaler : $LastScalerError" `
            -ForegroundColor Yellow
        Write-Host "Derniere erreur du lecteur EVE : $LastMonitorError" `
            -ForegroundColor Yellow
        & docker compose logs `
            "--tail=100" api dashboard gateway-init gateway
        throw "Les services ne sont pas devenus operationnels dans le delai prevu."
    }

    if ($Readiness.model_loaded) {
        Write-Host "[OK] Modele IA charge." -ForegroundColor Green
    }
    else {
        Write-Host (
            "[ATTENTION] Modele IA pas encore charge ; " +
            "le site reste accessible."
        ) -ForegroundColor Yellow
    }

    if ($Readiness.scaler_loaded) {
        Write-Host "[OK] Normalisation MinMax du modele chargee." `
            -ForegroundColor Green
    }
    else {
        Write-Host (
            "[ATTENTION] Scaler MinMax absent : les flux bruts utiliseront " +
            "le mode de secours jusqu'a la prochaine execution du " +
            "pretraitement."
        ) -ForegroundColor Yellow
    }

    if (
        $Readiness.monitor_enabled -and
        $Readiness.monitor_thread_alive -and
        $Readiness.monitor_file_exists
    ) {
        Write-Host "[OK] Lecteur automatique eve.json actif." `
            -ForegroundColor Green
    }
    else {
        Write-Host (
            "[ATTENTION] Le lecteur EVE attend encore eve.json ; " +
            "le site reste accessible."
        ) -ForegroundColor Yellow
    }
    Write-Host "[OK] Dashboard Streamlit operationnel." `
        -ForegroundColor Green
    Write-Host "[OK] HTTPS local et certificat SCA operationnels." `
        -ForegroundColor Green

    Write-Step 6 "Ouverture du site"

    $DashboardUrl = "https://localhost/SCA/"
    Start-Process $DashboardUrl | Out-Null

    Write-Section "SITE COMPLET OPERATIONNEL"
    Write-Host "Dashboard : https://localhost/SCA/" `
        -ForegroundColor Green
    Write-Host "API       : interne, non exposee sur Windows" `
        -ForegroundColor DarkGray
    Write-Host "Suricata  : capture active sur $($Adapter.Name)" `
        -ForegroundColor Green
    Write-Host "HOME_NET  : $HomeNet"
    Write-Host "Journal   : $AlertsDirectory\eve.json"
    Write-Host ""
    Write-Host (
        "Pour tout arreter proprement, double-cliquez sur " +
        "ARRETER_TOUT.bat."
    ) -ForegroundColor Yellow

    & docker compose ps
    exit 0
}
catch {
    Write-Host ""
    Write-Host "[ERREUR] $($_.Exception.Message)" `
        -ForegroundColor Red
    Write-Host ""
    Write-Host (
        "Les journaux et l'historique existants n'ont pas ete supprimes."
    ) -ForegroundColor Yellow
    exit 1
}

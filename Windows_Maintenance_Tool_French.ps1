# ===== ADMIN CHECK =====
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Ce script a besoin des privilèges administrateur."
    Write-Host "Demande d'élévation en cours..."
    Start-Process powershell.exe "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

function Pause-Menu {
    Write-Host
    Read-Host "Presser la touche Entrée pour retourner au menu"
}

function Show-Translation {
    if (-not ([bool]$global:__ShowTranslationOnce)) {
        Write-Host "Je n'ai que traduis le script en Français, pour une assistance, contactez l'auteur !" -ForegroundColor Cyan
        Write-Host "❗ Attention : Nous vous recommandons de créer un point de restauration avant d'utiliser le script !" -ForegroundColor Red
        Pause-Menu
        $global:__ShowTranslationOnce = $true
    }
}

function Show-Menu {
    Clear-Host
    Show-Translation
    Clear-Host
    Write-Host "==========================================================================="
    Write-Host "  OUTIL DE MAINTENANCE WINDOWS V3.5.0 - Par Lil_Batti & Chaython & Traduis par Owned67  " -ForegroundColor Yellow
    Write-Host "==========================================================================="
    Write-Host
    Write-Host "     === MISES À JOUR WINDOWS ==="
    Write-Host "  [1]  MAJ Apps/Programmes avec Winget upgrade"
    Write-Host
    Write-Host "     === CONTRÔLES DE SANTÉ DU SYSTÈME ==="
    Write-Host "  [2]  Recherche de fichier(s) corrompu(s) (SFC /scannow) [Admin]"
    Write-Host "  [3]  Contrôle de la santé système Windows (DISM /CheckHealth) [Admin]"
    Write-Host "  [4]  Restauration de la santé système Windows (DISM /RestoreHealth) [Admin]"
    Write-Host "  [4.1]  Vérification du magasin des composants (DISM /AnalyzeComponentStore) [Admin]"
    
    Write-Host
    Write-Host "     === Outils Réseaux ==="
    Write-Host "  [5]  Options DNS (Vider cache DNS/Définir DNS/Réinitialiser DNS)"
    Write-Host "  [6]  Afficher les informations du réseau (ipconfig /all)"
    Write-Host "  [7]  Redémarrer les adaptateurs Wi-Fi"
    Write-Host "  [8]  Réparation réseau - Dépannage automatique"
    Write-Host "  [9]  Gestionnaire du Pare-Feu [Admin]"
    Write-Host
    Write-Host "     === NETTOYAGE ET OPTIMISATION ==="
    Write-Host " [10]  Nettoyage de disque (cleanmgr)"
    Write-Host " [11]  Exécuter l'analyse des erreurs (CHKDSK) [Admin]"
    Write-Host " [12]  Effectuer l'optimisation du système (supprimer les fichiers temporaires)"
    Write-Host " [13]  Nettoyage avancé du registre"
    Write-Host " [14]  Optimise SSD (ReTrim)"
    Write-Host " [15]  Gestion des tâches (tâches planifiées) [Admin]"
    Write-Host
    Write-Host "     === Utilitaires et Extras ==="
    Write-Host " [20]  Voir les pilotes installés"
    Write-Host " [21]  Outil de réparation de Windows Update"
    Write-Host " [22]  Générer un rapport complet du système"
    Write-Host " [23]  Utilitaire MAJ Windows & Réinitialisation des services"
    Write-Host " [24]  Afficher la table de routage du réseau [Avancé]"
    Write-Host " [25]  Réinitialisation des associations de fichiers"
    Write-Host " [26]  Lancer le moniteur de fiabilité" 
    Write-Host
    Write-Host "     === SUPPORT ==="
    Write-Host " [30]  Informations de contact et d'assistance (Discord)"

    Write-Host
    Write-Host " [0]  Quitter"
    Write-Host "------------------------------------------------------"
}

function Show-WingetUpdates {
    Write-Host "🔍 Mises à jour disponibles via Winget :`n" -ForegroundColor Cyan
    Write-Host
    winget upgrade --include-unknown
}


function Choice-1 {
    $log = "$env:USERPROFILE\Desktop\WinGet-Upgrade_{0}.log" -f (Get-Date -Format "yyyy-MM-dd_HHmmss")
    Clear-Host
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        Write-Host "❌ Winget n'est pas installé. Tentative d'installation en cours..."
        try {
            # Method 1: Try installing via Microsoft Store (App Installer)
            Write-Host "Installing Winget via Microsoft Store..."
            $result = Start-Process "ms-windows-store://pdp/?productid=9NBLGGH4NNS1" -Wait -PassThru
            
            if ($result.ExitCode -eq 0) {
                Write-Host "Microsoft Store ouvert avec succès. Veuillez terminer l'installation."
                Write-Host "Après l'installation, redémarrez cet outil pour utiliser les fonctionnalités de Winget."
                Pause-Menu
                return
            } else {
                # Method 2: Alternative direct download if Store method fails
                Write-Host "Échec de la méthode du Microsoft Store, tentative de téléchargement direct..."
                $wingetUrl = "https://aka.ms/getwinget"
                $installerPath = "$env:TEMP\winget-cli.msixbundle"
                
                # Download the installer
                Invoke-WebRequest -Uri $wingetUrl -OutFile $installerPath
                
                # Install Winget
                Add-AppxPackage -Path $installerPath
                
                # Verify installation
                if (Get-Command winget -ErrorAction SilentlyContinue) {
                    Write-Host "Winget installé avec succès !"
                    Start-Sleep -Seconds 2
                } else {
                    Write-Host "L'installation a échoué. Veuillez l'installer manuellement depuis le Microsoft Store."
                    Pause-Menu
                    return
                }
            }
        } catch {
            Write-Host "❌ Échec du téléchargement ou de l'exécution du script d'installation."
            Pause-Menu
            return
        }
        if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
            Write-Host "❌ L'installation de Winget a échoué. Veuillez installer le programme d'installation d'application depuis Microsoft Store."
            Pause-Menu
            return
        }
        Write-Host "✅ Winget a été installé avec succès."
    }

    Write-Host "========================================="
    Write-Host "    Mises à Jours windows avec Winget    "
    Write-Host "========================================="
    Show-WingetUpdates
    Write-Host
    Pause-Menu
    while ($true) {
        Write-Host "==============================================="
        Write-Host "Options :"
        Write-Host "[1] Mettre à niveau tous les packages"
        Write-Host "[2] Mettre à niveau les packages sélectionnés"
        Write-Host "[0] Annuler"
        Write-Host
        $input = Read-Host "Choisissez une option"
        $input = $upopt.Trim()
        switch ($input) {
            "0" {
                Write-Host "Annulé. Retour au menu..."
                Pause-Menu
                return
            }
            "1" {
                $logallFile = "$env:USERPROFILE\Desktop\WinGet-all_{0}.log" -f (Get-Date -Format "yyyy-MM-dd_HHmmss")
                Write-Host "Exécution d'une mise à niveau complète..."
                winget upgrade --all --include-unknown | Tee-Object -FilePath $logallFile
                Pause-Menu
                return
            }
            "2" {
                Clear-Host
                Write-Host "============================================================"
                Write-Host "   Paquets disponibles [Copiez l'ID pour mettre à niveau]   "
                Write-Host "============================================================"
                winget upgrade --include-unknown
                Write-Host
                Write-Host "Saisissez un ou plusieurs identifiants de package à mettre à niveau (séparés par des virgules, sans espaces)"
                $packlist = Read-Host "IDs"
                $packlist = $packlist -replace ' ', ''
                if ([string]::IsNullOrWhiteSpace($packlist)) {
                    Write-Host "Aucun identifiant de package saisi."
                    Pause-Menu
                    return
                }
                $ids = $packlist.Split(",")
                foreach ($id in $ids) {
                    $logFile = "$env:USERPROFILE\Desktop\WinGet-$id_{0}.log" -f (Get-Date -Format "yyyy-MM-dd_HHmmss")
                    Write-Host "Mise à niveau de $id..."
                    winget upgrade --id $id --include-unknown | Tee-Object -FilePath $logFile
                    Write-Host
                }
                Pause-Menu
                return
            }
            default {
                Write-Host "Option invalide. Veuillez choisir 1, 2 ou 0."
                continue
            }
        }
    }
}
function Choice-2 {
    $sourceLog = "$env:USERPROFILE\Desktop\sfc-scannow.log"
    $destLog   = "$env:USERPROFILE\Desktop\CBS_Erreurs_Detaillees_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').txt"
    Clear-Host
    Write-Host "Recherche de fichiers corrompus (SFC /scannow)..."
    if (Test-Path $sourceLog) {
        $date = Get-Date -Format "yyyy-MM-dd_HHmmss"
        $dir = Split-Path $sourceLog -Parent
        $name = Split-Path $sourceLog -Leaf
        $newName = "$($name)-$date"
        Rename-Item -Path $sourceLog -NewName $newName
    }
    sfc /scannow 2>&1 | Tee-Object -FilePath "$env:USERPROFILE\Desktop\sfc-scannow.log"
    $patterns = @(
        'cannot repair',
        'corrupt',
        'Repairing'
        'repaired',
        '\[SR\]',
        'error',
        'Failed',
        'Missing',
        'CSI.*repaired',
        'Hashes for file member',
        'DIRSD OWNER WARNING',
        'is owned twice'
    )

    Select-String -Path $sourceLog -Pattern $patterns -SimpleMatch |
        Sort-Object LineNumber |
        Out-File -Encoding UTF8 -FilePath $destLog

    Write-Host "✅ Résumé des erreurs CBS enregistré dans : $destLog"
    Pause-Menu
}

function Choice-3 {
    Clear-Host
    Write-Host "Vérification de l'état de santé de Windows (DISM /CheckHealth)..."
    $logPath = "$env:USERPROFILE\Desktop\dism-checkhealth.log"
    dism /online /cleanup-image /checkhealth 2>&1 | Tee-Object -FilePath "$logPath"
    if (-not (Select-String -Path $logPath -Pattern "Aucun endommagement" -Quiet)) {
        Write-Host "Votre système semble être endommagé/corrompu..." -ForegroundColor Red
        Remove-Item -Path $logPath -Force -ErrorAction SilentlyContinue
        Write-Host "Tentative de réparation..." -ForegroundColor Cyan
        while ($true) {
          $restart = Read-Host "Souhaitez-vous exécuter la tentative de réparation ? (O/N)"
          switch ($restart.ToUpper()) {
              "O" { Choice-4; return }
              "N" { Show-Menu; return }
              default { Write-Host "Entrée invalide. Veuillez saisir O ou N." }
          }
        }
    } else {
        Write-Host "✔️ Aucun endommagement détecté dans l'image Windows."
        Pause-Menu
        Show-Menu
    }
    Pause-Menu
}

function Choice-4 {
    Clear-Host
    $restorehealth = "$env:SystemDrive\Windows\Logs\DISM\dism.log"
    Write-Host "Restauration de l'état de santé de Windows (DISM /RestoreHealth)..."
    if (Test-Path $restorehealth) {
        $date = Get-Date -Format "yyyy-MM-dd_HHmmss"
        $dir = Split-Path $restorehealth -Parent
        $name = Split-Path $restorehealth -Leaf
        $newName = "$($name)-$date"
        Rename-Item -Path $restorehealth -NewName $newName
    }
    dism /online /cleanup-image /restorehealth
    Pause-Menu
}

function Choice-4.1 {
    Clear-Host
    function Run-ComponentCleanup {
        Write-Host "Désactivation des services msiserver et TrustedInstaller" -ForegroundColor Cyan
        $services = @("msiserver", "TrustedInstaller")

        foreach ($svc in $services) {
            try {
                Set-Service -Name $svc -StartupType Disabled -ErrorAction Stop            } catch {
                Write-Host "[ERREUR] Impossible de désactiver le démarrage du service $svc." -ForegroundColor Red
                Write-Host "Cela peut empêcher le bon fonctionnement de l’analyse." -ForegroundColor Yellow
                $choice = Read-Host "Continuer malgré tout ? (O/N)"
                if ($choice.ToUpper() -ne "O") {
                    Write-Host "Opération annulée par l'utilisateur." -ForegroundColor DarkGray
                    return
                }
            }
        }

        foreach ($svc in $services) {
            try {
                Stop-Service -Name $svc -Force -ErrorAction Stop
            } catch {
                Write-Host "[ERREUR] Impossible d’arrêter le service $svc." -ForegroundColor Red
                Write-Host "Cela peut empêcher le bon fonctionnement de l’analyse." -ForegroundColor Yellow
                $choice = Read-Host "Continuer malgré tout ? (O/N)"                if ($choice.ToUpper() -ne "O") {
                    Write-Host "Opération annulée par l'utilisateur." -ForegroundColor DarkGray
                    Pause-Menu;return
                }
            }
        }

        # Analyse du magasin de composants
        $analyzeLog = "$PSScriptRoot\AnalyzeComponentStore.log"
        Write-Host "`nExécution de la commande : Dism.exe /Online /Cleanup-Image /AnalyzeComponentStore" -ForegroundColor Cyan
        Write-Host "Il faudra plusieurs minutes avant que la commande se termine..." -ForegroundColor DarkGray
        dism.exe /Online /Cleanup-Image /AnalyzeComponentStore | Tee-Object -FilePath $analyzeLog
        $needCleanup = Select-String -Path $analyzeLog -Pattern "Nettoyage du magasin.*:.*Oui" -Quiet
        if ($needCleanup) {
            Write-Host "`nUn nettoyage du magasin de composants est nécessaire." -ForegroundColor Yellow
            $choice = Read-Host "Souhaitez-vous effectuer le nettoyage maintenant ? (O/N)"
            if ($choice.ToUpper() -ne "O") {
                Write-Host "Opération annulée par l'utilisateur." -ForegroundColor DarkGray
                Restore-Services
                Pause-Menu;return
            }
            Remove-Item $analyzeLog -Force -ErrorAction SilentlyContinue
            Start-ComponentCleanup
        } else {
            Write-Host "`nAucun nettoyage nécessaire." -ForegroundColor Green
            Restore-Services
        }

    }

    function Start-ComponentCleanup {
        $cleanupLog = "$PSScriptRoot\StartComponentCleanup.log"
        Write-Host "`nExécution de la commande : Dism.exe /Online /Cleanup-Image /StartComponentCleanup" -ForegroundColor Cyan
        Write-Host "Il faudra plusieurs minutes avant que la commande se termine..." -ForegroundColor DarkGray
        dism.exe /Online /Cleanup-Image /StartComponentCleanup | Tee-Object -FilePath $cleanupLog
        Restore-Services
    }

    function Restore-Services {
        $services = @("msiserver", "TrustedInstaller")

        foreach ($svc in $services) {
            try {
                Set-Service -Name $svc -StartupType Manual
            } catch {
                Write-Host "[ERREUR] Impossible de configurer $svc en manuel." -ForegroundColor Red
                Pause
                return
            }
        }

        foreach ($svc in $services) {
            try {
                Start-Service -Name $svc
            } catch {
                Write-Host "[ERREUR] Impossible de démarrer le service $svc." -ForegroundColor Red
                Pause
                return
            }
        }

        Write-Host "`n✅ Intégrité du fichier terminée. Fermeture après confirmation." -ForegroundColor Green
        Pause-Menu
    }

    Run-ComponentCleanup
}
function Choice-5 {

    #function Get-ActiveAdapters {
        # Exclude virtual adapters like vEthernet
    #    Get-NetAdapter | Where-Object { $_.InterfaceDescription -notmatch "Wi-Fi|Wireless|WLAN|Wireless|Wintun|Virtualbox|VMware|Wintun|Loopback|Bluetooth|Hyper-V|Ndis|Miniport|TAP|QEMU|Cisco|Teredo|ISATAP|vEthernet|Bridge" -and $_.Status -eq 'Up' } | Select-Object -ExpandProperty Name
    #}
    function Get-ActiveAdapters {
        # Exclude virtual adapters like vEthernet
        Get-NetAdapter | Where-Object { $_.Status -eq 'Up' -and $_.InterfaceDescription -notlike '*Virtual*' -and $_.Name -notlike '*vEthernet*' } | Select-Object -ExpandProperty Name
    }
    # Check if DoH is supported (Windows 11 or recent Windows 10)
    function Test-DoHSupport {
        $osVersion = [System.Environment]::OSVersion.Version
        return ($osVersion.Major -eq 10 -and $osVersion.Build -ge 19041) -or ($osVersion.Major -gt 10)
    }

    # Check if running as Administrator
    function Test-Admin {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }

    # Function to enable DoH for all known DNS servers using netsh
    function Enable-DoHAllServers {
        $dnsServers = @(
            # Cloudflare DNS
            @{ Server = "1.1.1.1"; Template = "https://cloudflare-dns.com/dns-query" },
            @{ Server = "1.0.0.1"; Template = "https://cloudflare-dns.com/dns-query" },
            @{ Server = "2606:4700:4700::1111"; Template = "https://cloudflare-dns.com/dns-query" },
            @{ Server = "2606:4700:4700::1001"; Template = "https://cloudflare-dns.com/dns-query" },
            # Google DNS
            @{ Server = "8.8.8.8"; Template = "https://dns.google/dns-query" },
            @{ Server = "8.8.4.4"; Template = "https://dns.google/dns-query" },
            @{ Server = "2001:4860:4860::8888"; Template = "https://dns.google/dns-query" },
            @{ Server = "2001:4860:4860::8844"; Template = "https://dns.google/dns-query" },
            # Quad9 DNS
            @{ Server = "9.9.9.9"; Template = "https://dns.quad9.net/dns-query" },
            @{ Server = "149.112.112.112"; Template = "https://dns.quad9.net/dns-query" },
            @{ Server = "2620:fe::fe"; Template = "https://dns.quad9.net/dns-query" },
            @{ Server = "2620:fe::fe:9"; Template = "https://dns.quad9.net/dns-query" },
            # AdGuard DNS
            @{ Server = "94.140.14.14"; Template = "https://dns.adguard.com/dns-query" },
            @{ Server = "94.140.15.15"; Template = "https://dns.adguard.com/dns-query" },
            @{ Server = "2a10:50c0::ad1:ff"; Template = "https://dns.adguard.com/dns-query" },
            @{ Server = "2a10:50c0::ad2:ff"; Template = "https://dns.adguard.com/dns-query" }
        )
        Write-Host "Activation de DoH pour tous les serveurs DNS connus..."
        $successCount = 0
        foreach ($dns in $dnsServers) {
            try {
                $command = "netsh dns add encryption server=$($dns.Server) dohtemplate=$($dns.Template) autoupgrade=yes udpfallback=no"
                $result = Invoke-Expression $command 2>&1
                if ($LASTEXITCODE -eq 0) {
                    Write-Host "  - DoH activé pour $($dns.Server) avec le modèle $($dns.Template)" -ForegroundColor Green
                    $successCount++
                } else {
                    Write-Host "  - Échec de l'activation de DoH pour $($dns.Server) : $result" -ForegroundColor Yellow
                }
            } catch {
                Write-Host "  - Échec de l'activation de DoH pour $($dns.Server): $_" -ForegroundColor Yellow
            }
        }
        if ($successCount -eq 0) {
            Write-Host "  - Aucun paramètre DoH n'a été appliqué correctement. Vérifiez les autorisations système ou la version de Windows." -ForegroundColor Red
            return $false
        }
        # Flush DNS cache to ensure changes are applied
        try {
            Invoke-Expression "ipconfig /flushdns" | Out-Null
            Write-Host "  - Le cache DNS a été vidé." -ForegroundColor Green
        } catch {
            Write-Host "  - Échec du vidage du cache DNS : $_" -ForegroundColor Yellow
        }
        # Attempt to restart DNS client service if running as Administrator
        if (Test-Admin) {
            $service = Get-Service -Name Dnscache -ErrorAction SilentlyContinue
            if ($service.Status -eq "Running" -and $service.StartType -ne "Disabled") {
                try {
                    Restart-Service -Name Dnscache -Force -ErrorAction Stop
                    Write-Host "  - Le service client DNS a été redémarré pour appliquer les paramètres DoH" -ForegroundColor Green
                } catch {
                    Write-Host "  - Échec du redémarrage du service client DNS : $_" -ForegroundColor Yellow
                    try {
                        $stopResult = Invoke-Expression "net stop dnscache" 2>&1
                        if ($LASTEXITCODE -eq 0) {
                            Start-Sleep -Seconds 2
                            $startResult = Invoke-Expression "net start dnscache" 2>&1
                            if ($LASTEXITCODE -eq 0) {
                                Write-Host "  - Le service client DNS a redémarré à l'aide de net stop/start" -ForegroundColor Green
                            } else {
                                Write-Host "  - Échec du redémarrage du service client DNS : $startResult" -ForegroundColor Yellow
                            }
                        } else {
                            Write-Host "  - Échec lors de l'arrêt du service client DNS : $stopResult" -ForegroundColor Yellow
                        }
                    } catch {
                        Write-Host "  - Échec du redémarrage du service client DNS : $_" -ForegroundColor Yellow
                    }
                }
            } else {
                Write-Host "  - Le service client DNS n'est pas en cours d'exécution ou est désactivé. Veuillez l'activer et le démarrer manuellement." -ForegroundColor Yellow
            }
            Write-Host "  - Veuillez redémarrer votre système pour appliquer les paramètres DoH ou redémarrer manuellement le service 'Client DNS' dans services.msc." -ForegroundColor Yellow
        } else {
            Write-Host "  - Impossible d'exécuter l'application en tant qu'administrateur. Impossible de redémarrer le service client DNS. Veuillez redémarrer pour appliquer les paramètres DoH." -ForegroundColor Yellow
        }
        return $true
    }

    # Function to check DoH status
    function Check-DoHStatus {
        try {
            $netshOutput = Invoke-Expression "netsh dns show encryption" | Out-String
            if ($netshOutput -match "cloudflare-dns\.com|dns\.google|dns\.quad9\.net|dns\.adguard\.com") {
                Write-Host "DoH Status :"
                Write-Host $netshOutput -ForegroundColor Green
                Write-Host "DoH est activé pour au moins un serveur DNS connu." -ForegroundColor Green
            } else {
                Write-Host "DoH Status:"
                Write-Host $netshOutput -ForegroundColor Yellow
                Write-Host "Aucun paramètre DoH détecté. Vérifiez que les serveurs DNS sont configurés et que le DoH a été appliqué correctement.." -ForegroundColor Yellow
            }
        } catch {
            Write-Host "Échec de la vérification de l'état de DoH : $_" -ForegroundColor Red
        }
        Pause-Menu
    }

    # Function to update hosts file with ad-blocking entries
function Update-HostsFile {
    Clear-Host
    Write-Host "==============================================="
    Write-Host "   Mise à jour du fichier hosts Windows avec blocage des publicités"
    Write-Host "==============================================="
    
    # Check for admin privileges. no needed add to start
    #if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    #    Write-Host "Error: This function requires administrator privileges." -ForegroundColor Red
    #   Write-Host "Please run the script as Administrator and try again."
    #    Pause-Menu
    #    return
    #}
    
    $hostsPath = "$env:windir\System32\drivers\etc\hosts"
    $backupDir = "$env:windir\System32\drivers\etc\hosts_backups"
    $dnsService = "Dnscache"
    $maxRetries = 3
    $retryDelay = 2 # seconds

    # List of mirrors to try (in order)
    $mirrors = @(
        "https://o0.pages.dev/Lite/hosts.win",
        "https://cdn.jsdelivr.net/gh/badmojr/1Hosts@master/Lite/hosts.win",
        "https://raw.githubusercontent.com/badmojr/1Hosts/master/Lite/hosts.win"
    )

    try {
        # ===== ENSURE BACKUP DIRECTORY EXISTS =====
        if (-not (Test-Path $backupDir)) {
            New-Item -ItemType Directory -Path $backupDir -Force | Out-Null
            Write-Host "Created backup directory: $backupDir" -ForegroundColor Green
        }

        # ===== CREATE BACKUP =====
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $uniqueBackupPath = "$backupDir\hosts_$timestamp.bak"
        
        if (Test-Path $hostsPath) {
            Write-Host "Création d'une sauvegarde du fichier hosts..."
            try {
                Copy-Item $hostsPath $uniqueBackupPath -Force
                Write-Host "Sauvegarde créée dans $uniqueBackupPath" -ForegroundColor Green
            } catch {
                Write-Host "Attention : Sauvegarde non créée - $($_.Exception.Message)" -ForegroundColor Yellow
                $uniqueBackupPath = $null
            }
        } else {
            Write-Host "Aucun fichier hosts existant trouvé – un nouveau fichier sera créé" -ForegroundColor Yellow
            $uniqueBackupPath = $null
        }

        # ===== DOWNLOAD WITH MIRROR FALLBACK =====
        $adBlockContent = $null
        $successfulMirror = $null

        foreach ($mirror in $mirrors) {
            Write-Host "`nTentative de téléchargement depuis : $mirror"
            
            try {
                $webClient = New-Object System.Net.WebClient
                $adBlockContent = $webClient.DownloadString($mirror)
                $successfulMirror = $mirror
                Write-Host "Fichier hosts téléchargé avec succès" -ForegroundColor Green
                break
            } catch [System.Net.WebException] {
                Write-Host "Échec du téléchargement : $($_.Exception.Message)" -ForegroundColor Yellow
                continue
            } catch {
                Write-Host "Erreur inconnu : $($_.Exception.Message)" -ForegroundColor Yellow
                continue
            } finally {
                if ($webClient -ne $null) {
                    $webClient.Dispose()
                }
            }
        }

        if (-not $adBlockContent) {
            throw "Tous les miroirs ont échoué ! Impossible de télécharger le fichier hosts de blocage des publicités.."
        }

        # ===== PREPARE NEW CONTENT =====
        $existingContent = if ($uniqueBackupPath -and (Test-Path $uniqueBackupPath)) {
            Get-Content $uniqueBackupPath | Where-Object {
                $_ -notmatch "^# Ad-blocking entries" -and 
                $_ -notmatch "^0\.0\.0\.0" -and 
                $_ -notmatch "^127\.0\.0\.1" -and
                $_ -notmatch "^::1" -and
                $_ -notmatch "^$"
            }
        } else { "" }
        
        $newContent = @"
# Ad-blocking entries - Updated $(Get-Date)
# Downloaded from: $successfulMirror
# Original hosts file backed up to: $(if ($uniqueBackupPath) { $uniqueBackupPath } else { "No backup created" })

$existingContent

$adBlockContent
"@

        # ===== UPDATE HOSTS FILE =====
        Write-Host "`nPréparation de la mise à jour du fichier hosts..."
        
        # Write new content with retry logic
        $attempt = 0
        $success = $false
        
        while (-not $success -and $attempt -lt $maxRetries) {
            $attempt++
            try {
                # Create temporary file
                $tempFile = [System.IO.Path]::GetTempFileName()
                [System.IO.File]::WriteAllText($tempFile, $newContent, [System.Text.Encoding]::UTF8)
                
                # Replace hosts file using cmd.exe for maximum reliability
                $tempDest = "$hostsPath.tmp"
                $copyCommand = @"
@echo off
if exist "$hostsPath" move /Y "$hostsPath" "$tempDest"
move /Y "$tempFile" "$hostsPath"
if exist "$tempDest" del /F /Q "$tempDest"
"@
                $batchFile = [System.IO.Path]::GetTempFileName() + ".cmd"
                [System.IO.File]::WriteAllText($batchFile, $copyCommand)
                
                Start-Process "cmd.exe" -ArgumentList "/c `"$batchFile`"" -Wait -WindowStyle Hidden
                Remove-Item $batchFile -Force
                
                if (Test-Path $tempFile) { Remove-Item $tempFile -Force }
                if (Test-Path $tempDest) { Remove-Item $tempDest -Force }
                
                $success = $true
                $entryCount = ($adBlockContent -split "`n").Count
                Write-Host "Fichier hosts mis à jour avec succès avec les entrées $entryCount de blocage des publicités." -ForegroundColor Green
            } catch {
                Write-Host "Tentative $attempt a échoué : $($_.Exception.Message)" -ForegroundColor Yellow
                if ($attempt -lt $maxRetries) {
                    Write-Host "Nouvelle tentative dans $retryDelay secondes..."
                    Start-Sleep -Seconds $retryDelay
                }
                # Clean up any temp files
                if (Test-Path $tempFile) { Remove-Item $tempFile -Force }
                if (Test-Path $tempDest) { Remove-Item $tempDest -Force }
            }
        }

        if (-not $success) {
            throw "Échec de la mise à jour du fichier hosts après $maxRetries tentatives."
        }

        # ===== FLUSH DNS =====
        Write-Host "Vider le cache DNS..."
        try {
            ipconfig /flushdns | Out-Null
            Write-Host "Le cache DNS a été vidé avec succès." -ForegroundColor Green
        } catch {
            Write-Host "Avertissement : Impossible de vider le cache DNS. Les modifications peuvent nécessiter un redémarrage." -ForegroundColor Yellow
        }

        # ===== CLEAN UP ALL BACKUPS =====
        if ($success -and $uniqueBackupPath) {
            Write-Host "`nVérification des fichiers de sauvegarde dans $backupDir..."
            
            # Get all backup files
            $allBackups = Get-ChildItem -Path $backupDir -Filter "hosts_*.bak" | 
                         Sort-Object CreationTime -Descending
            
            if ($allBackups.Count -gt 0) {
                Write-Host "Trouvé $($allBackups.Count) fichiers de sauvegarde :"
                $allBackups | ForEach-Object {
                    Write-Host "  - $($_.Name) (Créé : $($_.CreationTime))" -ForegroundColor Yellow
                }
                
                Write-Host "`nAVERTISSEMENT : la suppression de ces fichiers de sauvegarde est définitive et ils NE PEUVENT PAS être restaurés !" -ForegroundColor Red
                $confirm = Read-Host "Êtes-vous sûr de vouloir supprimer TOUS les $($allBackups.Count) fichiers de sauvegarde ? (O/1 pour Oui, N/0 pour Non)"
                if ($confirm -match '^[Oo1]$') {
                    $deletedCount = 0
                    $allBackups | ForEach-Object {
                        try {
                            Remove-Item $_.FullName -Force
                            Write-Host "Supprimé : $($_.Name)" -ForegroundColor Green
                            $deletedCount++
                        } catch {
                            Write-Host "Echec lors de la suppression de $($_.Name) : $($_.Exception.Message)" -ForegroundColor Red
                        }
                    }
                    Write-Host "Supprimé $deletedCount fichiers de sauvegarde." -ForegroundColor Green
                } else {
                    Write-Host "Conserver tous les fichiers de sauvegarde." -ForegroundColor Yellow
                }
            } else {
                Write-Host "Aucun fichier de sauvegarde trouvé dans $backupDir." -ForegroundColor Green
            }
        }

    } catch {
        Write-Host "`nERREUR : $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "La mise à jour du fichier hosts a échoué !" -ForegroundColor Red
        
        # Attempt to restore from backup
        if ($uniqueBackupPath -and (Test-Path $uniqueBackupPath)) {
            Write-Host "Tentative de restauration à partir d'une sauvegarde..."
            try {
                # Use cmd.exe for reliable file replacement
                $restoreCommand = @"
@echo off
if exist "$hostsPath" del /F /Q "$hostsPath"
copy /Y "$uniqueBackupPath" "$hostsPath"
"@
                $batchFile = [System.IO.Path]::GetTempFileName() + ".cmd"
                [System.IO.File]::WriteAllText($batchFile, $restoreCommand)
                
                Start-Process "cmd.exe" -ArgumentList "/c `"$batchFile`"" -Wait -WindowStyle Hidden
                Remove-Item $batchFile -Force
                
                Write-Host "Restauration du fichier hosts d'origine à partir d'une sauvegarde." -ForegroundColor Green
            } catch {
                Write-Host "ERREUR CRITIQUE : Impossible de restaurer la sauvegarde !" -ForegroundColor Red
                Write-Host "Récupération manuelle requise. Une sauvegarde existe dans :" -ForegroundColor Yellow
                Write-Host $uniqueBackupPath -ForegroundColor Yellow
                Write-Host "Vous devrez peut-être copier ce fichier dans $hostsPath manuellement" -ForegroundColor Yellow
            }
        } else {
            Write-Host "Aucune sauvegarde disponible pour la restauration." -ForegroundColor Red
            if (-not (Test-Path $hostsPath)) {
                Write-Host "Le fichier hosts n'existe pas à $hostsPath" -ForegroundColor Yellow
            }
        }
    }
    
    Pause-Menu
}
    # End of Function to update hosts file with ad-blocking entries, start of settings

    $dohSupported = Test-DoHSupport
    if (-not $dohSupported) {
        Write-Host "Attention : DNS sur HTTPS (DoH) n'est pas pris en charge sur ce système. L'option 5 ne sera pas disponible." -ForegroundColor Yellow
    }

    while ($true) {
        Clear-Host
        Write-Host "======================================================"
        Write-Host "Outils DNS / Réseau"
        Write-Host "======================================================"
        Write-Host "[1] Définir les DNS Google (8.8.8.8 / 8.8.4.4, IPv6)"
        Write-Host "[2] Définir les DNS Cloudflare (1.1.1.1 / 1.0.0.1, IPv6)"
        Write-Host "[3] Restaurer les DNS (DHCP)"
        Write-Host "[4] utilisez vos DNS (IPv4/IPv6)"
        if ($dohSupported) {
            Write-Host "[5] Crypter DNS : activer DoH à l'aide de netsh sur tous les serveurs DNS connus"
        }
        Write-Host "[6] Mettre à jour le fichier hosts avec blocage de publicités"
        Write-Host "[0] Retour au menu"
        Write-Host "======================================================"
        $dns_choice = Read-Host "Entrer votre choix"
        switch ($dns_choice) {
            "1" {
                $adapters = Get-ActiveAdapters
                if (!$adapters) { Write-Host "Aucune carte réseau active n'a été trouvée !" -ForegroundColor Red; Pause-Menu; return }
                Write-Host "Application des DNS Google (IPv4: 8.8.8.8/8.8.4.4, IPv6: 2001:4860:4860::8888/2001:4860:4860::8844) à :"
                foreach ($adapter in $adapters) {
                    Write-Host "  - $adapter"
                    $dnsAddresses = @("8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844")
                    try {
                        Set-DnsClientServerAddress -InterfaceAlias $adapter -ServerAddresses $dnsAddresses -ErrorAction Stop
                        Write-Host "  - Les DNS Google ont été appliqués avec succès pour $adapter" -ForegroundColor Green
                    } catch {
                        Write-Host "  - Échec de la configuration des DNS Google pour : $_" -ForegroundColor Yellow
                    }
                }
                Write-Host "Terminé. DNS Google configuré avec IPv4 et IPv6."
                Write-Host " Pour activer DoH, utilisez l'option [5] ou configurez manuellement dans les paramètres."
                Pause-Menu
                return
            }
            "2" {
                $adapters = Get-ActiveAdapters
                if (!$adapters) { Write-Host "Aucune carte réseau active n'a été trouvée !" -ForegroundColor Red; Pause-Menu; return }
                Write-Host "Application des DNS Cloudflare (IPv4: 1.1.1.1/1.0.0.1, IPv6: 2606:4700:4700::1111/2606:4700:4700::1001) à :"
                foreach ($adapter in $adapters) {
                    Write-Host "  - $adapter"
                    $dnsAddresses = @("1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001")
                    try {
                        Set-DnsClientServerAddress -InterfaceAlias $adapter -ServerAddresses $dnsAddresses -ErrorAction Stop
                        Write-Host "  - Les DNS Cloudflare ont été appliqués avec succès pour $adapter" -ForegroundColor Green
                    } catch {
                        Write-Host "  - Échec de la configuration des DNS Cloudflare pour $adapter : $_" -ForegroundColor Yellow
                    }
                }
                Write-Host "Terminé. DNS Cloudflare configuré avec IPv4 et IPv6."
                Write-Host "Pour activer DoH, utilisez l'option [5] ou configurez manuellement dans les paramètres."
                Pause-Menu
                return
            }
            "3" {
                $adapters = Get-ActiveAdapters
                if (!$adapters) { Write-Host "Aucune carte réseau active n'a été trouvée !" -ForegroundColor Red; Pause-Menu; return }
                Write-Host "Restauration automatique du DNS (DHCP) :"
                foreach ($adapter in $adapters) {
                    Write-Host "  - $adapter"
                    try {
                        Set-DnsClientServerAddress -InterfaceAlias $adapter -ResetServerAddresses -ErrorAction Stop
                        Write-Host "  - DNS réglé sur automatique pour $adapter" -ForegroundColor Green
                    } catch {
                        Write-Host "  - Échec de la réinitialisation du DNS pour $adapter : $_" -ForegroundColor Yellow
                    }
                }
                Write-Host "Terminé. DNS défini sur automatique."
                Pause-Menu
                return
            }
            "4" {
                $adapters = Get-ActiveAdapters
                if (!$adapters) { Write-Host "Aucune carte réseau active n'a été trouvée !" -ForegroundColor Red; Pause-Menu; return }
                while ($true) {
                    Clear-Host
                    Write-Host "==============================================="
                    Write-Host "          Enter your custom DNS"
                    Write-Host "==============================================="
                    Write-Host "Saisissez au moins un serveur DNS (IPv4 ou IPv6). Les adresses multiples peuvent être séparées par des virgules.."
                    $customDNS = Read-Host "Entrez les adresses DNS (Exemple : 8.8.8.8,2001:4860:4860::8888)"
                    Clear-Host
                    Write-Host "==============================================="
                    Write-Host "         Validation des adresses DNS..."
                    Write-Host "==============================================="
                    $dnsAddresses = $customDNS.Split(",", [StringSplitOptions]::RemoveEmptyEntries) | ForEach-Object { $_.Trim() }
                    if ($dnsAddresses.Count -eq 0) {
                        Write-Host "[!] ERREUR : Aucune adresse DNS saisie." -ForegroundColor Red
                        Pause-Menu
                        continue
                    }
                    $validDnsAddresses = @()
                    $allValid = $true
                    foreach ($dns in $dnsAddresses) {
                        $isIPv6 = $dns -match ":"
                        $reachable = Test-Connection -ComputerName $dns -Count 1 -Quiet -ErrorAction SilentlyContinue
                        if ($reachable) {
                            $validDnsAddresses += $dns
                            Write-Host "Validé : $dns" -ForegroundColor Green
                        } else {
                            Write-Host "[!] ERREUR : l'adresse DNS `"$dns`" n'est pas accessible et sera ignorée." -ForegroundColor Yellow
                            $allValid = $false
                        }
                    }
                    if ($validDnsAddresses.Count -eq 0) {
                        Write-Host "[!] ERREUR : Aucune adresse DNS valide fournie." -ForegroundColor Red
                        Pause-Menu
                        continue
                    }
                    break
                }
                Clear-Host
                Write-Host "==============================================="
                Write-Host "    Configuration DNS pour tous les adaptateurs actifs..."
                Write-Host "==============================================="
                foreach ($adapter in $adapters) {
                    Write-Host "  - $adapter"
                    try {
                        Set-DnsClientServerAddress -InterfaceAlias $adapter -ServerAddresses $validDnsAddresses -ErrorAction Stop
                        Write-Host "  - DNS personnalisé appliqué avec succès sur $adapter" -ForegroundColor Green
                    } catch {
                        Write-Host "  - Échec de la configuration du DNS personnalisé sur $adapter : $_" -ForegroundColor Yellow
                    }
                }
                Write-Host
                Write-Host "==============================================="
                Write-Host "    e DNS a été mis à jour avec succès :"
                foreach ($dns in $validDnsAddresses) {
                    Write-Host "      - $dns"
                }
                Write-Host "Pour activer DoH, utilisez l'option [5] ou configurez manuellement dans les paramètres."
                Write-Host "==============================================="
                Pause-Menu
                return
            }
            "5" {
                if (-not $dohSupported) {
                    Write-Host "Error: DoH is not supported on this system. Option 5 is unavailable." -ForegroundColor Red
                    Pause-Menu
                    return
                }
                $dohApplied = Enable-DoHAllServers
                while ($true) {
                    Clear-Host
                    Write-Host "======================================================"
                    Write-Host "Menu de configuration DoH"
                    Write-Host "======================================================"
                    if ($dohApplied) {
                        Write-Host "DoH a été appliqué pour $successCount serveurs DNS."
                    } else {
                        Write-Host "Échec de l'application DoH. Vérifiez les permissions système ou la version de Windows."
                    }
                    Write-Host "[1] Vérifier l'état DoH"
                    Write-Host "[2] Return au menu"
                    Write-Host "======================================================"
                    $doh_choice = Read-Host "Entrer votre choix"
                    switch ($doh_choice) {
                        "1" { Check-DoHStatus }
                        "2" { return }
                        default { Write-Host "Choix non valide, veuillez réessayer." -ForegroundColor Red; Pause-Menu }
                    }
                }
            }
            "6" { Update-HostsFile }
            "0" { return }
            default { Write-Host "Choix non valide, veuillez réessayer." -ForegroundColor Red; Pause-Menu }
        }
    }
}

function Choice-6 { Clear-Host; Write-Host "Affichage des informations sur le réseau..."; ipconfig /all; Pause-Menu }

function Choice-7 {
    Clear-Host
    Write-Host "=========================================="
    Write-Host "    Redémarrage de tous les adaptateurs Wi-Fi..."
    Write-Host "=========================================="

    $wifiAdapters = Get-NetAdapter | Where-Object { $_.InterfaceDescription -match "Wi-Fi|Wireless" -and $_.Status -eq "Up" -or $_.Status -eq "Disabled" }

    if (-not $wifiAdapters) {
        Write-Host "Aucun adaptateur Wi-Fi trouvé!"
        Pause-Menu
        return
    }

    foreach ($adapter in $wifiAdapters) {
        Write-Host "Redémarrage de '$($adapter.Name)'..."

        Disable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        Enable-NetAdapter -Name $adapter.Name -Confirm:$false -ErrorAction SilentlyContinue

        Start-Sleep -Seconds 5

        # Check connection
        $status = Get-NetAdapter -Name $adapter.Name
        if ($status.Status -eq "Up") {
            Write-Host "SUCCÈS : '$($adapter.Name)' est de nouveau fonctionnel !" -ForegroundColor Green
        } else {
            Write-Host "ATTENTION : '$($adapter.Name)' n'est pas fonctionnel !" -ForegroundColor Yellow
        }
    }

    Pause-Menu
}


function Choice-8 {
    function Get-ActiveDHCPInterfaces {
        Get-NetIPConfiguration |
        Where-Object {
            $_.NetAdapter.Status -eq 'Up' -and
            $_.NetAdapter.InterfaceDescription -notmatch 'Wi-Fi|Wireless|WLAN|Wireless|Wintun|Virtualbox|VMware|Wintun|Loopback|Bluetooth|Hyper-V|Ndis|Miniport|TAP|QEMU|Cisco|Teredo|ISATAP|vEthernet|Bridge'
        } |
        Where-Object { $_.DHCP -eq 'Enabled' }
    }
    $Host.UI.RawUI.WindowTitle = "Réparation réseau - Dépannage automatique"
    Clear-Host
    Write-Host
    Write-Host "===================================="
    Write-Host "  Réparation automatique du réseau  "
    Write-Host "===================================="
    Write-Host
    $dhcpAdapters = Get-ActiveDHCPInterfaces
    if ($dhcpAdapters.Count -gt 0) {
        Write-Host "Étape 1 : DHCP détecté. Renouvellement de votre adresse IP..."
        ipconfig /release | Out-Null
        ipconfig /renew  | Out-Null
        Write-Host
    } else {
        Write-Host "Étape 1 : Aucune interface réseau en DHCP. Aucun renouvellement nécessaire."
        Write-Host
    }
    Write-Host "Étape 2 : Actualisation des paramètres DNS..."
    ipconfig /flushdns | Out-Null
    Write-Host
    Write-Host "Étape 3 : Réinitialisation des composants réseau..."
    netsh winsock reset | Out-Null
    netsh int ip reset  | Out-Null
    Write-Host
    Write-Host "Vos paramètres réseau ont été actualisés."
    Write-Host "Un redémarrage du PC est recommandé."
    Write-Host
    while ($true) {
        $restart = Read-Host "Souhaitez-vous redémarrer maintenant ? (O/N)"
        switch ($restart.ToUpper()) {
            "O" { shutdown /r /t 5; return }
            "N" { return }
            default { Write-Host "Entrée invalide. Veuillez saisir O ou N." }
        }
    }
}

function Choice-9 {
    $Host.UI.RawUI.WindowTitle = "Gestionnaire de pare-feu"
    Clear-Host
    Write-Host
    Write-Host "==============================="
    Write-Host "      Gestionnaire de pare-feu"
    Write-Host "==============================="
    Write-Host
    
    # Main program loop - adapted from the original script
    do {
        Write-Host
        Write-Host "1: Afficher et gérer les règles de pare-feu"
        Write-Host "2: Exporter les règles de pare-feu au format CSV"
        Write-Host "3: Importer les règles de pare-feu au format CSV"
        Write-Host "0: Retour au menu principal"
        Write-Host
        
        $selection = Read-Host "Veuillez choisir une sélection"
        
        switch ($selection.ToUpper()) {
            '1' {
                do {
                    Clear-Host
                    Write-Host
                    Write-Host "==============================="
                    Write-Host "      Règles Pare-Feu"
                    Write-Host "==============================="
                    Write-Host
                    
                    # Sort rules alphabetically by DisplayName
                    $rules = Get-NetFirewallRule | Sort-Object -Property DisplayName
                    $count = 1
                    
                    Write-Host "#  Action   Active   Règle   Nom"
                    Write-Host "--  ------   -------   ---------"
                    
                    foreach ($rule in $rules) {
                        $action = $rule.Action.ToString().PadRight(6)
                        $enabled = if ($rule.Enabled -eq $true) { "Oui" } else { "Non" }
                        $cleanName = Get-CleanRuleName -name $rule.DisplayName
                        if ([string]::IsNullOrWhiteSpace($cleanName)) {
                            $cleanName = Get-CleanRuleName -name $rule.Name
                        }
                        Write-Host "$($count.ToString().PadLeft(2))  $action   $($enabled.PadRight(7))   $cleanName"
                        $count++
                    }
                    
                    Write-Host
                    Write-Host "1: Activer une règle (type '1 NUMBER')"
                    Write-Host "2: Désactiver une règle (type '2 NUMBER')"
                    Write-Host "3: Ajouter une règle"
                    Write-Host "4: Supprimer une règle (type '4 NUMBER')"
                    Write-Host "0: Retour"
                    Write-Host
                    
                    $input = Read-Host "Saisissez l'action et le numéro (par exemple, « 2 5 ») ou 0 pour revenir"
                    
                    if ($input -eq '0') { break }
                    
                    $parts = $input -split '\s+'
                    $action = $parts[0]
                    $ruleNum = if ($parts.Count -gt 1) { $parts[1] } else { $null }
                    
                    if (@('1','2','4') -contains $action -and ($ruleNum -notmatch '^\d+$')) {
                        Write-Host "Numéro de règle invalide" -ForegroundColor Red
                        Write-Host "Appuyez sur n'importe quelle touche pour continuer..."
                        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                        continue
                    }
                    
                    switch ($action) {
                        '1' { 
                            $rules = @(Get-NetFirewallRule | Sort-Object -Property DisplayName)
                            if ($ruleNum -gt 0 -and $ruleNum -le $rules.Count) {
                                $rule = $rules[$ruleNum - 1]
                                $ruleName = Get-CleanRuleName -name $rule.DisplayName
                                try {
                                    Set-NetFirewallRule -Name $rule.Name -Enabled True -ErrorAction Stop
                                    Write-Host "Règle activée : $ruleName" -ForegroundColor Green
                                } catch {
                                    Write-Host "Échec de l'activation de la règle $ruleName`: $_" -ForegroundColor Red
                                }
                            } else {
                                Write-Host "Numéro de règle invalide" -ForegroundColor Red
                            }
                            Write-Host "Appuyez sur n'importe quelle touche pour continuer..."
                            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                        }
                        '2' { 
                            $rules = @(Get-NetFirewallRule | Sort-Object -Property DisplayName)
                            if ($ruleNum -gt 0 -and $ruleNum -le $rules.Count) {
                                $rule = $rules[$ruleNum - 1]
                                $ruleName = Get-CleanRuleName -name $rule.DisplayName
                                try {
                                    Set-NetFirewallRule -Name $rule.Name -Enabled False -ErrorAction Stop
                                    Write-Host "Règle déssactivée : $ruleName" -ForegroundColor Green
                                } catch {
                                    Write-Host "Échec de la désactivation de la règle $ruleName`: $_" -ForegroundColor Red
                                }
                            } else {
                                Write-Host "Numéro de règle invalide" -ForegroundColor Red
                            }
                            Write-Host "Appuyez sur n'importe quelle touche pour continuer..."
                            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                        }
                        '3' { 
                            Clear-Host
                            Write-Host
                            Write-Host "==============================="
                            Write-Host "      Ajouter une nouvelle règle de pare-feu"
                            Write-Host "==============================="
                            Write-Host
                            
                            $displayName = Read-Host "Enter a display name for the rule"
                            $name = Read-Host "Enter a unique name for the rule (no spaces, use hyphens)"
                            $description = Read-Host "Enter a description for the rule"
                            
                            do {
                                $direction = Read-Host "Enter direction (Inbound/Outbound)"
                            } while ($direction -notin "Inbound", "Outbound")
                            
                            do {
                                $action = Read-Host "Enter action (Allow/Block)"
                            } while ($action -notin "Allow", "Block")
                            
                            do {
                                $profile = Read-Host "Enter profile (Domain, Private, Public, Any)"
                            } while ($profile -notin "Domain", "Private", "Public", "Any")
                            
                            do {
                                $protocol = Read-Host "Enter protocol (TCP, UDP, ICMP, Any)"
                            } while ($protocol -notin "TCP", "UDP", "ICMP", "Any")
                            
                            $localPort = Read-Host "Enter local port (leave blank for any)"
                            $remotePort = Read-Host "Enter remote port (leave blank for any)"
                            $program = Read-Host "Enter program path (leave blank for any)"
                            
                            try {
                                $params = @{
                                    DisplayName = $displayName
                                    Name        = $name
                                    Description = $description
                                    Direction   = $direction
                                    Action      = $action
                                    Profile     = $profile
                                    Protocol    = $protocol
                                }
                                
                                if ($localPort) { $params['LocalPort'] = $localPort }
                                if ($remotePort) { $params['RemotePort'] = $remotePort }
                                if ($program) { $params['Program'] = $program }
                                
                                New-NetFirewallRule @params
                                Write-Host "Firewall rule created: $displayName" -ForegroundColor Green
                            } catch {
                                Write-Host "Failed to create rule: $_" -ForegroundColor Red
                            }
                            Write-Host "Appuyez sur n'importe quelle touche pour continuer..."
                            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                        }
                        '4' { 
                            $rules = @(Get-NetFirewallRule | Sort-Object -Property DisplayName)
                            if ($ruleNum -gt 0 -and $ruleNum -le $rules.Count) {
                                $rule = $rules[$ruleNum - 1]
                                $ruleName = Get-CleanRuleName -name $rule.DisplayName
                                try {
                                    Remove-NetFirewallRule -Name $rule.Name -ErrorAction Stop
                                    Write-Host "Removed rule: $ruleName" -ForegroundColor Green
                                } catch {
                                    Write-Host "Failed to remove rule $ruleName`: $_" -ForegroundColor Red
                                }
                            } else {
                                Write-Host "Numéro de règle invalide" -ForegroundColor Red
                            }
                            Write-Host "Appuyez sur n'importe quelle touche pour continuer..."
                            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                        }
                        default { 
                            Write-Host "Invalid action" -ForegroundColor Red
                            Write-Host "Appuyez sur n'importe quelle touche pour continuer..."
                            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                        }
                    }
                } while ($true)
            }
            '2' {
                Clear-Host
                Write-Host
                Write-Host "==============================="
                Write-Host "      Export Firewall Rules"
                Write-Host "==============================="
                Write-Host
                
                $defaultPath = "$env:USERPROFILE\Desktop\firewall_rules_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
                $filePath = Read-Host "Enter the file path to save the CSV (default: $defaultPath)"
                
                if ([string]::IsNullOrWhiteSpace($filePath)) {
                    $filePath = $defaultPath
                }
                
                try {
                    Get-NetFirewallRule | Sort-Object -Property DisplayName | Export-Csv -Path $filePath -NoTypeInformation
                    Write-Host "Rules exported to $filePath" -ForegroundColor Green
                } catch {
                    Write-Host "Export failed: $_" -ForegroundColor Red
                }
                Write-Host "Appuyez sur n'importe quelle touche pour continuer..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            '3' {
                Clear-Host
                Write-Host
                Write-Host "==============================="
                Write-Host "      Import Firewall Rules"
                Write-Host "==============================="
                Write-Host
                
                $defaultPath = "$env:USERPROFILE\Desktop\firewall_rules.csv"
                $filePath = Read-Host "Enter the file path of the CSV to import (default looks on Desktop for firewall_rules.csv)"
                
                if ([string]::IsNullOrWhiteSpace($filePath)) {
                    $filePath = $defaultPath
                }
                
                if (Test-Path $filePath) {
                    try {
                        $rules = Import-Csv -Path $filePath
                        $successCount = 0
                        $errorCount = 0
                        
                        foreach ($rule in $rules) {
                            try {
                                $params = @{
                                    DisplayName = $rule.DisplayName
                                    Name        = $rule.Name
                                    Description = $rule.Description
                                    Direction   = $rule.Direction
                                    Action      = $rule.Action
                                    Profile     = $rule.Profile
                                    Enabled     = if ($rule.Enabled -eq "True") { $true } else { $false }
                                }
                                
                                New-NetFirewallRule @params
                                $successCount++
                            } catch {
                                $errorCount++
                                Write-Host "Error importing rule $($rule.DisplayName): $_" -ForegroundColor Yellow
                            }
                        }
                        
                        Write-Host "Import completed: $successCount succeeded, $errorCount failed" -ForegroundColor Green
                    } catch {
                        Write-Host "Import failed: $_" -ForegroundColor Red
                    }
                } else {
                    Write-Host "File not found: $filePath" -ForegroundColor Red
                }
                Write-Host "Appuyez sur n'importe quelle touche pour continuer..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            '0' { return }
            default { 
                Write-Host "Invalid selection" -ForegroundColor Red
                Write-Host "Appuyez sur n'importe quelle touche pour continuer..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
        }
    } while ($true)
}

# Helper function needed by Choice-9
function Get-CleanRuleName {
    param ([string]$name)
    if ($name -match '@{.+?}\(?(.+?)\)?$') { $name = $matches[1] }
    if ($name -match '(.+?)_\d+\.\d+\.\d+\.\d+_x64__.+') { $name = $matches[1] + "_x64" }
    elseif ($name -match '(.+?)_\d+\.\d+\.\d+\.\d+_.+') { $name = $matches[1] }
    $name = $name -replace '({[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}})', ''
    return $name.Trim()
}

function Choice-10 { Clear-Host; Write-Host "Exécution du nettoyage de disque..."; Start-Process "cleanmgr.exe"; Pause-Menu }

function Choice-11 {
    Clear-Host
    Write-Host "==============================================="
    Write-Host "Exécution d'une analyse avancée sur tous les lecteurs..."
    Write-Host "==============================================="
    $drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -ne $null } | Select-Object -ExpandProperty Name
    foreach ($drive in $drives) {
        Write-Host
        Write-Host "Vérification du disque $drive` :" ...
        chkdsk "${drive}:" /f /r /x
    }
    Write-Host
    Write-Host "Tous les lecteurs ont été analysés."
    Pause-Menu
}

function Choice-12 {
    Clear-Host
    Write-Host "==============================================="
    Write-Host "   Supprimer les fichiers temporaires et le cache système"
    Write-Host "==============================================="
    Write-Host
    Write-Host "Ceci supprimera définitivement les fichiers temporaires pour votre utilisateur et Windows.."
    Write-Host "Attention : Fermez toutes les applications pour éviter les conflits de fichiers."
    Write-Host

    $deleteOption = ""
    while ($true) {
        Write-Host "==============================================="
        Write-Host "   Choisir une option de nettoyage"
        Write-Host "==============================================="
        Write-Host "[1] Supprimer définitivement les fichiers temporaires"
        Write-Host "[2] Supprimer définitivement les fichiers temporaires et vider la corbeille"
        Write-Host "[3] Nettoyage avancé de la confidentialité (inclut les fichiers temporaires et les données confidentielles)"
        Write-Host "[0] Annuler"
        Write-Host
        $optionChoice = Read-Host "Sélectionner une option"
        switch ($optionChoice) {
            "1" { $deleteOption = "DeleteOnly"; break }
            "2" { $deleteOption = "DeleteAndEmpty"; break }
            "3" { $deleteOption = "PrivacyCleanup"; break }
            "0" {
                Write-Host "Opération annulée." -ForegroundColor Yellow
                Pause-Menu
                return
            }
            default { Write-Host "Saisie non valide. Veuillez saisir 1, 2, 3 ou 0." -ForegroundColor Red }
        }
        if ($deleteOption) { break }
    }

    # Define paths to clean (remove redundant paths)
    $paths = @(
        $env:TEMP,              # User temp folder
        "C:\Windows\Temp",      # System temp folder
        $env:LOCALAPPDATA\Temp  # temp folder
    )

    # Remove duplicates
    $paths = $paths | Select-Object -Unique

    # Load assembly for Recycle Bin if needed (only for DeleteAndEmpty option)
    if ($deleteOption -eq "DeleteAndEmpty" -or $deleteOption -eq "PrivacyCleanup") {
        try {
            Add-Type -AssemblyName Microsoft.VisualBasic -ErrorAction Stop
        } catch {
            Write-Host "ERREUR] Échec du chargement de l'assembly Microsoft.VisualBasic pour les opérations de la Corbeille.." -ForegroundColor Red
            Write-Host "Suppression en cours (la Corbeille ne sera pas vidée)." -ForegroundColor Yellow
            $deleteOption = "DeleteOnly"
        }
    }

    $deletedCount = 0
    $skippedCount = 0

    # Perform permanent deletion
    foreach ($path in $paths) {
        # Validate path
        if (-not (Test-Path $path)) {
            Write-Host "[ERREUR] Le chemin n'existe pas : $path" -ForegroundColor Red
            continue
        }

        # Additional safety check for user temp path
        if ($path -eq $env:TEMP -and -not ($path.ToLower() -like "*$($env:USERNAME.ToLower())*")) {
            Write-Host "[ERREUR] Chemin temporaire non sécurisé ou non valide : $path" -ForegroundColor Red
            Write-Host "Ignorer pour éviter d'endommager le système." -ForegroundColor Red
            continue
        }

        Write-Host "Nettoyage du chemin : $path"
        try {
            Get-ChildItem -Path $path -Recurse -Force -ErrorAction Stop | ForEach-Object {
                try {
                    Remove-Item -Path $_.FullName -Force -Recurse -ErrorAction Stop
                    if ($_.PSIsContainer) {
                        Write-Host "Répertoire supprimé définitivement : $($_.FullName)" -ForegroundColor Green
                    } else {
                        Write-Host "Fichier supprimé définitivement : $($_.FullName)" -ForegroundColor Green
                    }
                    $deletedCount++
                } catch {
                    $skippedCount++
                    Write-Host "Ignoré : $($_.FullName) ($($_.Exception.Message))" -ForegroundColor Yellow
                }
            }
        } catch {
            Write-Host "Erreur lors du traitement du chemin path : $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # Empty Recycle Bin if selected
    if ($deleteOption -eq "DeleteAndEmpty" -or $deleteOption -eq "PrivacyCleanup") {
        try {
            Write-Host "Vidage de la corbeille..." -ForegroundColor Green
            [Microsoft.VisualBasic.FileIO.FileSystem]::DeleteDirectory(
                "C:\`$Recycle.Bin",
                'OnlyErrorDialogs',
                'DeletePermanently'
            )
            Write-Host "La corbeille a été vidée avec succès." -ForegroundColor Green
        } catch {
            Write-Host "Erreur lors du vidage de la corbeille : $($_.Exception.Message)" -ForegroundColor Red
        }
    }

    # Perform privacy cleanup if selected
    if ($deleteOption -eq "PrivacyCleanup") {
        Write-Host
        Write-Host "==============================================="
        Write-Host "   Exécution du nettoyage avancé de la confidentialité"
        Write-Host "==============================================="
        
        # Clear Activity History
        try {
            Write-Host "Effacement de l'historique des activités..."
            reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist" /f 2>&1 | Out-Null
            Write-Host "Historique des activités supprimés ave succès." -ForegroundColor Green
        } catch {
            Write-Host "Échec lors du nettoyage de l'historique des activités : $_" -ForegroundColor Yellow
        }

        # Clear Location History
        try {
            Write-Host "Effacement de l'historique des positions..."
            Get-Process LocationNotificationWindows -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
            reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" /f 2>&1 | Out-Null
            Write-Host "Historique des positions supprimés avec succès." -ForegroundColor Green
        } catch {
            Write-Host "Échec de l'effacement de l'historique des positions : $_" -ForegroundColor Yellow
        }

        # Clear Diagnostic Data
        try {
            Write-Host "Effacement des données de diagnostic..."
            wevtutil cl Microsoft-Windows-Diagnostics-Performance/Operational 2>&1 | Out-Null
            Write-Host "Données de diagnostic effacées avec succès." -ForegroundColor Green
        } catch {
            Write-Host "Échec de la suppression des données de diagnostic : $_" -ForegroundColor Yellow
        }

        # Additional privacy cleanup commands
        try {
            Write-Host "Suppression des éléments récents..."
            Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Recent\*" -Force -Recurse -ErrorAction SilentlyContinue
            Write-Host "Éléments récents effacés avec succès." -ForegroundColor Green
        } catch {
            Write-Host "Échec de la suppression des éléments récents : $_" -ForegroundColor Yellow
        }

        try {
            Write-Host "Suppression du cache des vignettes..."
            Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db" -Force -ErrorAction SilentlyContinue
            Write-Host "Cache des vignettes effacés avec succès." -ForegroundColor Green
        } catch {
            Write-Host "Échec de la suppression du cache des vignettes : $_" -ForegroundColor Yellow
        }
    }

    Write-Host
    Write-Host "Nettoyage terminé. $deletedCount fichiers/répertoires ont été traités. $skippedCount fichiers/répertoires ont été ignorés." -ForegroundColor Green
    if ($deleteOption -eq "PrivacyCleanup") {
        Write-Host "Les données relatives à la confidentialité ont également été supprimées."
    } else {
        Write-Host "Les fichiers et répertoires ont été définitivement supprimés."
    }

    Pause-Menu
}

function Choice-13 {
    while ($true) {
        Clear-Host
        Write-Host "======================================================"
        Write-Host " Nettoyage et optimisation avancés du registre"
        Write-Host "======================================================"
        Write-Host " [1] Liste des clés de registre 'sûres à supprimer' sous Désinstaller"
        Write-Host " [2] Supprimer toutes les clés de registre 'sûres à supprimer' (avec sauvegarde)"
        Write-Host " [3] Créer une sauvegarde du registre"
        Write-Host " [4] Restaurer la sauvegarde du registre"
        Write-Host " [5] Rechercher les entrées de registre corrompues"
        Write-Host " [0] Retour au menu principal"
        Write-Host
        $rchoice = Read-Host "Entrez votre choix"
        switch ($rchoice) {
            "1" {
                Write-Host
                Write-Host "Liste des clés de registre correspondant à : IE40, IE4Data, DirectDrawEx, DXM_Runtime, SchedulingAgent"
                Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall |
                  Where-Object { $_.PSChildName -match 'IE40|IE4Data|DirectDrawEx|DXM_Runtime|SchedulingAgent' } |
                  ForEach-Object { Write-Host $_.PSChildName }
                Pause
            }
            "2" {
    Write-Host
    $backupFolder = "$env:SystemRoot\Temp\RegistryBackups"
    if (-not (Test-Path $backupFolder)) { New-Item -Path $backupFolder -ItemType Directory | Out-Null }

    $now = Get-Date
    $existingBackup = Get-ChildItem -Path $backupFolder -Filter "RegistryBackup_*.reg" |
        Where-Object { ($now - $_.CreationTime).TotalMinutes -lt 10 } |  # backup within last 10 min
        Sort-Object CreationTime -Descending | Select-Object -First 1

    $backupFile = $null
    if ($existingBackup) {
        Write-Host "Une sauvegarde récente existe déjà : $($existingBackup.Name)"
        $useOld = Read-Host "Utilisez cette sauvegarde ? (O/n)"
        if ($useOld -notin @("n", "N")) {
            $backupFile = $existingBackup.FullName
            Write-Host "Utilisation de la sauvegarde existante : $backupFile"
        } else {
            $backupName = "RegistryBackup_{0}.reg" -f ($now.ToString("yyyy-MM-dd_HH-mm"))
            $backupFile = Join-Path $backupFolder $backupName
            reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" $backupFile /y | Out-Null
            Write-Host "Nouvelle sauvegarde créée : $backupFile" -ForegroundColor Green
        }
    } else {
        $backupName = "RegistryBackup_{0}.reg" -f ($now.ToString("yyyy-MM-dd_HH-mm"))
        $backupFile = Join-Path $backupFolder $backupName
        reg export "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" $backupFile /y | Out-Null
        Write-Host "Sauvegarde créée : $backupFile" -ForegroundColor Green
    }

    Write-Host "`nSuppression des clés de registre correspondantes : IE40, IE4Data, DirectDrawEx, DXM_Runtime, SchedulingAgent"
    $keys = Get-ChildItem HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall |
        Where-Object { $_.PSChildName -match 'IE40|IE4Data|DirectDrawEx|DXM_Runtime|SchedulingAgent' }
    
    if ($keys) {
        foreach ($key in $keys) {
            try {
                Remove-Item $key.PSPath -Recurse -Force -ErrorAction Stop
                Write-Host "Supprimé :" $key.PSChildName -ForegroundColor Green
            } catch {
                Write-Host "ERREUR de suppression :" $key.PSChildName "($_.Exception.Message)" -ForegroundColor Red
            }
        }
    } else {
        Write-Host "Aucune clé de registre correspondante trouvée."
    }
    Pause
}

            "3" {
                $backupFolder = "$env:SystemRoot\Temp\RegistryBackups"
                if (-not (Test-Path $backupFolder)) { New-Item -Path $backupFolder -ItemType Directory | Out-Null }
                $backupName = "RegistryBackup_{0}.reg" -f (Get-Date -Format "yyyy-MM-dd_HH-mm")
                $backupFile = Join-Path $backupFolder $backupName
                reg export HKLM $backupFile /y
                Write-Host "Sauvegarde HKLM complète créée : $backupFile"
                Pause
            }
            "4" {
                $backupFolder = "$env:SystemRoot\Temp\RegistryBackups"
                Write-Host "Sauvegardes disponibles :"
                Get-ChildItem "$backupFolder\*.reg" | ForEach-Object { Write-Host $_.Name }
                $backupFile = Read-Host "Entrez le nom du fichier à restaurer"
                $fullBackup = Join-Path $backupFolder $backupFile
                if (Test-Path $fullBackup) {
                    reg import $fullBackup
                    Write-Host "Sauvegarde restaurée avec succès." -ForegroundColor Green
                } else {
                    Write-Host "Fichier non trouvé." -ForegroundColor Red
                }
                Pause
            }
            "5" {
                Clear-Host
                Write-Host "Vérification de l'intégrité du système..."
                Start-Process "cmd.exe" "/c sfc /scannow" -Wait
                Start-Process "cmd.exe" "/c dism /online /cleanup-image /checkhealth" -Wait
                Write-Host "Veuillez consulter le fichier C:\Windows\Logs\DISM\Dism.log et C:\Windows\Logs\CBS\CBS.log dans le dossier"
                Write-Host "Si une ou plusieurs erreurs ont été rencontrés, veuillez re-exécuter le script en redémarrant à chaque fois sinon il faudra envisager une réparation/réinstallation du système."
                Pause
            }
            "0" { return }
            default { Write-Host "Entrée invalide, veuillez reéssayez."; Pause }
        }
    }
}


function Choice-14 {
    Clear-Host
    Write-Host "=========================================="
    Write-Host "     Optimisation SSD (ReTrim/TRIM)"
    Write-Host "=========================================="
    Write-Host "Cela optimisera automatiquement (TRIM) tous les SSD détectés."
    Write-Host
    Write-Host "Liste de tous les disques SSD détectés..."

    $ssds = Get-PhysicalDisk | Where-Object MediaType -eq 'SSD'
    if (-not $ssds) {
        Write-Host "Pas de SSD trouvés."
        Pause-Menu
        return
    }

    $log = "$env:USERPROFILE\Desktop\SSD_OPTIMIZE_{0}.log" -f (Get-Date -Format "yyyy-MM-dd_HHmmss")
    $logContent = @()
    $logContent += "Optimisation SSD Log - $(Get-Date)"

    foreach ($ssd in $ssds) {
        $disk = Get-Disk | Where-Object { $_.FriendlyName -eq $ssd.FriendlyName }
        if ($disk) {
            $volumes = $disk | Get-Partition | Get-Volume | Where-Object DriveLetter -ne $null
            foreach ($vol in $volumes) {
                Write-Host "Optimisation SSD : $($vol.DriveLetter):"
                $logContent += "Optimisation SSD : $($vol.DriveLetter):"
                $result = Optimize-Volume -DriveLetter $($vol.DriveLetter) -ReTrim -Verbose 4>&1
                $logContent += $result
            }
        } else {
            $logContent += "Impossible de trouver le disque pour SSD : $($ssd.FriendlyName)"
        }
    }
    Write-Host
    Write-Host "Optimisation du SSD terminée. Fichier journal enregistré sur le bureau : $log"
    $logContent | Out-File -FilePath $log -Encoding UTF8
    Pause-Menu
}

function Choice-15 {
    Clear-Host
    Write-Host "==============================================="
    Write-Host "     Gestion des tâches planifiées [Admin]"
    Write-Host "==============================================="
    Write-Host "Lister toutes les tâches planifiées..."
    Write-Host "Les tâches Microsoft seront affichées en vert, les tâches tierces en jaune."
    Write-Host

    # Check for admin privileges. no needed add to start
    #if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    #    Write-Host "Error: This function requires administrator privileges." -ForegroundColor Red
    #   Write-Host "Please run the script as Administrator and try again."
    #    Pause-Menu
    #    return
    #}

    # Helper function to display task list with dynamic alignment and modified author/taskname
    function Show-TaskList {
        # Retrieve scheduled tasks
        try {
            $tasks = schtasks /query /fo CSV /v | ConvertFrom-Csv | Where-Object {
                $_."TaskName" -ne "" -and                        # Exclude empty TaskName
                $_."TaskName" -ne "TaskName" -and               # Exclude placeholder "TaskName"
                $_."Author" -ne "Author" -and                   # Exclude placeholder "Author"
                $_."Status" -ne "Status" -and                   # Exclude placeholder "Status"
                $_."Author" -notlike "*Scheduling data is not available in this format.*" -and  # Exclude invalid scheduling data
                $_."TaskName" -notlike "*Enabled*" -and         # Exclude rows starting with "Enabled"
                $_."TaskName" -notlike "*Disabled*"             # Exclude rows starting with "Disabled"
            }
            if (-not $tasks) {
                Write-Host "Aucune tâche planifiée valide n'a été trouvée." -ForegroundColor Yellow
                return $null
            }
        } catch {
            Write-Host "Erreur lors de la récupération des tâches planifiées : $_" -ForegroundColor Red
            return $null
        }

        # Remove duplicates based on TaskName, Author, and Status
        $uniqueTasks = $tasks | Sort-Object "TaskName", "Author", "Status" -Unique

        # Calculate maximum lengths for dynamic alignment
        $maxIdLength = ($uniqueTasks.Count.ToString()).Length  # Length of largest ID
        $maxTaskNameLength = 50  # Default max length for TaskName, adjustable
        $maxAuthorLength = 30    # Default max length for Author, adjustable
        $maxStatusLength = 10    # Default max length for Status (e.g., "Running", "Ready", "Disabled")

        # Process tasks to adjust Author and TaskName, and calculate max lengths
        $processedTasks = @()
        foreach ($task in $uniqueTasks) {
            $taskName = if ($task."TaskName") { $task."TaskName" } else { "N/A" }
            $author = if ($task."Author") { $task."Author" } else { "N/A" }
            $status = if ($task."Status") { $task."Status" } else { "Unknown" }

            # Fix Author field for Microsoft tasks with resource strings (e.g., $(@%SystemRoot%\...))
            if ($author -like '$(@%SystemRoot%\*' -or $taskName -like '\Microsoft\*') {
                $author = "Microsoft Corporation"
            }

            # Extract first folder from TaskName for Author if still N/A
            if ($author -eq "N/A" -and $taskName -match '^\\([^\\]+)\\') {
                $author = $matches[1]  # Get first folder (e.g., "LGTV Companion")
            }

            # Remove first folder from TaskName
            $displayTaskName = $taskName -replace '^\\[^\\]+\\', ''  # Remove "\Folder\"
            if ($displayTaskName -eq $taskName) { $displayTaskName = $taskName.TrimStart('\') }  # Fallback for tasks without folder

            # Truncate long fields for alignment
            if ($displayTaskName.Length -gt $maxTaskNameLength) { $displayTaskName = $displayTaskName.Substring(0, $maxTaskNameLength - 3) + "..." }
            if ($author.Length -gt $maxAuthorLength) { $author = $author.Substring(0, $maxAuthorLength - 3) + "..." }

            # Update max lengths based on processed data
            $maxTaskNameLength = [Math]::Max($maxTaskNameLength, [Math]::Min($displayTaskName.Length, 50))
            $maxAuthorLength = [Math]::Max($maxAuthorLength, [Math]::Min($author.Length, 30))
            $maxStatusLength = [Math]::Max($maxStatusLength, $status.Length)

            $processedTasks += [PSCustomObject]@{
                OriginalTaskName = $task."TaskName"
                DisplayTaskName  = $displayTaskName
                Author           = $author
                Status           = $status
            }
        }

        # Print header with dynamic widths
        $headerFormat = "{0,-$maxIdLength} | {1,-$maxTaskNameLength} | {2,-$maxAuthorLength} | {3}"
        Write-Host ($headerFormat -f "ID", "Task Name", "Author", "Status")
        Write-Host ("-" * $maxIdLength + "-+-" + "-" * $maxTaskNameLength + "-+-" + "-" * $maxAuthorLength + "-+-" + "-" * $maxStatusLength)

        # Display tasks with index and color coding
        $taskList = @()
        $index = 1
        foreach ($task in $processedTasks) {
            $isMicrosoft = $task.OriginalTaskName -like "\Microsoft\*" -or $task.Author -like "*Microsoft*"
            $taskList += [PSCustomObject]@{
                Index      = $index
                TaskName   = $task.OriginalTaskName  # Store original for schtasks commands
                Author     = $task.Author
                Status     = $task.Status
                IsMicrosoft = $isMicrosoft
            }
            $color = if ($isMicrosoft) { "Green" } else { "Yellow" }
            Write-Host ($headerFormat -f $index, $task.DisplayTaskName, $task.Author, $task.Status) -ForegroundColor $color
            $index++
        }
        Write-Host
        return $taskList
    }

    # Display task list initially
    $taskList = Show-TaskList
    if (-not $taskList) {
        Pause-Menu
        return
    }

    # Main loop for task management options
    while ($true) {
        Write-Host "Options :"
        Write-Host "[1] Activer une tâche"
        Write-Host "[2] Désactiver une tâche"
        Write-Host "[3] Supprimer une tâche"
        Write-Host "[4] Actualiser la liste des tâches"
        Write-Host "[0] Retour au menu principal"
        Write-Host

        $action = Read-Host "Saisissez l'option (0-4) ou l'ID de tâche à gérer"
        if ($action -eq "0") {
            return
        } elseif ($action -eq "1") {
            $id = Read-Host "Entrez l'ID de tâche à activer"
            if ($id -match '^\d+$' -and $id -ge 1 -and $id -le $taskList.Count) {
                $selectedTask = $taskList[$id - 1]
                Write-Host "Activation de la tâche : $($selectedTask.TaskName)"
                try {
                    schtasks /change /tn "$($selectedTask.TaskName)" /enable | Out-Null
                    Write-Host "Tâche activé avec succès." -ForegroundColor Green
                } catch {
                    Write-Host "Erreur lors de l'activation de la tâche : $_" -ForegroundColor Red
                }
            } else {
                Write-Host "L'ID de la tâche est invalide." -ForegroundColor Red
            }
            Pause-Menu
            Clear-Host
            Write-Host "==============================================="
            Write-Host "     Scheduled Task Management [Admin]"
            Write-Host "==============================================="
            Write-Host "Refreshing task list..."
            Write-Host "Microsoft tasks are shown in Green, third-party tasks in Yellow."
            Write-Host
            $taskList = Show-TaskList
            if (-not $taskList) {
                Pause-Menu
                return
            }
        } elseif ($action -eq "2") {
            $id = Read-Host "Enter task ID to disable"
            if ($id -match '^\d+$' -and $id -ge 1 -and $id -le $taskList.Count) {
                $selectedTask = $taskList[$id - 1]
                Write-Host "Disabling task: $($selectedTask.TaskName)"
                try {
                    schtasks /change /tn "$($selectedTask.TaskName)" /disable | Out-Null
                    Write-Host "Task disabled successfully." -ForegroundColor Green
                } catch {
                    Write-Host "Error disabling task: $_" -ForegroundColor Red
                }
            } else {
                Write-Host "Invalid task ID." -ForegroundColor Red
            }
            Pause-Menu
            Clear-Host
            Write-Host "==============================================="
            Write-Host "     Scheduled Task Management [Admin]"
            Write-Host "==============================================="
            Write-Host "Refreshing task list..."
            Write-Host "Microsoft tasks are shown in Green, third-party tasks in Yellow."
            Write-Host
            $taskList = Show-TaskList
            if (-not $taskList) {
                Pause-Menu
                return
            }
        } elseif ($action -eq "3") {
            $id = Read-Host "Enter task ID to delete"
            if ($id -match '^\d+$' -and $id -ge 1 -and $id -le $taskList.Count) {
                $selectedTask = $taskList[$id - 1]
                Write-Host "WARNING: Deleting task: $($selectedTask.TaskName)" -ForegroundColor Yellow
                $confirm = Read-Host "Are you sure? (Y/N)"
                if ($confirm -eq "Y" -or $confirm -eq "y") {
                    try {
                        schtasks /delete /tn "$($selectedTask.TaskName)" /f | Out-Null
                        Write-Host "Task deleted successfully." -ForegroundColor Green
                    } catch {
                        Write-Host "Error deleting task: $_" -ForegroundColor Red
                    }
                } else {
                    Write-Host "Action cancelled." -ForegroundColor Yellow
                }
            } else {
                Write-Host "Invalid task ID." -ForegroundColor Red
            }
            Pause-Menu
            Clear-Host
            Write-Host "==============================================="
            Write-Host "     Scheduled Task Management [Admin]"
            Write-Host "==============================================="
            Write-Host "Refreshing task list..."
            Write-Host "Microsoft tasks are shown in Green, third-party tasks in Yellow."
            Write-Host
            $taskList = Show-TaskList
            if (-not $taskList) {
                Pause-Menu
                return
            }
        } elseif ($action -eq "4") {
            Clear-Host
            Write-Host "==============================================="
            Write-Host "     Scheduled Task Management [Admin]"
            Write-Host "==============================================="
            Write-Host "Refreshing task list..."
            Write-Host "Microsoft tasks are shown in Green, third-party tasks in Yellow."
            Write-Host
            $taskList = Show-TaskList
            if (-not $taskList) {
                Pause-Menu
                return
            }
        } else {
            Write-Host "Invalid option. Please enter 0-4 or a valid task ID." -ForegroundColor Red
            Pause-Menu
        }
    }
}

function Choice-30 {
    while ($true) {
        Clear-Host
        $discordUrl = "https://discord.gg/bCQqKHGxja"
        $githubUrl = "https://github.com/ios12checker/Windows-Maintenance-Tool/issues/new/choose"
        Write-Host
        Write-Host "=================================================="
        Write-Host "               CONTACT ET ASSISTANCE"
        Write-Host "=================================================="
        Write-Host "Contactez le propriétaire sur discord : Lil_Batti"
        Write-Host "Comment pouvons-nous vous aider ?"
        Write-Host
        Write-Host " [1] Serveur Discord d'assistance ouvert ($discordUrl)"
        Write-Host " [2] Créer un ticket sur GitHub ($githubUrl)"
        Write-Host
        Write-Host " [0] Revenir au menu principal"
        Write-Host "=================================================="

        $supportChoice = Read-Host "Entrez votre choix"

        switch ($supportChoice) {
            "1" {
                Write-Host "Ouverture de Discord dans votre navigateur..."
                try {
                    Start-Process $discordUrl -ErrorAction Stop
                    Write-Host "Le site de support Discord a été ouvert." -ForegroundColor Green
                } catch {
                    Write-Host "Impossible d'ouvrir le lien. Veuillez la consulter manuellement : $discordUrl" -ForegroundColor Red
                }
                Pause-Menu
                return
            }
            "2" {
                Write-Host "Ouverture la page de création de ticket sur GitHub dans votre navigateur..."
                try {
                    Start-Process $githubUrl -ErrorAction Stop
                    Write-Host "L'ouverture du lien est un succès." -ForegroundColor Green
                } catch {
                    Write-Host "Impossible d'ouvrir le lien. Veuillez la consulter manuellement : $githubUrl" -ForegroundColor Red
                }
                Pause-Menu
                return
            }
            "0" { return }
            default { Write-Host "Choix invalide. Veuillez entrer 1, 2, ou 0." -ForegroundColor Red; Start-Sleep -Seconds 2 }
        }
    }
}

function Choice-0 { Clear-Host; Write-Host "Quitter le script..."; exit }

function Choice-20 {
    Clear-Host
    Write-Host "==============================================="
    Write-Host "    Enregistrement du rapport des pilotes installés sur le bureau"
    Write-Host "==============================================="
    $outfile = "$env:USERPROFILE\Desktop\Installed_Drivers.txt"
    driverquery /v > $outfile
    Write-Host
    Write-Host "Le rapport des pilotes installés a été enregistré dans : $outfile"
    Clear-Host
    Write-Host "`nAppuyez sur une touche pour continuer..." -ForegroundColor DarkGray
    [void][System.Console]::ReadKey($true)
    $confirm = Read-Host "Voulez-vous sauvegarder les pilotes ? (O/N)"
    $c = $confirm.ToUpper().Trim()

    if ($c -eq "O" -or $c -eq "OUI" -or $c -eq "OUIE" -or $c -eq "VI") {
        $BackupDrivers = "$env:SystemDrive\DriversBackup"
        New-Item -ItemType Directory -Path $BackupDrivers -Force | Out-Null

        Write-Host "🔄 Sauvegarde des pilotes en cours..." -ForegroundColor Cyan

        try {
            $Export = Export-WindowsDriver -Online -Destination "$BackupDrivers" -ErrorAction Stop
            Write-Host "✅ Les pilotes ont été sauvegardés dans le dossier : $BackupDrivers" -ForegroundColor Green
        } catch {
            Write-Host "❌ Erreur lors de la sauvegarde des pilotes : $_" -ForegroundColor Red
        }

        Pause-Menu
        return
    }

    if ($c -eq "N" -or $c -eq "NON" -or $c -eq "NO") {
        Write-Host "⛔ Opération annulée." -ForegroundColor Yellow
        Pause-Menu
        return
    }

    Write-Host "❗ Entrée invalide. Veuillez saisir O ou N." -ForegroundColor Red
    Pause-Menu
}

function Choice-21 {
    Clear-Host
    Write-Host "==============================================="
    Write-Host "   Outil de réparation de mise à jour Windows [Admin]"
    Write-Host "==============================================="
    Write-Host
    Write-Host "[1/4] Arrêt des services liés aux mises à jour..."
    $services = @('wuauserv','bits','cryptsvc','msiserver','usosvc','trustedinstaller')
    foreach ($service in $services) {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne "Stopped") {
            Write-Host "Arrêt de $service"
            try { Stop-Service -Name $service -Force -ErrorAction Stop } catch {}
        }
    }
    Start-Sleep -Seconds 2
    Write-Host
    Write-Host "[2/4] Renommer les dossiers de cache de mise à jour..."
    $SUFFIX = ".bak_{0}" -f (Get-Random -Maximum 99999)
    $SD = "$env:windir\SoftwareDistribution"
    $CR = "$env:windir\System32\catroot2"
    $renamedSD = "$env:windir\SoftwareDistribution$SUFFIX"
    $renamedCR = "$env:windir\System32\catroot2$SUFFIX"
    if (Test-Path $SD) {
        try {
            Rename-Item $SD -NewName ("SoftwareDistribution" + $SUFFIX) -ErrorAction Stop
            if (Test-Path $renamedSD) {
                Write-Host "Renommé : $renamedSD"
            } else {
                Write-Host "ATTENTION : SoftwareDistribution n'a pas pu être renommé (en cours d'utilisation ?)."
            }
        } catch { Write-Host "ATTENTION : SoftwareDistribution n'a pas pu être renommé (en cours d'utilisation ?)." }
    } else { Write-Host "Info : SoftwareDistribution n'a pas été trouvé." }
    if (Test-Path $CR) {
        try {
            Rename-Item $CR -NewName ("catroot2" + $SUFFIX) -ErrorAction Stop
            if (Test-Path $renamedCR) {
                Write-Host "Renommé : $renamedCR"
            } else {
                Write-Host "ATTENTION : catroot2 n'a pas pu être renommé."
            }
        } catch { Write-Host "ATTENTION : catroot2 n'a pas pu être renommé." }
    } else { Write-Host "Info : catroot2 n'a pas été trouvé." }
    Write-Host
    Write-Host "[3/4] Redémarrage des services..."
    foreach ($service in $services) {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -ne "Running") {
            Write-Host "Démarrage du service $service"
            try { Start-Service -Name $service -ErrorAction Stop } catch {}
        }
    }
    Write-Host
    Write-Host "[4/4] Les composants de Windows Update ont été réinitialisés."
    Write-Host
    Write-Host "Dossiers renommés :"
    Write-Host "  - $renamedSD"
    Write-Host "  - $renamedCR"
    Write-Host "Vous pouvez les supprimer manuellement après le redémarrage si tout fonctionne."
    Write-Host
    Pause-Menu
}

function Choice-22 {
    Clear-Host
    Write-Host "==============================================="
    Write-Host "    Génération de rapports système séparés..."
    Write-Host "==============================================="
    Write-Host
    Write-Host "Choisissez l'emplacement de sortie :"
    Write-Host " [1] Bureau (recommandé)"
    Write-Host " [2] Entrez un chemin personnalisé"
    Write-Host " [3] Afficher le guide pour la configuration du chemin personnalisé"
    $opt = Read-Host ">"
    $outpath = ""
    if ($opt -eq "1") {
        $desktop = [Environment]::GetFolderPath('Desktop')
        $reportdir = "SystemReports_{0}" -f (Get-Date -Format "yyyy-MM-dd_HHmm")
        $outpath = Join-Path $desktop $reportdir
        if (-not (Test-Path $outpath)) { New-Item -Path $outpath -ItemType Directory | Out-Null }
    } elseif ($opt -eq "2") {
        $outpath = Read-Host "Entrez le chemin complet (Exemple : D:\Reports)"
        if (-not (Test-Path $outpath)) {
            Write-Host
            Write-Host "[ERREUR] Le dossier $outpath n'a pas été trouvé"
            Pause-Menu
            return
        }
    } elseif ($opt -eq "3") {
        Clear-Host
        Write-Host "==============================================="
        Write-Host "    Comment utiliser un chemin de rapport personnalisé"
        Write-Host "==============================================="
        Write-Host
        Write-Host "1. Ouvrez l’explorateur de fichiers et créez un nouveau dossier, Exemple :"
        Write-Host "   C:\Users\Votre_Nom\Desktop\SystemReports"
        Write-Host "   ou"
        Write-Host "   C:\Users\Votre_Nom\OneDrive\Documents\SystemReports"
        Write-Host
        Write-Host "2. Copiez le chemin complet du dossier depuis la barre d'adresse."
        Write-Host "3. Réexécutez ceci et choisissez l'option [2], puis collez-la."
        Write-Host
        Pause-Menu
        return
    } else {
        Write-Host
        Write-Host "Sélection invalide."
        Start-Sleep -Seconds 2
        return
    }
    $datestr = Get-Date -Format "yyyy-MM-dd"
    $sys   = Join-Path $outpath "System_Info_$datestr.txt"
    $net   = Join-Path $outpath "Network_Info_$datestr.txt"
    $drv   = Join-Path $outpath "Driver_List_$datestr.txt"
    Write-Host
    Write-Host "Écriture des informations système dans : $sys"
    systeminfo | Out-File -FilePath $sys -Encoding UTF8
    Write-Host "Écrire des informations sur le réseau dans : $net"
    ipconfig /all | Out-File -FilePath $net -Encoding UTF8
    Write-Host "Écriture de la liste des pilotes dans : $drv"
    driverquery | Out-File -FilePath $drv -Encoding UTF8
    Write-Host
    Write-Host "Rapports enregistrés dans :"
    Write-Host $outpath
    Write-Host
    Pause-Menu
}

function Choice-23 {
    while ($true) {
        Clear-Host
        Write-Host "======================================================"
        Write-Host "           Utilitaire de mise à jour et réinitialisation du service Windows"
        Write-Host "======================================================"
        Write-Host "Cet outil redémarrera les principaux services Windows Update."
        Write-Host "Assurez-vous qu'aucune mise à jour Windows n'est en cours d'installation."
        Pause-Menu
        Write-Host
        Write-Host "[1] Réinitialiser les services de mise à jour (wuauserv, cryptsvc, appidsvc, bits)"
        Write-Host "[2] Retourner au menu principal"
        Write-Host
        $fixchoice = Read-Host "Sélectionnez une option"
        switch ($fixchoice) {
            "1" {
                Clear-Host
                Write-Host "======================================================"
                Write-Host "    Réinitialisation de Windows Update et des services associés"
                Write-Host "======================================================"
                Write-Host "Arrêt du service de mises à jours..."
                try { Stop-Service -Name wuauserv -Force -ErrorAction Stop } catch {}
                Write-Host "Arrêt du service de Services de chiffrement..."
                try { Stop-Service -Name cryptsvc -Force -ErrorAction Stop } catch {}
                Write-Host "Démarrage du service Identité de l’application..."
                try { Start-Service -Name appidsvc -ErrorAction Stop } catch {}
                Write-Host "Démarrage du service de mises à jours..."
                try { Start-Service -Name wuauserv -ErrorAction Stop } catch {}
                Write-Host "Démarrage du service Service de transfert intelligent en arrière-plan..."
                try { Start-Service -Name bits -ErrorAction Stop } catch {}
                Write-Host
                Write-Host "[OK] Les services ont été redémarrés."
                Pause-Menu
                return
            }
            "2" { return }
            default { Write-Host "Invalid input. Try again."; Pause-Menu }
        }
    }
}

function Choice-24 {
    while ($true) {
        Clear-Host
        Write-Host "==============================================="
        Write-Host "     Afficher la table de routage réseau [Avancé]"
        Write-Host "==============================================="
        Write-Host "Cela montre comment votre système gère le trafic réseau."
        Write-Host
        Write-Host "[1] Afficher la table de routage dans cette fenêtre"
        Write-Host "[2] Sauvegarde la table de routage dans un fichier sur le Bureau"
        Write-Host "[3] Retourner au menu principal"
        Write-Host
        $routeopt = Read-Host "Choisissez une option"
        switch ($routeopt) {
            "1" {
                Clear-Host
                route print
                Write-Host
                Pause-Menu
                return
            }
            "2" {
                $desktop = "$env:USERPROFILE\Desktop"
                if (-not (Test-Path $desktop)) {
                    Write-Host "Le dossier Desktop n'a pas été trouvé."
                    Pause-Menu
                    return
                }
                $dt = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
                if (-not $dt) { $dt = "manual_timestamp" }
                $file = Join-Path $desktop "routing_table_${dt}.txt"
                Clear-Host
                Write-Host "Sauvegarde de la table de routage dans : `"$file`""
                Write-Host
                route print | Out-File -FilePath $file -Encoding UTF8
                if (Test-Path $file) {
                    Write-Host "[OK] Table de routage enregistrée avec succès." -ForegroundColor Green
                } else {
                    Write-Host "[ERREUR] Échec de l'enregistrement de la table de routage dans le fichier." -ForegroundColor Red 
                }
                Write-Host
                Pause-Menu
                return
            }
            "3" { return }
            default {
                Write-Host "Entrée invalide. Veuillez saisir 1, 2 ou 3.." -ForegroundColor Red
                Pause-Menu
            }
        }
    }
}


function Choice-25 {
    Clear-Host
    Write-Host "==============================================="
    Write-Host " Réinitialisation des associations de fichiers"
    Write-Host "==============================================="

    Write-Host
    Write-Host "[1] Réintialiser les extensions (.exe, .lnk, .bat, .cmd, .reg, .msi, .vbs) avec Powershell"
    Write-Host "[2] Sauvegarde la table de routage dans un fichier sur le Bureau"
    Write-Host "[3] Retourner au menu principal"
    Write-Host
    $resetassoc = Read-Host "Choisissez une option"
    switch ($resetassoc) {
            "1" {
                    $extensions = @{
                        ".exe" = "exefile"
                        ".lnk" = "lnkfile"
                        ".bat" = "batfile"
                        ".cmd" = "cmdfile"
                        ".reg" = "regfile"
                        ".msi" = "Msi.Package"
                        ".vbs" = "VBSFile"
                    }

                    foreach ($ext in $extensions.Keys) {
                        $class = $extensions[$ext]
                        try {
                            Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$ext\UserChoice" -Force -ErrorAction SilentlyContinue
                            cmd /c "assoc $ext=$class"
                            Write-Host "✅ $ext réinitialisé vers $class" -ForegroundColor Green
                        } catch {
                            Write-Host "❌ Erreur pour $ext : $_" -ForegroundColor Red
                        }
                    }

                    Pause-Menu
            }
            "2" {
                $FolderDownloads = "$env:USERPROFILE\Downloads"
                
                if (-not (Test-Path $FolderDownloads)) {
                    Write-Host "Le dossier Desktop n'a pas été trouvé."
                    Pause-Menu
                    return
                }

                curl -L -o "$FolderDownloads\FAF2.zip" "https://www.thewindowsclub.com/downloads/FAF2.zip"
                if (-Not (Test-Path "$FolderDownloads\FAF2")) {
                    Expand-Archive -LiteralPath "$FolderDownloads\FAF2.zip" -DestinationPath "$FolderDownloads\FAF2" -Force
                }
                Remove-Item -LiteralPath "$FolderDownloads\FAF2.zip" -Force -ErrorAction SilentlyContinue
                $exePath = if ([Environment]::Is64BitOperatingSystem) {
                    "FAF x64.exe"
                } else {
                    "FAF x86.exe"
                }

                if (Test-Path $exePath) {
                    Start-Process -FilePath $exePath -Wait
                    Remove-Item "$FolderDownloads\FAF2" -Recurse -Force -ErrorAction SilentlyContinue
                } else {
                    Write-Host "❌ Fichier introuvable : $exePath" -ForegroundColor Red
                    Pause-Menu
                    return
                }
                Pause-Menu
                return
            }
            "3" { return }
            default {
                Write-Host "Entrée invalide. Veuillez saisir 1, 2 ou 3.." -ForegroundColor Red
                Pause-Menu
            }
        }
}

function Choice-25 {
    Clear-Host
    Write-Host "==============================================="
    Write-Host " Moniteur de fiabilité  "
    Write-Host "==============================================="

    Write-Host "Démarrage du moniteur de fiabilité..."
    Start-Process "perfmon.exe" -ArgumentList "/rel" -Wait
    Write-Host
    Write-Host "Retour au menu principal..."
    Write-Host
    Pause-Menu
}    
# === MAIN MENU LOOP ===
while ($true) {
    Show-Menu
    $choice = Read-Host "Entrez votre choix"
    switch ($choice) {
        "1"  { Choice-1; continue }
        "2"  { Choice-2; continue }
        "3"  { Choice-3; continue }
        "4"  { Choice-4; continue }
        "5"  { Choice-5; continue }
        "6"  { Choice-6; continue }
        "7"  { Choice-7; continue }
        "8"  { Choice-8; continue }
        "9"  { Choice-9; continue }
        "10" { Choice-10; continue }
        "11" { Choice-11; continue }
        "12" { Choice-12; continue }
        "13" { Choice-13; continue }
        "14" { Choice-14; continue }
        "15" { Choice-15; continue }
        "20" { Choice-20; continue }
        "21" { Choice-21; continue }
        "22" { Choice-22; continue }
        "23" { Choice-23; continue }
        "24" { Choice-24; continue }
        default { Write-Host "Choix invalide, veuillez réessayer."; Pause-Menu }
    }
}
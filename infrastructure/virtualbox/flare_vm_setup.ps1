# FLARE VM Setup Script for MASARE
# Purpose: Automated deployment of Windows malware analysis VM
# Author: Security Research Team
# Last Updated: 2025-11-15
# Requires: PowerShell 5.1+, VirtualBox installed

#Requires -RunAsAdministrator

# Configuration
$VMName = "FLARE_MASARE"
$VMMemory = 4096  # 4GB RAM
$VMCPUs = 2
$VMVRam = 128
$VMDiskSize = 81920  # 80GB in MB
$NetworkName = "vboxnet0"
$VMIP = "192.168.1.20"
$GatewayIP = "192.168.1.1"

# Windows 10 ISO path (download from Microsoft)
$Win10ISO = "$env:USERPROFILE\Downloads\Win10_Enterprise_x64.iso"

Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║          MASARE - FLARE VM Setup Script                 ║" -ForegroundColor Green
Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""

# Check VirtualBox installation
function Test-VirtualBox {
    Write-Host "[*] Checking VirtualBox installation..." -ForegroundColor Yellow

    $VBoxPath = "C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
    if (-not (Test-Path $VBoxPath)) {
        Write-Host "[✗] VirtualBox not found!" -ForegroundColor Red
        Write-Host "[i] Install from: https://www.virtualbox.org/wiki/Downloads" -ForegroundColor Yellow
        exit 1
    }

    $Version = & $VBoxPath --version
    Write-Host "[✓] VirtualBox $Version installed" -ForegroundColor Green
    return $VBoxPath
}

# Create FLARE VM
function New-FLAREVM {
    param($VBoxManage)

    Write-Host "[*] Creating FLARE VM..." -ForegroundColor Yellow

    # Check if VM exists
    $ExistingVMs = & $VBoxManage list vms
    if ($ExistingVMs -match $VMName) {
        $Response = Read-Host "[!] VM $VMName already exists. Delete it? (y/n)"
        if ($Response -eq 'y') {
            Write-Host "[*] Removing existing VM..." -ForegroundColor Yellow
            & $VBoxManage unregistervm $VMName --delete
        } else {
            Write-Host "[✗] Aborting setup" -ForegroundColor Red
            exit 1
        }
    }

    # Create VM
    & $VBoxManage createvm --name $VMName --ostype Windows10_64 --register

    # Configure memory and CPU
    & $VBoxManage modifyvm $VMName `
        --memory $VMMemory `
        --cpus $VMCPUs `
        --vram $VMVRam `
        --accelerate3d off `
        --accelerate2dvideo off

    # Network configuration (Host-Only)
    & $VBoxManage modifyvm $VMName `
        --nic1 hostonly `
        --hostonlyadapter1 $NetworkName `
        --nictype1 82540EM `
        --macaddress1 080027000020

    # Disable unnecessary features
    & $VBoxManage modifyvm $VMName `
        --clipboard disabled `
        --draganddrop disabled `
        --usb off `
        --audio none

    # Create virtual hard disk
    $VMPath = & $VBoxManage showvminfo $VMName --machinereadable | Select-String "CfgFile" | ForEach-Object { $_.ToString().Split('=')[1].Trim('"') }
    $VMDir = Split-Path -Parent $VMPath
    $VDIPath = Join-Path $VMDir "$VMName.vdi"

    & $VBoxManage createhd --filename $VDIPath --size $VMDiskSize --variant Standard

    # Attach storage controller
    & $VBoxManage storagectl $VMName --name "SATA" --add sata --controller IntelAhci --portcount 2 --bootable on
    & $VBoxManage storageattach $VMName --storagectl "SATA" --port 0 --device 0 --type hdd --medium $VDIPath

    # Attach Windows ISO
    if (Test-Path $Win10ISO) {
        & $VBoxManage storageattach $VMName --storagectl "SATA" --port 1 --device 0 --type dvddrive --medium $Win10ISO
        Write-Host "[✓] Windows 10 ISO attached" -ForegroundColor Green
    } else {
        Write-Host "[!] Windows 10 ISO not found: $Win10ISO" -ForegroundColor Red
        Write-Host "[i] Download from: https://www.microsoft.com/software-download/windows10" -ForegroundColor Yellow
        Write-Host "[i] Manual installation required" -ForegroundColor Yellow
    }

    Write-Host "[✓] VM created successfully" -ForegroundColor Green
}

# Create shared folders
function New-SharedFolders {
    param($VBoxManage)

    Write-Host "[*] Creating shared folders..." -ForegroundColor Yellow

    # Create host directories
    $SharedPath = "$env:USERPROFILE\MASARE\shared"
    New-Item -Path "$SharedPath\malware\samples" -ItemType Directory -Force | Out-Null
    New-Item -Path "$SharedPath\analysis\results" -ItemType Directory -Force | Out-Null
    New-Item -Path "$SharedPath\logs" -ItemType Directory -Force | Out-Null

    # Add shared folders
    & $VBoxManage sharedfolder add $VMName `
        --name "malware_samples" `
        --hostpath "$SharedPath\malware\samples" `
        --readonly `
        --automount

    & $VBoxManage sharedfolder add $VMName `
        --name "analysis_results" `
        --hostpath "$SharedPath\analysis\results" `
        --automount

    Write-Host "[✓] Shared folders created" -ForegroundColor Green
}

# Create baseline snapshot
function New-BaselineSnapshot {
    param($VBoxManage)

    Write-Host "[*] Creating baseline snapshot..." -ForegroundColor Yellow

    & $VBoxManage snapshot $VMName take "baseline_clean" `
        --description "Clean Windows 10 installation ($(Get-Date -Format 'yyyy-MM-dd'))"

    Write-Host "[✓] Baseline snapshot created" -ForegroundColor Green
}

# Generate post-installation script
function New-PostInstallScript {
    $PostInstallScript = @"
# FLARE VM Post-Installation Configuration
# Run this script AFTER Windows 10 installation is complete

Write-Host "╔════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║     FLARE VM Post-Installation Configuration      ║" -ForegroundColor Cyan
Write-Host "╚════════════════════════════════════════════════════╝" -ForegroundColor Cyan

# 1. Disable Windows Defender
Write-Host "[*] Disabling Windows Defender..." -ForegroundColor Yellow
Set-MpPreference -DisableRealtimeMonitoring `$true
Set-MpPreference -DisableBehaviorMonitoring `$true
Set-MpPreference -DisableBlockAtFirstSeen `$true
Set-MpPreference -DisableIOAVProtection `$true
Set-MpPreference -DisableScriptScanning `$true

# 2. Disable Windows Update
Write-Host "[*] Disabling Windows Update..." -ForegroundColor Yellow
Stop-Service wuauserv
Set-Service wuauserv -StartupType Disabled

# 3. Disable UAC
Write-Host "[*] Disabling UAC..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Value 0

# 4. Show hidden files and extensions
Write-Host "[*] Configuring Explorer..." -ForegroundColor Yellow
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "Hidden" -Value 1
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0

# 5. Configure static IP
Write-Host "[*] Configuring static IP..." -ForegroundColor Yellow
`$Adapter = Get-NetAdapter | Where-Object { `$_.Status -eq "Up" }
New-NetIPAddress -InterfaceIndex `$Adapter.ifIndex -IPAddress "$VMIP" -PrefixLength 24 -DefaultGateway "$GatewayIP"
Set-DnsClientServerAddress -InterfaceIndex `$Adapter.ifIndex -ServerAddresses "$GatewayIP"

# 6. Install Chocolatey
Write-Host "[*] Installing Chocolatey..." -ForegroundColor Yellow
Set-ExecutionPolicy Bypass -Scope Process -Force
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072
iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# 7. Install FLARE VM tools (from Mandiant)
Write-Host "[*] Installing FLARE VM tools..." -ForegroundColor Yellow
Write-Host "[i] Download FLARE VM installer from: https://github.com/mandiant/flare-vm" -ForegroundColor Cyan
Write-Host "[i] Run: Install-BoxStartup.ps1 -password <password>" -ForegroundColor Cyan

# 8. Install Python
choco install python -y
choco install git -y

# 9. Install Cuckoo Agent
Write-Host "[*] Setting up Cuckoo Agent..." -ForegroundColor Yellow
New-Item -Path "C:\cuckoo_agent" -ItemType Directory -Force
# Download agent.py from Cuckoo server (192.168.1.10)

Write-Host "`n[✓] Post-installation complete!" -ForegroundColor Green
Write-Host "[i] Reboot required for all changes to take effect" -ForegroundColor Yellow
Write-Host "[i] After reboot, install FLARE VM tools manually" -ForegroundColor Yellow
"@

    $PostInstallPath = "$env:USERPROFILE\MASARE\infrastructure\virtualbox\flare_post_install.ps1"
    $PostInstallScript | Out-File -FilePath $PostInstallPath -Encoding UTF8

    Write-Host "[✓] Post-installation script saved: $PostInstallPath" -ForegroundColor Green
}

# Post-installation instructions
function Show-PostInstallInstructions {
    Write-Host ""
    Write-Host "╔══════════════════════════════════════════════════════════╗" -ForegroundColor Green
    Write-Host "║              FLARE VM Setup Complete!                    ║" -ForegroundColor Green
    Write-Host "╚══════════════════════════════════════════════════════════╝" -ForegroundColor Green
    Write-Host ""
    Write-Host "Next Steps:" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "1. Start the VM and install Windows 10:" -ForegroundColor White
    Write-Host "   VBoxManage startvm $VMName" -ForegroundColor Green
    Write-Host ""
    Write-Host "2. After Windows installation, run post-install script (inside VM):" -ForegroundColor White
    Write-Host "   Copy flare_post_install.ps1 to VM and execute as Administrator" -ForegroundColor Green
    Write-Host ""
    Write-Host "3. Install FLARE VM tools (inside VM):" -ForegroundColor White
    Write-Host "   https://github.com/mandiant/flare-vm" -ForegroundColor Green
    Write-Host ""
    Write-Host "4. Install Cuckoo Agent (inside VM):" -ForegroundColor White
    Write-Host "   Download agent.py from Cuckoo server (192.168.1.10)" -ForegroundColor Green
    Write-Host "   Configure auto-start: Task Scheduler or Startup folder" -ForegroundColor Green
    Write-Host ""
    Write-Host "5. Verify network isolation:" -ForegroundColor White
    Write-Host "   ping 8.8.8.8  (should FAIL - no internet)" -ForegroundColor Green
    Write-Host "   ping 192.168.1.10  (should SUCCEED - REMnux VM)" -ForegroundColor Green
    Write-Host ""
    Write-Host "Security Checklist:" -ForegroundColor Yellow
    Write-Host "  ☐ Windows Defender disabled" -ForegroundColor White
    Write-Host "  ☐ Windows Update disabled" -ForegroundColor White
    Write-Host "  ☐ UAC disabled" -ForegroundColor White
    Write-Host "  ☐ Static IP configured ($VMIP)" -ForegroundColor White
    Write-Host "  ☐ No internet access verified" -ForegroundColor White
    Write-Host "  ☐ Cuckoo Agent installed and running" -ForegroundColor White
    Write-Host ""
}

# Main execution
$VBoxManage = Test-VirtualBox
New-FLAREVM -VBoxManage $VBoxManage
New-SharedFolders -VBoxManage $VBoxManage
New-BaselineSnapshot -VBoxManage $VBoxManage
New-PostInstallScript
Show-PostInstallInstructions

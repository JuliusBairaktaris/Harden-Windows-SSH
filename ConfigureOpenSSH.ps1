function Test-IsAdmin {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-ElevateScript {
    Start-Process PowerShell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

function Get-SSHVersion {
    $versionString = & ssh -V 2>&1
    if ($versionString -match '_(\d+)\.(\d+)') {
        return [version]"$($matches[1]).$($matches[2])"
    }
    # Fallback for unexpected version string format
    return [version]"0.0"
}

function Set-SSHClientConfig {
    param (
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$ConfigContent
    )

    if ($Path -eq $script:ConfigPath -and (Test-Path -Path $script:ConfigPathUser)) {
        $deleteUserConfig = Read-Host "A user-specific configuration file exists which overrides the system-wide configuration. Do you wish to remove it? (Y/N)"
        if ($deleteUserConfig -eq "Y" -or $deleteUserConfig -eq "y") {
            Remove-Item -Path $script:ConfigPathUser -Force
            Write-Host "User-specific configuration file has been removed."
        }
    }

    Set-Content -Path $Path -Value $ConfigContent
    Write-Host "SSH configuration has been added to $Path"
}

function Set-SSHServerConfig {
    param (
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [string]$ConfigContent
    )

    Stop-Service -Name sshd

    Add-Content -Path $Path -Value "`n$ConfigContent"
    Write-Host "OpenSSH server configuration has been appended to $Path"

    Restart-Service -Name sshd -Force

    Read-Host "Press any key to exit..."
    exit
}

# Define the paths to the .ssh directory & the configuration files
$script:ConfigPath = Join-Path -Path $env:PROGRAMDATA -ChildPath "ssh\ssh_config"
$script:ConfigPathUser = Join-Path -Path $env:USERPROFILE -ChildPath ".ssh\config"
$script:ConfigPathServer = Join-Path -Path $env:PROGRAMDATA -ChildPath "ssh\sshd_config"
$script:sshVersion = Get-SSHVersion

# Get the directory of the script
$scriptRoot = $PSScriptRoot
if (-not $scriptRoot) {
    $scriptRoot = Split-Path -Path $MyInvocation.MyCommand.Path -Parent
}

# Read config files
try {
    $sshClientConfigContent = Get-Content -Path (Join-Path -Path $scriptRoot -ChildPath "ssh_config") -Raw
    $sshServerConfigContent = Get-Content -Path (Join-Path -Path $scriptRoot -ChildPath "sshd_config") -Raw
}
catch {
    Write-Error "Could not read ssh_config and/or sshd_config. Make sure they are in the same directory as the script: $scriptRoot"
    Read-Host "Press any key to exit..."
    exit 1
}

# Dynamically add settings based on SSH version
if ($script:sshVersion -ge [version]'9.0') {
    $sshClientConfigContent = $sshClientConfigContent -replace '(?<=KexAlgorithms\s)([^\r\n]*)', 'sntrup761x25519-sha512@openssh.com,$1'
    $sshServerConfigContent = $sshServerConfigContent -replace '(?<=KexAlgorithms\s)([^\r\n]*)', 'sntrup761x25519-sha512@openssh.com,$1'
}
if ($script:sshVersion -ge [version]'9.9') {
    $sshClientConfigContent = $sshClientConfigContent -replace '(?<=KexAlgorithms\s)([^\r\n]*)', 'mlkem768x25519-sha256,$1'
    $sshServerConfigContent = $sshServerConfigContent -replace '(?<=KexAlgorithms\s)([^\r\n]*)', 'mlkem768x25519-sha256,$1'
}
if ($script:sshVersion -ge [version]'10.1') {
    $sshClientConfigContent += "`nWarnWeakCrypto no"
}

if ($script:sshVersion.Major -eq 8) {
    $updateOpenSSH = Read-Host "Do you wish to install the latest version of OpenSSH? (Y/N)"
    if ($updateOpenSSH -eq "Y" -or $updateOpenSSH -eq "y") {
        Start-Process winget -ArgumentList "install -e --id Microsoft.OpenSSH.Beta" -Wait -NoNewWindow
        $script:sshVersion = Get-SSHVersion
    }
}

if (-not (Test-IsAdmin)) {
    Write-Host "This script requires administrator privileges to harden the OpenSSH client configuration system-wide & the OpenSSH server configuration!"
    $elevateScript = Read-Host "Do you wish to run this script with elevated privileges? (Y/N)"
    if ($elevateScript -eq "Y" -or $elevateScript -eq "y") {
        Invoke-ElevateScript
    }
    else {
        $hardenClientUser = Read-Host "Do you wish to harden the OpenSSH client configuration for the current user profile? (Y/N)"
        if ($hardenClientUser -eq "Y" -or $hardenClientUser -eq "y") {
            Set-SSHClientConfig -Path $script:ConfigPathUser -ConfigContent $sshClientConfigContent
        }
    }
}
else {
    $hardenClient = Read-Host "Do you wish to harden the OpenSSH client configuration? (Y/N)"
    if ($hardenClient -eq "Y" -or $hardenClient -eq "y") {
        $currentUserOnly = Read-Host "Choose an option:
1 - Apply the hardening script to the current user only. (This will only affect your user profile.)
2 - Apply the hardening script system-wide. (Requires administrator privileges; affects all users on this system.)
Enter 1 or 2"

        switch ($currentUserOnly) {
            "1" {
                Set-SSHClientConfig -Path $script:ConfigPathUser -ConfigContent $sshClientConfigContent
            }
            "2" {
                Set-SSHClientConfig -Path $script:ConfigPath -ConfigContent $sshClientConfigContent
            }
            default {
                Read-Host "Invalid input. Press any key to exit..."
                exit
            }
        }
    }

    $hardenServer = Read-Host "Do you wish to harden the OpenSSH server configuration? (Y/N)"
    if ($hardenServer -eq "Y" -or $hardenServer -eq "y") {
        Set-SSHServerConfig -Path $script:ConfigPathServer -ConfigContent $sshServerConfigContent
    }
}

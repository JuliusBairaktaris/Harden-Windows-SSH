function Test-IsAdmin {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-ElevateScript {
    Start-Process PowerShell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

function Set-SSHClientConfig {
    param (
        [Parameter(Mandatory)]
        [string]$Path
    )

    if ($Path -eq $script:ConfigPath -and (Test-Path -Path $script:ConfigPathUser)) {
        $deleteUserConfig = Read-Host "A user-specific configuration file exists which overrides the system-wide configuration. Do you wish to remove it? (Y/N)"
        if ($deleteUserConfig -eq "Y" -or $deleteUserConfig -eq "y") {
            Remove-Item -Path $script:ConfigPathUser -Force
            Write-Host "User-specific configuration file has been removed."
        }
    }

    $applyOverrides = Read-Host "Do you wish to apply additional overrides to the configuration? (Y/N)"
    if ($applyOverrides -eq "Y" -or $applyOverrides -eq "y") {
        $script:sshConfig = $script:sshConfig -replace '(?<=MACs\s)([^\r\n]*)', '$1,hmac-sha2-256'
    }

    Set-Content -Path $Path -Value $script:sshConfig
    if ($script:sshVersion -match "_9\.") {
        Add-Content -Path $Path -Value $script:sshConfigV9
    }
    Write-Host "SSH configuration has been added to $Path"
}

function Set-SSHServerConfig {
    param (
        [Parameter(Mandatory)]
        [string]$Path
    )

    Stop-Service -Name sshd

    if (Test-Path -Path $script:ConfigPathServer) {
        $removeSSHD = Read-Host "A configuration file for the OpenSSH server already exists. Do you wish to remove it? (Y/N)"
        if ($removeSSHD -eq "Y" -or $removeSSHD -eq "y") {
            Remove-Item -Path $script:ConfigPathServer -Force
            Write-Host "OpenSSH server configuration file has been removed."
        }
    }

    Restart-Service -Name sshd -Force

    $lineToFind = "#HostKey __PROGRAMDATA__/ssh/ssh_host_ed25519_key"
    $fileContent = Get-Content -Path $Path
    $lineIndex = $fileContent.IndexOf($lineToFind)

    if ($lineIndex -ge 0) {
        $newContent = $fileContent[$lineIndex] + "`r`n" + $script:sshConfigServer
        $fileContent[$lineIndex] = $newContent
        Set-Content -Path $Path -Value $fileContent
        Write-Host "OpenSSH server configuration has been added to $Path"
    }
    else {
        Write-Warning "The specified line '$lineToFind' was not found in the file."
    }

    Read-Host "Press any key to exit..."
    exit
}

# Define the paths to the .ssh directory & the configuration files
$script:ConfigPath = Join-Path -Path $env:PROGRAMDATA -ChildPath "ssh\ssh_config"
$script:ConfigPathUser = Join-Path -Path $env:USERPROFILE -ChildPath ".ssh\config"
$script:ConfigPathServer = Join-Path -Path $env:PROGRAMDATA -ChildPath "ssh\sshd_config"
$script:sshVersion = & ssh -V 2>&1

# SSH configuration
$script:sshConfig = @"
Host *
 KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256

 Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

 MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com

 HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256

 CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256

 PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256
"@

$script:sshConfigV9 = @"
 HostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256
"@

$script:sshConfigServer = @"
HostKey __PROGRAMDATA__/ssh/ssh_host_rsa_key
HostKey __PROGRAMDATA__/ssh/ssh_host_ed25519_key

KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256

Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com

HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256

CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256

HostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256

PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256
"@

if ($script:sshVersion -match "_8\.") {
    $updateOpenSSH = Read-Host "Do you wish to install the latest version of OpenSSH? (Y/N)"
    if ($updateOpenSSH -eq "Y" -or $updateOpenSSH -eq "y") {
        Start-Process winget -ArgumentList "install -e --id Microsoft.OpenSSH.Beta" -Wait -NoNewWindow
        $script:sshVersion = & ssh -V 2>&1
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
            Set-SSHClientConfig -Path $script:ConfigPathUser
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
                Set-SSHClientConfig -Path $script:ConfigPathUser
            }
            "2" {
                Set-SSHClientConfig -Path $script:ConfigPath
            }
            default {
                Read-Host "Invalid input. Press any key to exit..."
                exit
            }
        }
    }

    $hardenServer = Read-Host "Do you wish to harden the OpenSSH server configuration? (Y/N)"
    if ($hardenServer -eq "Y" -or $hardenServer -eq "y") {
        Set-SSHServerConfig -Path $script:ConfigPathServer
    }
}

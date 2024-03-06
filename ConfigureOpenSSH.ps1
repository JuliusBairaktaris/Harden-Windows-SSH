function Test-IsAdmin {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
}

function Invoke-ElevateScript {
    Start-Process PowerShell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

function Set-sshClientConfig {
    param (
        [Parameter(Mandatory)]
        [string]$Path
    )

    if ($Path -eq $GLOBAL:ConfigPath -and (Test-Path -Path $GLOBAL:ConfigPathUser)) {
        $DeleteUserConfig = Read-Host "A user-specific configuration file exists which overrides the system-wide configuration. Do you wish to remove it? (Y/N)"
        if ($DeleteUserConfig -eq "Y" -or $DeleteUserConfig -eq "y") {
            Remove-Item -Path $ConfigPathUser
            Write-Host "User-specific configuration file has been removed."
        }
    }

    $applyOverrides = Read-Host "Do you wish to apply additional overrides to the configuration? (Y/N)"
    if ($applyOverrides -eq "Y" -or $applyOverrides -eq "y") {
        $GLOBAL:sshConfig = $GLOBAL:sshConfig -replace '(?<=MACs\s)([^\r\n]*)', '$1,hmac-sha2-256'
    }

    Set-Content -Path $Path -Value $GLOBAL:sshConfig
    if ($GLOBAL:sshVersion -match "_9\.") {
        Add-Content -Path $Path -Value $GLOBAL:sshConfigV9
    }
    Write-Host "SSH configuration has been added to $Path"
}

function Set-sshServerConfig {
    param (
        [Parameter(Mandatory)]
        [string]$Path
    )

    Stop-Service -Name sshd
    if (Test-Path -Path $ConfigPathServer) {
        $RemoveSSHD = Read-Host "A configuration file for the OpenSSH server already exists. Do you wish to remove it? (Y/N)"
        if ($RemoveSSHD -eq "Y" -or $RemoveSSHD -eq "y") {
            Remove-Item -Path $ConfigPathServer
            Write-Host "OpenSSH server configuration file has been removed."
        }
    } 

    #Ensures configuration file exists
    Start-Service -Name sshd
    Stop-Service -Name sshd
    $lineToFind = "#HostKey __PROGRAMDATA__/ssh/ssh_host_ed25519_key"
    $fileContent = Get-Content $Path
    $lineIndex = $fileContent.IndexOf($lineToFind)
    if ($GLOBAL:sshVersion -match "_9\.") {
        $newContent = $fileContent[$lineIndex] + "`r`n" + $GLOBAL:sshConfigServer + $GLOBAL:sshConfigV9
    }
    else {
        $newContent = $fileContent[$lineIndex] + "`r`n" + $GLOBAL:sshConfigServer
    }
    $fileContent[$lineIndex] = $newContent
    # Write the updated content back to the file
    $fileContent | Set-Content $Path
    Write-Host "OpenSSH server configuration has been added to $Path"
    Read-Host "Press any key to exit..."
    exit
}

# Define the path to the .ssh directory & the configuration file
$ConfigPath = Join-Path -Path $env:PROGRAMDATA -ChildPath "ssh\ssh_config"
$ConfigPathUser = Join-Path -Path $env:USERPROFILE -ChildPath ".ssh\config"
$ConfigPathServer = Join-Path -Path $env:PROGRAMDATA -ChildPath "ssh\sshd_config"
$sshVersion = & ssh -V 2>&1

# SSH configuration
$sshConfig = @"
Host *
 KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256

 Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

 MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com

 HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256

 CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256

 PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256
"@
$sshConfigV9 = @"
 HostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256
"@

$sshConfigServer = @"
HostKey __PROGRAMDATA__/ssh/ssh_host_rsa_key
HostKey __PROGRAMDATA__/ssh/ssh_host_ed25519_key

KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256

Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com

HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256

CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256

HostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256

PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256
"@

if ($sshVersion -match "_8\.") {
    $UpdateOpenSSH = Read-Host "Do you wish to install the latest version of OpenSSH? (Y/N)"
    if ($UpdateOpenSSH -eq "Y" -or $UpdateOpenSSH -eq "y") {
        Start-Process winget -ArgumentList "install -e --id Microsoft.OpenSSH.Beta" -Wait -NoNewWindow
        $sshVersion = & ssh -V 2>&1
    }
}

if (-not (Test-IsAdmin)) {
    Write-Host "This script requires administrator privileges to harden the OpenSSH client configuration system-wide & the OpenSSH server configuration!"
    $ElevateScript = Read-Host "Do you wish to run this script with elevated privileges? (Y/N)"
    if ($ElevateScript -eq "Y" -or $ElevateScript -eq "y") {
        Invoke-ElevateScript
    }
    else {
        $HardenClientUser = Read-Host "Do you wish to harden the OpenSSH client configuration for the current user profile? (Y/N)"
        if ($HardenClientUser -eq "Y" -or $HardenClientUser -eq "y") {
            Set-sshClientConfig -Path $ConfigPathUser
        }
    }
}

else {
    $HardenClient = Read-Host "Do you wish to harden the OpenSSH client configuration? (Y/N)"
    if ($HardenClient -eq "Y" -or $HardenClient -eq "y") {
        $CurrentUserOnly = Read-Host "Choose an option:
1 - Apply the hardening script to the current user only. (This will only affect your user profile.)
2 - Apply the hardening script system-wide. (Requires administrator privileges; affects all users on this system.)
Enter 1 or 2"

        switch ($CurrentUserOnly) {
            "1" {
                Set-sshClientConfig -Path $ConfigPathUser
            }
            "2" {
                Set-sshClientConfig -Path $ConfigPath
            }
            default {
                Read-Host "Invalid input. Press any key to exit..."
                exit
            }
        }
    }

    $HardenServer = Read-Host "Do you wish to harden the OpenSSH server configuration? (Y/N)"
    if ($HardenServer -eq "Y" -or $HardenServer -eq "y") {
        Set-sshServerConfig -Path $ConfigPathServer
    }
}
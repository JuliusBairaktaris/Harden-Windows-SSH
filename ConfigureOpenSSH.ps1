param (
    [switch]$AdminMode
)

function Test-IsAdmin {
    return ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
}

function Invoke-ElevateScript {
    Start-Process PowerShell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -AdminMode" -Verb RunAs
    exit
}

function Set-SSHConfig {
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
    Write-Host "SSH configuration has been appended to $Path"
}

# Define the path to the .ssh directory & the configuration file
$ConfigPath = Join-Path -Path $env:PROGRAMDATA -ChildPath "ssh\ssh_config"
$ConfigPathUser = Join-Path -Path $env:USERPROFILE -ChildPath ".ssh\config"
$sshVersion = & ssh -V 2>&1

# SSH configuration
$sshConfig = @"
Host *
 Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

 KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512

 MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com

 HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256

 CASignatureAlgorithms sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512,rsa-sha2-256

 PubkeyAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256
"@
$sshConfigV9 = @"

 HostbasedAcceptedAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,sk-ssh-ed25519@openssh.com,ssh-ed25519,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-256

"@

if ($AdminMode) {
    Set-SSHConfig -Path $ConfigPath
    Read-host "Press any key to exit..."
    exit
}

$CurrentUserOnly = Read-Host "Choose an option:
1 - Apply the hardening script to the current user only. (This will only affect your user profile.)
2 - Apply the hardening script system-wide. (Requires administrator privileges; affects all users on this system.)
Enter 1 or 2"

switch ($CurrentUserOnly) {
    "1" {
        Set-SSHConfig -Path $ConfigPathUser
    }
    "2" {
        if (-not (Test-IsAdmin)) {
            Invoke-ElevateScript
        }
        else {
            Set-SSHConfig -Path $ConfigPath
        }
    }
    default {
        Read-Host "Invalid input. Press any key to exit..."
        exit
    }
}
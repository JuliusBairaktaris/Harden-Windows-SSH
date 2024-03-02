# Harden-Windows-SSH

The OpenSSH implementation in Windows 11 is vulnerable to security weaknesses, including the recently discovered [Terrapin attack](https://nvd.nist.gov/vuln/detail/CVE-2023-48795) among other security weaknesses. This repository provides PowerShell scripts to mitigate these weaknesses as much as possible. The hardening measures are taken from [SSH-Audit](https://www.sshaudit.com/).

## Compliance Statement
This module, alongside its hardening measures, adheres completely to the specifications outlined in the Technical Guideline [Technical Guideline TR-02102-4](https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/Publications/TechGuidelines/TG02102/BSI-TR-02102-4.pdf?__blob=publicationFile&v=5) issued by the German Federal Office for Information Security (Bundesamt für Sicherheit in der Informationstechnik, BSI). The inclusion of NIST ciphers has been deliberately omitted due to their contentious nature.

## Install latest OpenSSH version for Windows

It is strongly recommended to upgrade to the beta version of the OpenSSH implementation for Windows using winget, which patches the Terrapin vulnerability (CVE-2023-48795).
```
winget install -e --id Microsoft.OpenSSH.Beta
```
To test which OpenSSH version you are currently running, run in a terminal:
```
ssh -V
```

## How to harden the OpenSSH implementation
Execute:
```powershell
irm 'https://raw.githubusercontent.com/JuliusBairaktaris/Harden-Windows-SSH/main/ConfigureOpenSSH.ps1' | iex
```

[In Windows, the OpenSSH Client (ssh) reads configuration data from a configuration file in the following order](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_server_configuration): 

1. By launching ssh.exe with the -F parameter, specifying a path to a configuration file and an entry name from that file.
2. A user's configuration file at %userprofile%\.ssh\config.
3. The system-wide configuration file at %programdata%\ssh\ssh_config.


#### Optional overrides
-  `hmac-sha2-256`: This MAC is necessary to connect to the default SSH configuration of OpenWRT, Debian, DietPi, and other similar systems.

## Security Scores using [SSH-Audit](https://www.sshaudit.com/)
Default OpenSSH v8.X Configuration: 
<img src="https://github.com/JuliusBairaktaris/Harden-Windows-SSH/blob/main/Images/Default_OpenSSHv8.png" alt="Default Windows OpenSSH v8 Client Score">

Hardened OpenSSH v8.X Client Configuration:
<img src="https://github.com/JuliusBairaktaris/Harden-Windows-SSH/blob/main/Images/Hardened_OpenSSHv8.png" alt="Hardend Windows OpenSSH v8 Client Score">

Default OpenSSH v8.X Server Configuration:
<img src="https://github.com/JuliusBairaktaris/Harden-Windows-SSH/blob/main/Images/Default_OpenSSHv8_Server.png" alt="Default Windows OpenSSH v8 Server Score">

Hardened OpenSSH v8.X Server Configuration:
<img src="https://github.com/JuliusBairaktaris/Harden-Windows-SSH/blob/main/Images/Hardened_OpenSSHv8_Server.png" alt="Hardend Windows OpenSSH v8 Server Score">




## Further hardening recommendations
To further secure Windows, check out the great [Harden-Windows-Security](https://github.com/HotCakeX/Harden-Windows-Security) module by [HotCakeX](https://github.com/HotCakeX/Harden-Windows-Security).

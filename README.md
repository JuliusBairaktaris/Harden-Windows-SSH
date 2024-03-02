# Harden-Windows-SSH

The OpenSSH implementation in Windows 11 is vulnerable to security weaknesses, including the recently discovered [Terrapin attack](https://nvd.nist.gov/vuln/detail/CVE-2023-48795) among other security weaknesses. This repository provides PowerShell scripts to mitigate these weaknesses as much as possible.


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


#### Optional Overrides
-  `hmac-sha2-256`: This MAC is necessary to connect to the default SSH configuration of OpenWRT, Debian, DietPi, and other similar systems.

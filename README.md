# Harden-Windows-SSH

This repository provides a PowerShell script to harden the OpenSSH client and server configuration on Windows. It makes your SSH connections more secure by disabling outdated algorithms and enabling modern, more secure options, including post-quantum cryptography for recent OpenSSH versions.

The script is designed to be:

- **Modular:** The SSH configurations are stored in external `ssh_config` and `sshd_config` files, making them easy to view and customize.
- **Intelligent:** It automatically detects your OpenSSH version and applies the most secure settings your client can support. This means you get the benefits of post-quantum cryptography on newer versions without breaking older clients.
- **Secure:** The hardening measures are based on recommendations from [SSH-Audit](https://www.sshaudit.com/) and the latest best practices in SSH security.

## How it Works

The `ConfigureOpenSSH.ps1` script performs the following actions:

1. **Reads Base Configuration:** It reads the baseline hardened configurations from the `ssh_config` and `sshd_config` files in this repository.
2. **Detects SSH Version:** It checks your system's OpenSSH version.
3. **Applies Modern Features (Conditionally):** Based on your SSH version, it dynamically adds advanced security features:
    - **Post-Quantum Key Exchange:** For OpenSSH 9.0+, it adds `sntrup761x25519-sha512@openssh.com`. For 9.9+, it adds `mlkem768x25519-sha256`.
    - **Weak Crypto Warning:** For OpenSSH 10.1+, it adds `WarnWeakCrypto no` to the client configuration.
4. **Applies Configuration:** It applies the generated configuration to your system's OpenSSH client and/or server.

## How to Use

Execute the following command in PowerShell to run the script:

```powershell
irm 'https://raw.githubusercontent.com/JuliusBairaktaris/Harden-Windows-SSH/main/ConfigureOpenSSH.ps1' | iex
```

The script will guide you through the process of hardening your OpenSSH client and/or server.

## Customization

You can easily customize the SSH configurations by editing the `ssh_config` and `sshd_config` files in this repository before running the script. If you have forked this repository, you can modify the files in your fork and the script will use your customized versions.

The base configuration applied by the script is as follows:

```
# ssh_config and sshd_config base
KexAlgorithms curve25519-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,diffie-hellman-group-exchange-sha256
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com
HostKeyAlgorithms sk-ssh-ed25519-cert-v01@openssh.com,ssh-ed25519-cert-v01@openssh.com,rsa-sha2-512-cert-v01@openssh.com,rsa-sha2-256-cert-v01@openssh.com,rsa-sha2-512,rsa-sha2-256
```

## Install the Latest OpenSSH Version

To take full advantage of the latest security features, it is strongly recommended to upgrade to the latest version of OpenSSH for Windows using winget.

```
winget install Microsoft.OpenSSH.Preview
```

To check your current OpenSSH version, run:

```
ssh -V
```

## Security Scores using [SSH-Audit](https://www.sshaudit.com/)

Default OpenSSH v8.X Configuration:
<img src="https://github.com/JuliusBairaktaris/Harden-Windows-SSH/blob/main/Images/Default_OpenSSHv8.png" alt="Default Windows OpenSSH v8 Client Score">

Hardened OpenSSH v8.X Client Configuration:
<img src="https://github.com/JuliusBairaktaris/Harden-Windows-SSH/blob/main/Images/Hardened_OpenSSHv8.png" alt="Hardend Windows OpenSSH v8 Client Score">

Default OpenSSH v8.X Server Configuration:
<img src="https://github.com/JuliusBairaktaris/Harden-Windows-SSH/blob/main/Images/Default_OpenSSHv8_Server.png" alt="Default Windows OpenSSH v8 Server Score">

Hardened OpenSSH v8.X Server Configuration:
<img src="https://github.com/JuliusBairaktaris/Harden-Windows-SSH/blob/main/Images/Hardened_OpenSSHv8_Server.png" alt="Hardend Windows OpenSSH v8 Server Score">

## Further Hardening

For comprehensive security hardening of your Windows system, check out the excellent [Harden-Windows-Security](https://github.com/HotCakeX/Harden-Windows-Security) module.

# Linux Server Security Audit and Hardening Script

## Overview

This Bash script automates the process of performing security audits and applying hardening measures on Linux servers. It includes checks for user and group audits, file permissions, service audits, firewall and network security, IP and network configuration, security updates, log monitoring, and server hardening.

## Features

- **User and Group Audits**: Lists all users and groups, checks for root privileges, and identifies weak passwords.
- **File and Directory Permissions**: Scans for world-writable files, SSH directory permissions, and SUID/SGID bits.
- **Service Audits**: Lists running services and checks for unnecessary or unauthorized services.
- **Firewall and Network Security**: Verifies firewall configuration, open ports, and network settings.
- **IP and Network Configuration Checks**: Identifies public vs. private IP addresses and checks for sensitive services on public IPs.
- **Security Updates and Patching**: Checks for available security updates and ensures automatic updates are configured.
- **Log Monitoring**: Monitors logs for suspicious entries, such as failed SSH login attempts.
- **Server Hardening**: Implements SSH hardening, disables IPv6 (if not required), secures the GRUB bootloader, and configures the firewall.

## Usage

### Running the Script

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/security-audit-script.git
   cd security-audit-script
   
2. **Make the script executable**
```bash
 chmod +x automate.sh
```

 3. **Run the script with the desired option**:
 ```bash
sudo ./automate.sh [option]
```


**Available Options**
-user_audit: Perform User and Group Audit

-file_permissions: Perform File and Directory Permissions Audit

-service_audit: Perform Service Audit

-firewall: Check Firewall and Network Security

-ip_checks: Perform IP and Network Configuration Checks

-security_updates: Check for Security Updates and Patching

-log_monitoring: Monitor Logs for Suspicious Entries

-server_hardening: Apply Server Hardening Steps

-all: Run all checks and hardening steps

-help: Display the help message


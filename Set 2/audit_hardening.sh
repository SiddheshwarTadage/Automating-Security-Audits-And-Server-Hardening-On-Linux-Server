#!/bin/bash

# Function: User and Group Audit
user_group_audit() {
    echo "Performing User and Group Audit..."
    # List all users and groups
    echo "Users and Groups:"
    cat /etc/passwd
    cat /etc/group

    # Check for users with UID 0 (root privileges)
    echo "Users with UID 0:"
    awk -F: '($3 == 0) {print}' /etc/passwd

    # Identify users without passwords or with weak passwords
    echo "Users without passwords or with weak passwords:"
    awk -F: '($2 == "" || length($2) < 6) {print $1}' /etc/shadow
}

# Function: File and Directory Permissions Audit
file_permissions_audit() {
    echo "Performing File and Directory Permissions Audit..."
    # Scan for world-writable files and directories
    echo "World-writable files and directories:"
    find / -type d -perm -0002 -ls 2>/dev/null
    find / -type f -perm -0002 -ls 2>/dev/null

    # Check for the presence of SSH directories and secure permissions
    echo "Checking SSH directories for secure permissions..."
    ls -ld /home/*/.ssh

    # Report files with SUID or SGID bits set
    echo "Files with SUID/SGID bits set:"
    find / -perm /6000 -type f 2>/dev/null
}

# Function: Service Audit
service_audit() {
    echo "Performing Service Audit..."
    # List all running services
    echo "Running Services:"
    systemctl list-units --type=service --state=running

    # Check for unnecessary or unauthorized services
    echo "Checking for unnecessary services..."
    # Custom list of services to check
    unnecessary_services=("cups" "avahi-daemon" "rpcbind")
    for service in "${unnecessary_services[@]}"; do
        systemctl is-active --quiet $service && echo "$service is running"
    done

    # Ensure critical services are running
    critical_services=("sshd" "iptables")
    for service in "${critical_services[@]}"; do
        systemctl is-active --quiet $service && echo "$service is running" || echo "$service is NOT running!"
    done
}

# Function: Firewall and Network Security
firewall_network_security() {
    echo "Checking Firewall and Network Security..."
    # Verify firewall status and configuration
    echo "Firewall status:"
    ufw status || iptables -L

    # Report open ports and associated services
    echo "Open ports and associated services:"
    netstat -tuln

    # Check for IP forwarding and insecure network configurations
    echo "IP forwarding status:"
    sysctl net.ipv4.ip_forward
    sysctl net.ipv6.conf.all.forwarding
}

# Function: IP and Network Configuration Checks
ip_network_checks() {
    echo "Performing IP and Network Configuration Checks..."
    # Identify public vs. private IPs
    echo "IP Addresses (Public vs. Private):"
    ip addr show | grep "inet"

    # Check for sensitive services on public IPs
    echo "Checking sensitive services on public IPs..."
    # Example check for SSH on public IPs
    ss -tunlp | grep ":22"
}

# Function: Security Updates and Patching
security_updates() {
    echo "Checking for Security Updates and Patching..."
    # Check for available security updates
    echo "Available security updates:"
    apt-get update && apt-get upgrade -s | grep "Inst"

    # Ensure automatic updates are configured
    echo "Checking for automatic updates configuration..."
    grep -i "APT::Periodic::Update-Package-Lists" /etc/apt/apt.conf.d/*
}

# Function: Log Monitoring
log_monitoring() {
    echo "Monitoring Logs for Suspicious Entries..."
    # Check for suspicious log entries
    echo "Recent SSH login attempts:"
    grep "Failed password" /var/log/auth.log

    echo "Suspicious entries in system logs:"
    grep -i "error" /var/log/syslog
}

# Function: Server Hardening
server_hardening() {
    echo "Applying Server Hardening Steps..."
    # SSH Configuration
    echo "Configuring SSH for key-based authentication..."
    sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
    systemctl reload sshd

    # Disable IPv6 if not required
    echo "Disabling IPv6..."
    echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
    sysctl -p

    # Secure the bootloader (GRUB)
    echo "Securing GRUB bootloader..."
    grub-mkpasswd-pbkdf2
    # Add the generated password hash to /etc/grub.d/40_custom

    # Firewall Configuration
    echo "Configuring firewall..."
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT ACCEPT
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    iptables-save > /etc/iptables/rules.v4
}

# Display help message
display_help() {
    echo "Usage: $0 [option]"
    echo "Options:"
    echo "-user_audit           Perform User and Group Audit"
    echo "-file_permissions     Perform File and Directory Permissions Audit"
    echo "-service_audit        Perform Service Audit"
    echo "-firewall             Check Firewall and Network Security"
    echo "-ip_checks            Perform IP and Network Configuration Checks"
    echo "-security_updates     Check for Security Updates and Patching"
    echo "-log_monitoring       Monitor Logs for Suspicious Entries"
    echo "-server_hardening     Apply Server Hardening Steps"
    echo "-all                  Run all checks and hardening steps"
    echo "-help                 Display this help message"
}

# Main script execution
case "$1" in
    -user_audit)
        user_group_audit
        ;;
    -file_permissions)
        file_permissions_audit
        ;;
    -service_audit)
        service_audit
        ;;
    -firewall)
        firewall_network_security
        ;;
    -ip_checks)
        ip_network_checks
        ;;
    -security_updates)
        security_updates
        ;;
    -log_monitoring)
        log_monitoring
        ;;
    -server_hardening)
        server_hardening
        ;;
    -all)
        user_group_audit
        file_permissions_audit
        service_audit
        firewall_network_security
        ip_network_checks
        security_updates
        log_monitoring
        server_hardening
        ;;
    -help)
        display_help
        ;;
    *)
        echo "Invalid option! Use -help for usage information."
        ;;
esac

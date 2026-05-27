#!/usr/local/bin/python3
#==========================================================================
#
#           File : services.py
#        Project : Linux Hardening Toolkit
#    Description : Contains definitions for ports / services
#                  To be called by linuxSecureconfigEvaluation.py
#
# History
#---------
#
# 260519    KL  Initial Prototype
#
#==========================================================================
#--------------
# Firewall Checks - Provide nested dictionaries of some ports and their associated info
#--------------
def standardPortDefinitionInformation():
    ports = {
        22: {
            "classification": "Core Administrative Ports",
            "port": 22,
            "protocol": "TCP",
            "service": "SSH",
            "risk_level": "LOW",
            "recommended": "Yes",
            "recommendation": "Restrict to trusted IPs, disable password authentication, enforce key-based auth"
        },

        23: {
            "classification": "Core Administrative Ports",
            "port": 23,
            "protocol": "TCP",
            "service": "Telnet",
            "risk_level": "HIGH",
            "recommended": "No",
            "recommendation": "Remove and replace with SSH"
        },

        3389: {
            "classification": "Core Administrative Ports",
            "port": 3389,
            "protocol": "TCP",
            "service": "RDP",
            "risk_level": "HIGH",
            "recommended": "Rarely",
            "recommendation": "Restrict via VPN or internal-only access"
        },

        5900: {
            "classification": "Core Administrative Ports",
            "port": 5900,
            "protocol": "TCP",
            "service": "VNC",
            "risk_level": "HIGH",
            "recommended": "Rarely",
            "recommendation": "Restrict to internal networks and require encryption"
        },

        80: {
            "classification": "Web & Application Ports",
            "port": 80,
            "protocol": "TCP",
            "service": "HTTP",
            "risk_level": "MEDIUM",
            "recommended": "Sometimes",
            "recommendation": "Redirect traffic to HTTPS where possible"
        },

        443: {
            "classification": "Web & Application Ports",
            "port": 443,
            "protocol": "TCP",
            "service": "HTTPS",
            "risk_level": "LOW",
            "recommended": "Yes",
            "recommendation": "Enforce TLS 1.2+ and strong ciphers"
        },

        8080: {
            "classification": "Web & Application Ports",
            "port": 8080,
            "protocol": "TCP",
            "service": "Alternate HTTP",
            "risk_level": "MEDIUM",
            "recommended": "Sometimes",
            "recommendation": "Restrict exposure and validate application security"
        },

        8443: {
            "classification": "Web & Application Ports",
            "port": 8443,
            "protocol": "TCP",
            "service": "Alternate HTTPS",
            "risk_level": "MEDIUM",
            "recommended": "Sometimes",
            "recommendation": "Use valid TLS certificates and restrict unnecessary access"
        },

        8000: {
            "classification": "Web & Application Ports",
            "port": 8000,
            "protocol": "TCP",
            "service": "Dev/Test Web Apps",
            "risk_level": "MEDIUM",
            "recommended": "No",
            "recommendation": "Avoid exposing development services publicly"
        },

        3000: {
            "classification": "Web & Application Ports",
            "port": 3000,
            "protocol": "TCP",
            "service": "Node.js Dev Server",
            "risk_level": "MEDIUM",
            "recommended": "No",
            "recommendation": "Restrict to localhost or internal development environments"
        },

        5000: {
            "classification": "Web & Application Ports",
            "port": 5000,
            "protocol": "TCP",
            "service": "Flask/Dev Apps",
            "risk_level": "MEDIUM",
            "recommended": "No",
            "recommendation": "Restrict to internal access and production-grade reverse proxy"
        },

        3306: {
            "classification": "Database Ports",
            "port": 3306,
            "protocol": "TCP",
            "service": "MySQL",
            "risk_level": "HIGH",
            "recommended": "Internal Only",
            "recommendation": "Bind to localhost or private network only"
        },

        5432: {
            "classification": "Database Ports",
            "port": 5432,
            "protocol": "TCP",
            "service": "PostgreSQL",
            "risk_level": "HIGH",
            "recommended": "Internal Only",
            "recommendation": "Restrict external access and enforce authentication"
        },

        1433: {
            "classification": "Database Ports",
            "port": 1433,
            "protocol": "TCP",
            "service": "MSSQL",
            "risk_level": "HIGH",
            "recommended": "Internal Only",
            "recommendation": "Restrict via firewall and require strong authentication"
        },

        1521: {
            "classification": "Database Ports",
            "port": 1521,
            "protocol": "TCP",
            "service": "Oracle DB",
            "risk_level": "HIGH",
            "recommended": "Internal Only",
            "recommendation": "Restrict to application hosts only"
        },

        27017: {
            "classification": "Database Ports",
            "port": 27017,
            "protocol": "TCP",
            "service": "MongoDB",
            "risk_level": "HIGH",
            "recommended": "Internal Only",
            "recommendation": "Disable public exposure and enable authentication"
        },

        6379: {
            "classification": "Database Ports",
            "port": 6379,
            "protocol": "TCP",
            "service": "Redis",
            "risk_level": "HIGH",
            "recommended": "Internal Only",
            "recommendation": "Bind locally and require authentication"
        },

        2375: {
            "classification": "Container & Cloud-Native Ports",
            "port": 2375,
            "protocol": "TCP",
            "service": "Docker API (unencrypted)",
            "risk_level": "CRITICAL",
            "recommended": "No",
            "recommendation": "Disable immediately or enforce TLS"
        },

        2376: {
            "classification": "Container & Cloud-Native Ports",
            "port": 2376,
            "protocol": "TCP",
            "service": "Docker TLS API",
            "risk_level": "HIGH",
            "recommended": "Internal Only",
            "recommendation": "Restrict to trusted management hosts"
        },

        6443: {
            "classification": "Container & Cloud-Native Ports",
            "port": 6443,
            "protocol": "TCP",
            "service": "Kubernetes API",
            "risk_level": "CRITICAL",
            "recommended": "Internal Only",
            "recommendation": "Restrict access with RBAC and network controls"
        },

        10250: {
            "classification": "Container & Cloud-Native Ports",
            "port": 10250,
            "protocol": "TCP",
            "service": "kubelet API",
            "risk_level": "HIGH",
            "recommended": "Internal Only",
            "recommendation": "Require authentication and restrict access"
        },

        10255: {
            "classification": "Container & Cloud-Native Ports",
            "port": 10255,
            "protocol": "TCP",
            "service": "Read-only kubelet",
            "risk_level": "CRITICAL",
            "recommended": "No",
            "recommendation": "Disable read-only kubelet endpoint"
        },

        1194: {
            "classification": "VPN & Security Services",
            "port": 1194,
            "protocol": "UDP",
            "service": "OpenVPN",
            "risk_level": "LOW",
            "recommended": "Yes",
            "recommendation": "Enforce certificate authentication"
        },

        51820: {
            "classification": "VPN & Security Services",
            "port": 51820,
            "protocol": "UDP",
            "service": "WireGuard",
            "risk_level": "LOW",
            "recommended": "Yes",
            "recommendation": "Restrict peer access and rotate keys regularly"
        }
    }

    return ports_dict

#==============================
# Reports services for service minimization checks
#==============================
def systemServicesInformation():
    services = {
        "sshd": {
            "classification": "Essential",
            "risk": "LOW",
            "recommended": "Yes",
            "status_if_running": "PASS",
            "recommendation": "Restrict SSH access to trusted IP ranges and enforce key-based authentication"
        },

        "systemd-journald": {
            "classification": "Essential",
            "risk": "LOW",
            "recommended": "Yes",
            "status_if_running": "PASS",
            "recommendation": "Ensure persistent logging is enabled"
        },

        "rsyslog": {
            "classification": "Logging",
            "risk": "LOW",
            "recommended": "Yes",
            "status_if_running": "PASS",
            "recommendation": "Centralize and rotate logs appropriately"
        },

        "auditd": {
            "classification": "Security Auditing",
            "risk": "LOW",
            "recommended": "Yes",
            "status_if_running": "PASS",
            "recommendation": "Ensure audit logging rules are configured properly"
        },

        "chronyd": {
            "classification": "Infrastructure",
            "risk": "LOW",
            "recommended": "Yes",
            "status_if_running": "PASS",
            "recommendation": "Synchronize time with trusted NTP servers"
        },

        "systemd-timesyncd": {
            "classification": "Infrastructure",
            "risk": "LOW",
            "recommended": "Yes",
            "status_if_running": "PASS",
            "recommendation": "Ensure accurate system time synchronization"
        },

        "cron": {
            "classification": "Infrastructure",
            "risk": "LOW",
            "recommended": "Yes",
            "status_if_running": "INFO",
            "recommendation": "Review scheduled tasks for unauthorized entries"
        },

        "crond": {
            "classification": "Infrastructure",
            "risk": "LOW",
            "recommended": "Yes",
            "status_if_running": "INFO",
            "recommendation": "Review scheduled tasks for unauthorized entries"
        },

        "nginx": {
            "classification": "Web Server",
            "risk": "MEDIUM",
            "recommended": "Depends",
            "status_if_running": "INFO",
            "recommendation": "Validate intended exposure and harden TLS configuration"
        },

        "apache2": {
            "classification": "Web Server",
            "risk": "MEDIUM",
            "recommended": "Depends",
            "status_if_running": "INFO",
            "recommendation": "Disable unused modules and enforce HTTPS"
        },

        "httpd": {
            "classification": "Web Server",
            "risk": "MEDIUM",
            "recommended": "Depends",
            "status_if_running": "INFO",
            "recommendation": "Disable unnecessary functionality and validate exposure"
        },

        "mysql": {
            "classification": "Database",
            "risk": "HIGH",
            "recommended": "Internal Only",
            "status_if_running": "WARN",
            "recommendation": "Restrict access to trusted internal systems only"
        },

        "mysqld": {
            "classification": "Database",
            "risk": "HIGH",
            "recommended": "Internal Only",
            "status_if_running": "WARN",
            "recommendation": "Bind database service to localhost or private interfaces"
        },

        "postgresql": {
            "classification": "Database",
            "risk": "HIGH",
            "recommended": "Internal Only",
            "status_if_running": "WARN",
            "recommendation": "Restrict external connectivity and enforce authentication"
        },

        "mongod": {
            "classification": "Database",
            "risk": "HIGH",
            "recommended": "Internal Only",
            "status_if_running": "WARN",
            "recommendation": "Disable public exposure and require authentication"
        },

        "redis-server": {
            "classification": "Database",
            "risk": "HIGH",
            "recommended": "Internal Only",
            "status_if_running": "WARN",
            "recommendation": "Restrict Redis to internal interfaces and enable authentication"
        },

        "docker": {
            "classification": "Containerization",
            "risk": "MEDIUM",
            "recommended": "Depends",
            "status_if_running": "INFO",
            "recommendation": "Restrict Docker socket access and validate daemon exposure"
        },

        "containerd": {
            "classification": "Containerization",
            "risk": "MEDIUM",
            "recommended": "Depends",
            "status_if_running": "INFO",
            "recommendation": "Validate container runtime security settings"
        },

        "kubelet": {
            "classification": "Kubernetes",
            "risk": "HIGH",
            "recommended": "Internal Only",
            "status_if_running": "WARN",
            "recommendation": "Ensure authentication and authorization are enforced"
        },

        "etcd": {
            "classification": "Kubernetes",
            "risk": "CRITICAL",
            "recommended": "Internal Only",
            "status_if_running": "WARN",
            "recommendation": "Restrict access and enable TLS encryption"
        },

        "prometheus": {
            "classification": "Monitoring",
            "risk": "MEDIUM",
            "recommended": "Internal Only",
            "status_if_running": "INFO",
            "recommendation": "Restrict metrics access to trusted systems"
        },

        "grafana-server": {
            "classification": "Monitoring",
            "risk": "MEDIUM",
            "recommended": "Internal Only",
            "status_if_running": "WARN",
            "recommendation": "Require authentication and avoid public exposure"
        },

        "telnet": {
            "classification": "Legacy/Insecure",
            "risk": "HIGH",
            "recommended": "No",
            "status_if_running": "FAIL",
            "recommendation": "Remove Telnet and replace with SSH"
        },

        "telnet.socket": {
            "classification": "Legacy/Insecure",
            "risk": "HIGH",
            "recommended": "No",
            "status_if_running": "FAIL",
            "recommendation": "Disable Telnet socket service immediately"
        },

        "vsftpd": {
            "classification": "Legacy/Insecure",
            "risk": "HIGH",
            "recommended": "No",
            "status_if_running": "FAIL",
            "recommendation": "Replace FTP with SFTP or SCP"
        },

        "proftpd": {
            "classification": "Legacy/Insecure",
            "risk": "HIGH",
            "recommended": "No",
            "status_if_running": "FAIL",
            "recommendation": "Replace insecure FTP services"
        },

        "tftpd": {
            "classification": "Legacy/Insecure",
            "risk": "HIGH",
            "recommended": "No",
            "status_if_running": "FAIL",
            "recommendation": "Disable TFTP unless explicitly required"
        },

        "rsh": {
            "classification": "Legacy/Insecure",
            "risk": "HIGH",
            "recommended": "No",
            "status_if_running": "FAIL",
            "recommendation": "Remove insecure remote shell services"
        },

        "rexec": {
            "classification": "Legacy/Insecure",
            "risk": "HIGH",
            "recommended": "No",
            "status_if_running": "FAIL",
            "recommendation": "Disable insecure remote execution services"
        },

        "rlogin": {
            "classification": "Legacy/Insecure",
            "risk": "HIGH",
            "recommended": "No",
            "status_if_running": "FAIL",
            "recommendation": "Remove insecure legacy authentication services"
        },

        "cups": {
            "classification": "Optional Desktop",
            "risk": "MEDIUM",
            "recommended": "Depends",
            "status_if_running": "WARN",
            "recommendation": "Disable printing services on servers if unnecessary"
        },

        "avahi-daemon": {
            "classification": "Optional Desktop",
            "risk": "MEDIUM",
            "recommended": "No",
            "status_if_running": "WARN",
            "recommendation": "Disable multicast discovery services on servers"
        },

        "bluetooth": {
            "classification": "Optional Hardware",
            "risk": "MEDIUM",
            "recommended": "No",
            "status_if_running": "WARN",
            "recommendation": "Disable Bluetooth services on systems where unnecessary"
        },

        "smb": {
            "classification": "File Sharing",
            "risk": "HIGH",
            "recommended": "Internal Only",
            "status_if_running": "WARN",
            "recommendation": "Restrict SMB exposure and disable SMBv1"
        },

        "nmb": {
            "classification": "File Sharing",
            "risk": "HIGH",
            "recommended": "Internal Only",
            "status_if_running": "WARN",
            "recommendation": "Restrict NetBIOS exposure"
        },

        "nfs-server": {
            "classification": "File Sharing",
            "risk": "HIGH",
            "recommended": "Internal Only",
            "status_if_running": "WARN",
            "recommendation": "Restrict NFS exports to trusted systems"
        },

        "rpcbind": {
            "classification": "Infrastructure",
            "risk": "MEDIUM",
            "recommended": "Depends",
            "status_if_running": "WARN",
            "recommendation": "Disable RPC services if not required"
        },

        "snmpd": {
            "classification": "Monitoring",
            "risk": "HIGH",
            "recommended": "Internal Only",
            "status_if_running": "WARN",
            "recommendation": "Use SNMPv3 and restrict community access"
        },

        "named": {
            "classification": "DNS",
            "risk": "MEDIUM",
            "recommended": "Depends",
            "status_if_running": "INFO",
            "recommendation": "Restrict recursive queries and zone transfers"
        },

        "bind9": {
            "classification": "DNS",
            "risk": "MEDIUM",
            "recommended": "Depends",
            "status_if_running": "INFO",
            "recommendation": "Restrict DNS recursion and external administration"
        },

        "fail2ban": {
            "classification": "Security",
            "risk": "LOW",
            "recommended": "Yes",
            "status_if_running": "PASS",
            "recommendation": "Ensure brute-force protections are properly configured"
        },

        "clamav-daemon": {
            "classification": "Security",
            "risk": "LOW",
            "recommended": "Optional",
            "status_if_running": "INFO",
            "recommendation": "Keep malware definitions updated"
        },

        "aide": {
            "classification": "Security",
            "risk": "LOW",
            "recommended": "Yes",
            "status_if_running": "PASS",
            "recommendation": "Regularly validate file integrity baselines"
        }
    }

    return services

#==========================================================================
# Main
#==========================================================================
def main():

    # Print Services information
    port_service_dict = standardPortDefinitionInformation()
    for service in port_services_dict:
        print(f"{service}")

    # Service information
    system_service_dict = systemServicesInformation()
    for sys_service in system_services_dict:
        print(f"{sys_service}")

if __name__="__main__":
    main()

# Linux Hardening Toolkit

Python-based Linux security auditing toolkit designed to identify insecure system configurations and validate common hardening controls.

The toolkit performs automated checks aligned with common enterprise security practices and CIS benchmark concepts.

---

## Features

### SSH Hardening Checks
- Detects root SSH login configuration
- Validates password authentication settings
- Checks SSH idle timeout configuration
- Identifies insecure SSH settings

### Firewall Validation
- Detects UFW/firewalld status
- Validates firewall enablement
- Checks secure deny-by-default settings
- Checks exposed listening ports

### Logging & Auditing
- Verifies `auditd` status
- Detects rsyslog configuration
- Checks journald persistence
- Validates log rotation configuration

### User & Privilege Auditing
- Identifies UID 0 accounts
- Detects users with sudo privileges
- Checks for service accounts with interactive shells

### Sysctl Hardening
- Verifies secure kernel parameters
- Checks IP forwarding configuration
- Validates SYN cookie protection

### Automatic Update
- Checks unattended upgrades enablement
- Detects configured package manager
- Verifies active update timer

### Credential Policy Auditing
- Verifies secure password configuration

### Sensitive File Permissions
- Checks for world-writable files
- Detects improper SSH key permissions
- Identifies SUID / SGID binaries
- Verifies sensitive file ownership

### Service Minimization
- Identifies running services (notes typical risk level)
- Checks exposed network services
- Detects legacy protocols (e.g. telnet, rsh, cups, etc.)

### Reporting
- Terminal-based results
- JSON audit report generation

---

## Example Output

```text
[PASS] UFW firewall enabled
[FAIL] Root SSH login permitted
[PASS] auditd service running
[WARN] 14 SUID binaries detected
```

Generated JSON report:

```json
{
  "hostname": "server01",
  "checks": {
    "ufw_enabled": "PASS",
    "ssh_root_login": "FAIL",
    "auditd_running": "PASS"
  }
}
```

---

## Project Structure

```text
linux-hardening-toolkit/
├── src/
│   ├── linuxSecureConfigEvaluation.py
│   └── services.py
├── docs/
├── screenshots/
├── examples/
├── reports/
├── tests/
├── requirements.txt
└── README.md
```

---

## Installation

Clone the repository:

```bash
git clone https://github.com/leewaye-sec/linux-hardening-toolkit.git
cd linux-hardening-toolkit
```

---

## Usage

Run the audit tool: --help

```bash
python3 src/linuxSecureConfigEvaluation.py --help
```

Run the audit tool: audit --full with verbose logging

```bash
python3 src/linuxSecureConfigEvaluation.py audit --full -v
```

Generate JSON report with specific name:

```bash
python3 src/linuxSecureConfigEvaluation.py audit --full --output server01_secure_configuration_audit_2026.json
```

Output results to STDOUT only:

```bash
python3 src/linuxSecureConfigEvaluation.py audit --full --print
```

---

## Security Considerations

- The toolkit is intended primarily for auditing and validation.
- No system changes are performed by default.
- Elevated privileges are required for certain checks.
- The tool does not store credentials or transmit data externally.

---

## Technologies Used

- Python 3
- Linux
- systemctl
- UFW / firewalld
- JSON reporting

---

## Learning Objectives

This project was built to improve practical skills in:
- Linux security hardening
- Security automation
- Python scripting
- System auditing
- Infrastructure security
- Security reporting

---

## Planned Features

- Auto-remediation mode

---

## Disclaimer

This project is intended for educational and authorized security auditing purposes only.

---

## License

MIT License

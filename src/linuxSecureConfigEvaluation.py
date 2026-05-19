#!/usr/local/bin/python3
#==========================================================================
#
#           File : main.py
#        Project : Linux Hardening Toolkit
#    Description : Checks multiple system / net settings, configures 
#                  to be in the more secure configuration
#
# History
#---------
#
# 260508    KL  Initial Prototype
#
#==========================================================================
#--------------------
# Imports
#--------------------
import sys
import os
import argparse
import logging

from pathlib import Path
import subprocess
import json
import platform
import shutil

#--------------------
# Global Variables
#--------------------
# Timestamp
global TIMESTAMP
timestamp_dirty = datetime.now()
TIMESTAMP = timestamp_dirty.strftime("%Y%m%d_%H%M%S")

# Path Definitions
global CWD
CWD = .os.path.abspath(os.getcwd())
CWD = CWD + "/"

# Check metrics
global PASSES
global FAILURES
global WARNINGS
global TOTAL_CHECKS
PASSES = 0
FAILURES = 0
WARNINGS = 0
TOTAL_CHECKS = 0

#--------------------------------------------------------------------------
# Functions
#--------------------------------------------------------------------------
#==============
# Generates name for audit report
#   Only called if not defined by user
#==============
def generateOutputName():

    system_identifier = None
    base_output_name = f"{CWD}{TIMESTAMP}_AuditLog"
    output_name_to_ret = base_output_name

    #---------
    # Define the paths of uid's for the system
    #   Will check several files to have several options
    #---------
    # Define machine-id file path 
    machine_id_path = Path("/etc/machine-id")

    # Define product_uuid path
    product_uuid_path = Path("/sys/class/dmi/id/product_uuid")

    #---------
    # Determine which uid to use
    #---------
    uid_path = None
    if machine_id_path.is_file():
        logging.debug(f"Using file path for machine id [ {machine_id_path} ]")
        uid_path = machine_id_path

    elif product_uuid_path.is_file():
        logging.debug(f"Using file path for product uuid [ {product_uuid_path} ]")
        uid_path = product_uuid_path 

    #---------
    # Determine Unique Identifier if available
    #---------
    if uid_path is not None:
        try:
            with open(uid_path, "r") as file:
                system_identifier = file.read()
            logging.debug(f"\tDetermining System UID [ {system_identifier} ]")
        except FileNotFoundError:
            logging.exception(f"Error: File was not found [ {uid_path} ]")
        except PermissionError:
            logging.exception(f"Error: Permissions error for uid file [ {uid_path} ]")
        except Exception as e:
            logging.exception(f"Unexpected error while reading uid file [ {e} ]")

        # Add the UID to the base name
        outputname_to_ret = f"{outputname_to_ret}_{system_identifier}.json"

    # If path check failed or opening/reading file failed, proceed without the information
    else:
        outputname_to_ret = f"{outputname_to_ret}.json"

    return outputname_to_ret 

#--------------
# Auto-Update Checks - unattended upgrades status
#   updateSummaryCounts(passed_passes, passed_failures, passed_warnings, passed_total_checks):
#--------------
def autoUpdateUpgrades():
    logging.debug(f"\tWorking on [ Auto-Updates : Unattended Upgrades ]")

    # Use apt-config
    # 1 = enabled | 0 = disabled
    unattend_upgrades_check = subprocess.check_output(["apt-config", "shell", "unattended", "APT::Periodic::Unattended-Upgrade"], universal_newlines=True)

    # Enabled
    if 'unattended="1"' in unattend_upgrades_check:

        # Put into dictionary
        unattended_upgrades_dict = {
            "expected" : "enabled",
            "actual" : "enabled",
            "status" : "PASS"
        }

        # Update globals
        updateSummaryCounts(1, 0, 0, 1)

        return unattended_upgrades_dict 

    # Disabled
    else:
        # Put into dictionary
        unattended_upgrades_dict = {
            "expected" : "enabled",
            "actual" : "disabled",
            "status" : "FAIL"
        }

        # Update globals
        updateSummaryCounts(0, 1, 0, 1)

        return unattended_upgrades_dict 


#--------------
# Auto-Update Checks - package manager configured
#--------------
def autoUpdatePackageManager():
    logging.debug(f"\tWorking on [ Auto-Updates : Package Manager ]")

    # Check for package manager
    #   Debian/Ubuntu  : apt
    #   Fedora//CentOS : dnf
    #   Arch Linux     : pacman
    #   openSUSE Linux : zypper
    #   Alpine Linux   : apk
    pkg_mngrs = ['apt', 'dnf', 'yum', 'pacman', 'zypper', 'apk']

    pkg_mgr = None
    # Iterate through possible
    for mngr in pkg_mngrs:
        # If package manager is installed, will evaluate true
        if shutil.which(mngr):
            pkg_mgr = mngr

    # Determine expected package manager
    if OS_UD:
        expected_mngr = "apt"
    elif OS_RC:
        expected_mngr = "dnf"

    # Check for success
    if expected_mngr == pkg_mgr:
        overall_status == "PASS"

        # Update globals
        updateSummaryCounts(1, 0, 0, 1)

    else:
        overall_status == "FAIL"

        # Update globals
        updateSummaryCounts(0, 1, 0, 1)

    pkg_mngr_dict = {
        "expected" : expected_mngr,
        "actual" : pkg_mgr,
        "status" : overall_status,
    }

    return pkg_mngr_dict 

#--------------
# Auto-Update Checks - update timer status
#--------------
def autoUpdateTimerStatus():
    logging.debug(f"\tWorking on [ Auto-Updates : Update Timer Status ]")

    # Determine timer
    if OS_UD:
        sys_timer = "apt-daily.timer"
    elif OS_RC:
        sys_timer = "dnf-makecache.timer"

    # Check if timer is active
    if subprocess.check_output(["systemctl", "is-active", sys_timer], text=True).strip():
        timer_activity = "active"
        status = "PASSED"

        # Update globals
        updateSummaryCounts(1, 0, 0, 1)

    else:
        timer_activity = "inactive"
        status = "FAILED"

        # Update globals
        updateSummaryCounts(0, 1, 0, 1)

    # Create dictionary
    timer_status_dict = {
        "expected" : "active",
        "actual" : timer_activity,
        "status" : status
    }

    return timer_status_dict


#--------------
# Credential Checks - minimum password length 
#   /etc/security/pwquality.conf : 'minlen' (12 or 14)
#--------------
def credentialMinLen():
    logging.debug(f"\tWorking on [ Credentials : Minimum Password Length ]")

    cred_path = "/etc/security/pwquality"
    search_minlen = "minlen"

    # Overall check values
    minlen_expected = 12
    minlen_actual = 0
    minlen_status = "FAIL"

    # First ingest the file
    min_len_ingest = isolateStringInFile(cred_path, [search_minlen])

    # Check to make sure setting was found
    if min_len_ingest is not None:

        # Isolate the minimum length
        minlen_actual = int(min_len_ingest.replace("minlen = ","")

        # Make sure min length is greater than 12
        if minlen_actual >= 12:
            # Adjust status to PASS
            minlen_status = "PASS"

            # Update globals
            updateSummaryCounts(1, 0, 0, 1)

        # IF the minlen is less than 12, mark check as fail in globals
        else:
            # Update globals
            updateSummaryCounts(0, 1, 0, 1)

    else:
        logging.debug(f"Failed to find '{search_minlen}' in file [ {cred_path} ]")

        # Update globals
        updateSummaryCounts(0, 1, 0, 1)


    # Create dictionary
    credential_len_dict = {
        "expected" : minlen_expected,
        "actual" : minlen_actual,
        "status" : minlen_status
    }

    return credential_len_dict 

#--------------
# Credential Checks - password complexity
#   /etc/security/pwquality.conf : 'dcredit', 'ucredit', 'lcredit', 'ocredit' (set to -1 = at least 1)
#   /etc/security/pwquality.conf : minlower, minupper, mindigit, minspecial
#--------------
def credentialComplexity():
    logging.debug(f"\tWorking on [ Credentials : Password Complexity ]")

    credential_complexity_dict = {}

    # Define path to conf file
    complexity_path = "/etc/security/pwquality"
    search_strings = ["minclass","mindigit","minlower","minupper","minspecial"]

    # Search the file for the strings
    found_strings = isolateStringInFile(complexity_path, search_strings)

    # Make sure results were actually returned
    if len(found_strings) != len(search_strings):
        logging.error(f"Failed to isolate password complexity configurations [ {complexity_path} ]")

        # Update globals
        updateSummaryCounts(0, len(search_strings), 0, len(search_strings))

    # Process the returned strings
    comp_minclasses = int(found_strings[0].replace("minclass = ",""))
    comp_mindigit = int(found_strings[1].replace("mindigit = ",""))
    comp_minlower = int(found_strings[2].replace("minlower = ",""))
    comp_minupper = int(found_strings[3].replace("minupper = ",""))
    comp_minspecial = int(found_strings[4].replace("minspecial = ",""))

    ######
    # Determine status
    ######
    #-----
    # Character class
    #-----
    expected_class = 4
    status_class = "FAILED"
    if comp_minclass == expected_class:
        status_class = "PASSED"
        # Update globals
        updateSummaryCounts(1, 0, 0, 1)
    else:
        # Update globals
        updateSummaryCounts(0, 1, 0, 1)

    complex_class_dict = {
        "expected" : expected_class,
        "actual" : comp_minclasses,
        "status" : status_class
    }

    #-----
    # Digit Required 
    #-----
    expected_digit = 1
    status_digit = "FAILED"
    if comp_mindigit == expected_digit:
        status_digit = "PASSED"
        # Update globals
        updateSummaryCounts(1, 0, 0, 1)
    else:
        # Update globals
        updateSummaryCounts(0, 1, 0, 1)

    complex_digit_dict = {
        "expected" : expected_digit,
        "actual" : comp_mindigit,
        "status" : status_digit
    }

    #-----
    # Lowercase Letter Required 
    #-----
    expected_lower = 1
    status_lower = "FAILED"
    if comp_minlower == expected_lower:
        status_lower = "PASSED"
        # Update globals
        updateSummaryCounts(1, 0, 0, 1)
    else:
        # Update globals
        updateSummaryCounts(0, 1, 0, 1)

    complex_lower_dict = {
        "expected" : expected_lower,
        "actual" : comp_minlower,
        "status" : status_lower
    }

    #-----
    # Uppercase Letter Required 
    #-----
    expected_upper = 1
    status_upper = "FAILED"
    if comp_minupper == expected_upper:
        status_upper = "PASSED"
        # Update globals
        updateSummaryCounts(1, 0, 0, 1)
    else:
        # Update globals
        updateSummaryCounts(0, 1, 0, 1)

    complex_upper_dict = {
        "expected" : expected_upper,
        "actual" : comp_minupper,
        "status" : status_upper
    }

    #-----
    # Special Letter Required 
    #-----
    expected_special = 1
    status_special = "FAILED"
    if comp_minspecial == expected_special:
        status_special = "PASSED"
        # Update globals
        updateSummaryCounts(1, 0, 0, 1)
    else:
        # Update globals
        updateSummaryCounts(0, 1, 0, 1)

    complex_special_dict = {
        "expected" : expected_special,
        "actual" : comp_minspecial,
        "status" : status_special
    }

    ######
    # Create final dictionary
    ######
    credential_complexity_dict['required_character_classes'] = complex_class_dict 
    credential_complexity_dict['required_character_digit'] = complex_digit_dict 
    credential_complexity_dict['required_character_lowercase'] = complex_lower_dict 
    credential_complexity_dict['required_character_uppercase'] = complex_upper_dict 
    credential_complexity_dict['required_character_special'] = complex_special_dict 

    return credential_complexity_dict 

#--------------
# Credential Checks - password expiration
#   /etc/login.defs : 'PASS_MAX_DAYS'
#--------------
def credentialExpiration():
    logging.debug(f"\tWorking on [ Credentials : Expiration ]")

    # Define path to conf file
    expire_path = "/etc/login.defts"
    search_strings = ["PASS_MAX_DAYS"]

    # Search the file for the string
    found_strings = isolateStringInFile(expire_path, search_strings)

    # Ensure something was returned
    if len(search_strings) != len(found_strings)
        logging.error(f"Failed to isolate password expiration configurations [ {expire_path} ]")

        # Update globals
        updateSummaryCounts(0, len(search_strings), 0, len(search_strings))

    # Determine check status
    expected_expire = 90
    actual_expire = int(found_strings[0].replace("PASS_MAX_DAYS","").strip())
    status_expire = "PASSED"

    # The the actual setting is less than 90 days = failure
    if actual_expire < expected_expire:
        status_expire = "FAILED"
        # Update globals
        updateSummaryCounts(0, 1, 0, 1)
    else:
        updateSummaryCounts(1, 0, 0, 1)

    # Put it all together in a dictionary
    password_expiration_dict = {
        "expected" : expected_expire,
        "actual" : actual_expire,
        "status" : status_expire
    }

    return password_expiration_dict 

#--------------
# Credential Checks - password reuse prevention
#   /etc/security/pwhistory.conf : 'remember' = 5
#--------------
def credentialReusePrevention():
    logging.debug(f"\tWorking on [ Credentials : Password Reuse Prevention ]")

#--------------
# Credential Checks - account lockout policy
#   /etc/pam.d/common-auth OR /etc/pam.d/system_auth
#   'deny=5' e.g. locks account after 5 failed attempts
#   'unlock_time=600' e.g. locks account for 10 mins
#--------------
def credentialLockout():
    logging.debug(f"\tWorking on [ Credentials : Account Lockout Policy ]")

#--------------
# Logging Checks - rsyslog enabled / active
#--------------
def loggingRsyslogActive():
    logging.debug(f"\tWorking on [ Logging Checks : rsyslog status ]")

#--------------
# Logging Checks - auditd installed/running
#--------------
def loggingAuditdActive():
    logging.debug(f"\tWorking on [ Logging Checks : auditd status ]")

#--------------
# Logging Checks - journald persistent logging
#--------------
def loggingJournaldPersistence():
    logging.debug(f"\tWorking on [ Logging Checks : journald persistence ]")

#--------------
# Logging Checks - log rotation configured
#--------------
def loggingLogRotation():
    logging.debug(f"\tWorking on [ Logging Checks : log rotation ]")

#--------------
# Firewall Checks - UFW / Firewalld Enabled
#--------------
def firewallEnabled():
    logging.debug(f"\tWorking on [ Firewall : Service Enabled ]")

#--------------
# Firewall Checks - Firewall active
#--------------
def firewallActive():
    logging.debug(f"\tWorking on [ Firewall : Service Active ]")

#--------------
# Firewall Checks - deny-by-default
#--------------
def firewallDenyDefault():
    logging.debug(f"\tWorking on [ Firewall : Deny-by-default ]")

#--------------
# Firewall Checks - Unnecessary Open Ports
#--------------
def firewallUnnecessaryOpenPorts():
    logging.debug(f"\tWorking on [ Firewall : Unnecessary Open Ports ]")

#--------------
# Firewall Checks - SSH Restrictions
#--------------
def firewallSSHRestricted():
    logging.debug(f"\tWorking on [ Firewall : SSH Restrictions ]")

#--------------
# Kernel Checks - Disable IP-Forwarding
#--------------
def kernelDisableIPForward():
    logging.debug(f"\tWorking on [ Kernel : IP-Forwarding Disabled ]")

#--------------
# Kernel Checks - Ignore ICMP Redirects
#--------------
def kernelDisableICMPRedirect():
    logging.debug(f"\tWorking on [ Kernel : ICMP Redirects Disabled]")

#--------------
# Kernel Checks - Enable SYN Cookies
#--------------
def kernelEnableSYNCookies():
    logging.debug(f"\tWorking on [ Kernel : SYN Cookies Enabled]")

#--------------
# Kernel Checks - Disable Source Routing
#--------------
def kernelDisableSourceRouting():
    logging.debug(f"\tWorking on [ Kernel : Source Routing Disabled ]")

#--------------
# Service Checks - Unnecessary Services
#--------------
def loggingUnnecessaryServices():
    logging.debug(f"\tWorking on [ Logging : Unnecessary Services ]")

#--------------
# Service Checks - Exposed Network Services
#--------------
def loggingExposedNetworkServices():
    logging.debug(f"\tWorking on [ Logging : Exposed Network Services ]")

#--------------
# Service Checks - Legacy Protocols
#--------------
def loggingLegacyProtocols():
    logging.debug(f"\tWorking on [ Logging : Legacy Protocols ]")

#--------------
# Permissions Checks - Legacy Protocols
#--------------
def permissionsWorldWritableFiles():
    logging.debug(f"\tWorking on [ Permissions : Legacy Protocols ]")

#--------------
# Permissions Checks - Improper SSH Key Permission
#--------------
def permissionsImproperSSHKeyPermissions():
    logging.debug(f"\tWorking on [ Permissions : Legacy Protocols ]")

#--------------
# Permissions Checks - SUID / SGID Binaries
#--------------
def permissionsSUIDSGIDBinaries():
    logging.debug(f"\tWorking on [ Permissions : SUID / SGID Binaries]")

#--------------
# Permissions Checks - Sensitive File Ownership
#--------------
def permissionsSensitiveFileOwnership():
    logging.debug(f"\tWorking on [ Permissions : Sensitive File Ownership ]")

#--------------
# Remote / SSH Checks - root login disabled
#--------------
def remoteRootLoginDisabled(config_str):
    logging.debug(f"\tWorking on [ Remote : Root Loging Disabled ]")

#--------------
# Remote / SSH Checks - password authentication disabled
#--------------
def remotePasswordAuthDisabled():
    logging.debug(f"\tWorking on [ Remote : Password Authentication Disabled ]")

#--------------
# Remote / SSH Checks - ssh protocol version
#--------------
def remoteProtocolVersion():
    logging.debug(f"\tWorking on [ Remote : SSH Protocol Version]")

#--------------
# Remote / SSH Checks - empty passwords disabled
#--------------
def remoteEmptyPasswordsDisabled():
    logging.debug(f"\tWorking on [ Remote : Empty Password Disabled ]")

#--------------
# Remote / SSH Checks - max authorization attempts
#--------------
def remoteMaxAuthAttempts():
    logging.debug(f"\tWorking on [ Remote : Max Authorization Attempts Configured ]")

#--------------
# Remote / SSH Checks - idle timeout configured
#--------------
def remoteIdleTimeoutConfigured():
    logging.debug(f"\tWorking on [ Remote : Idle Timeout Configured ]")

#--------------
# Remote / SSH Checks - Strong Cipher
#--------------
def remoteStrongCipher():
    logging.debug(f"\tWorking on [ Remote : Cipher Checks ]")

#--------------
# Service Minimalization - unnecessary services
#--------------
def servicesUnnecessary():
    logging.debug(f"\tWorking on [ Service Minimization : Unnecessary Services ]")

#--------------
# Service Minimalization - exposed network services
#--------------
def servicesExposedNetworkServices():
    logging.debug(f"\tWorking on [ Service Minimization : Exposed Network Services ]")

#--------------
# Service Minimalization - legacy protocols
#   (telnet, ftp, rsh, cups, avahi, unused web servers)
#--------------
def servicesLegacyProtocols():
    logging.debug(f"\tWorking on [ Service Minimization : Legacy Protocols ]")

#--------------
# User-Privileges - users with UID 0
#--------------
def userPrivUIDUsers():
    logging.debug(f"\tWorking on [ User Privileges : Users with UID 0 ]")

#--------------
# User-Privileges - sudo group memberships
#--------------
def userPrivSUDOGroupMemberships():
    logging.debug(f"\tWorking on [ User Privileges : SUDO Group Membership]")

#--------------
# User-Privileges - inactive accounts
#--------------
def userPrivInactiveAccounts():
    logging.debug(f"\tWorking on [ User Privileges : Inactive Accounts ]")

#--------------
# User-Privileges - empty passwords
#--------------
def userPrivEmptyPasswords():
    logging.debug(f"\tWorking on [ User Privileges : Empty Passwords ]")

#--------------
# User-Privileges - unauthorized users
#--------------
def userPrivUnauthorizedUsers():
    logging.debug(f"\tWorking on [ User Privileges : Unauthorized Users ]")

#--------------
# User-Privileges - service accounts with shells
#--------------
def userPrivServiceAccountShell():
    logging.debug(f"\tWorking on [ User Privileges : Service Accounts with Shells ]")

#==========================================
# Auto-Update Checks
#   - Unattended upgrades enabled
#   - Package manager configured
#   - Update timer status (active)
#==========================================
def checkAutoUpdates():
    logging.info(f"Current Check : [ Auto-Updates ]")

    # Create dictionary
    auto_update_dict = {}

    #---
    # Run the checks
    #---
    u_up_dict = autoUpdateUpgrades()
    pkt_man_dict = autoUpdatePackageManager()
    u_timer_dict = autoUpdateTimerStatus()

    #---
    # Update dictionary
    #---
    auto_update_dict['unattended_upgrades'] = u_up_dict
    auto_update_dict['packet_manager_configured'] = pkt_man_dict
    auto_update_dict['update_timer_status'] = u_timer_dict

    # Quick check
    logging.debug(f"Number of Checks : {TOTAL_CHECKS} | Checks Passed : {PASSES} | Checks Failed : {FAILURES} | Warnings : {WARNINGS}")

    # return check dictionary
    return auto_update_dict

#==========================================
# Credential / Password Policy Checks
#   - Minimum password length
#   - Password complexity requirements
#   - Password expiration
#   - Password reuse prevention
#   - Account lockout policy
#==========================================
def checkCredentialPassword():
    logging.info(f"Current Check : [ Credentials / Password ]")

    credential_checks_dict = {}

    #---
    # Run the checks
    #---
    min_pass_len_dict = credentialMinLen()
    pass_complexity_dict = credentialComplexity()
    pass_expire_dict = credentialExpiration()
    pass_reuse_prevent_dict = credentialReusePrevention()
    account_lockout_dict = credentialLockout()

    #---
    # Update dictionary
    #---
    credential_checks_dict['minimum_password_length'] = min_pass_len_dict
    credential_checks_dict['password_complexity'] = pass_complexity_dict 
    credential_checks_dict['password_expiration'] = pass_expire_dict 
    credential_checks_dict['password_reuse_prevention'] = pass_reuse_prevent_dict 
    credential_checks_dict['account_lockout_policy'] = account_lockout_dict 

    # Quick check
    logging.debug(f"Number of Checks : {TOTAL_CHECKS} | Checks Passed : {PASSES} | Checks Failed : {FAILURES} | Warnings : {WARNINGS}")

    return credential_checks_dict

#==========================================
# Logging Checks
#   - rsyslog enabled
#   - auditd installed/running
#   - journald persistent logging
#   - log rotation configured
#==========================================
def checkLogging():
    logging.info(f"Current Check : [ Logging Configuration ]")

    # Create dictionary
    logging_checks_dict = {}

    #---
    # Run the checks
    #---
    rs_checks = loggingRsyslogActive()
    auditd_checks = loggingAuditdActive()
    journald_persistence = loggingJournaldPersistence()
    log_rotation_config = loggingLogRotation()

    #---
    # Update dictionary
    #---
    logging_checks_dict['rsyslog_active'] = rs_checks
    logging_checks_dict['auditd_active'] = auditd_checks
    logging_checks_dict['journald_persistence'] = journald_persistence
    logging_checks_dict['log_rotation'] = log_rotation_config

    # Quick check
    logging.debug(f"Number of Checks : {TOTAL_CHECKS} | Checks Passed : {PASSES} | Checks Failed : {FAILURES} | Warnings : {WARNINGS}")

    return logging_checks_dict


#==========================================
# Firewall Checks
#   - UFW / firewalld Enabled
#   - Firewall active
#   - Deny-by-default
#   - Unnecessary ports open
#   - SSH Restricted
#==========================================
def checkFirewall():
    logging.info(f"Current Check : [ Firewall ]")

    # Create dictionary
    firewall_checks_dict = {}

    #---
    # Run the checks
    #---
    enabled_check = firewallEnabled()
    active_check = firewallActive()
    deny_check = firewallDenyDefault()
    unnecessary_check = firewallUnnecessaryOpenPorts()
    restricted_ssh_check = firewallSSHRestricted()

    #---
    # Update dictionary
    #---
    firewall_checks_dict['firewall_enabled'] = enabled_check
    firewall_checks_dict['firewall_active'] = active_check
    firewall_checks_dict['deny_by_default'] = deny_check
    firewall_checks_dict['exposed_ports'] = unnecessary_check
    firewall_checks_dict['restricted_ssh'] = restricted_ssh_check

    # Quick check
    logging.debug(f"Number of Checks : {TOTAL_CHECKS} | Checks Passed : {PASSES} | Checks Failed : {FAILURES} | Warnings : {WARNINGS}")

    return logging_checks_dict

#==========================================
# Kernel / System Checks
#   - Disable IP-Forwarding
#   - Ignore ICMP redirects
#   - Enable SYN cookies
#   - Disable source routing
#==========================================
def checkKernelSystem():
    logging.info(f"Current Check : [ Kernel / System ]")

    # Create dictionary
    kernel_checks_dict = {}

    #---
    # Run the checks
    #---
    ip_forward_checks = kernelDisableIPForward()
    ignore_icmp_checks = kernelDisableICMPRedirect()
    enable_syn_checks = kernelEnableSYNCookies()
    source_routing_checks = kernelDisableSourceRouting()

    #---
    # Update dictionary
    #---
    kernel_checks_dict['ip_forwarding'] = ip_forward_checks
    kernel_checks_dict['icmp_redirects'] = ignore_icmp_checks
    kernel_checks_dict['tcp_syn_cookies'] = enable_syn_checks
    kernel_checks_dict['source_routing'] = source_routing_checks

    # Quick check
    logging.debug(f"Number of Checks : {TOTAL_CHECKS} | Checks Passed : {PASSES} | Checks Failed : {FAILURES} | Warnings : {WARNINGS}")

    return kernel_checks_dict

#==========================================
# Permissions (File) Checks
#   - World-writable files
#   - Improper SSH key permissions
#   - SUID / SGID binaries
#   - Sensitive file ownership
#==========================================
def checkPermissions():
    logging.info(f"Current Check : [ Permissions (File) ]")

    # Create dictionary
    file_perm_checks_dict = {}

    #---
    # Run the checks
    #---
    world_write_checks = permissionsWorldWritableFiles()
    ssh_perm_checks = permissionsImproperSSHKeyPermissions()
    suid_bin_checks = permissionsSUIDSGIDBinaries()
    file_ownership_checks = permissionsSensitiveFileOwnership()

    #---
    # Update dictionary
    #---
    file_perm_checks_dict['world_writable_files'] = world_write_checks 
    file_perm_checks_dict['ssh_permissions'] = ssh_perm_checks 
    file_perm_checks_dict['suid_binaries'] = suid_bin_checks 
    file_perm_checks_dict['sensitive_file_ownerships'] = file_ownership_checks 
    
    # Quick check
    logging.debug(f"Number of Checks : {TOTAL_CHECKS} | Checks Passed : {PASSES} | Checks Failed : {FAILURES} | Warnings : {WARNINGS}")

    return file_perm_checks_dict

#==========================================
# Remote / SSH Checks
#   - Root login disabled
#   - Password authentication disabled
#   - SSH protocol version
#   - Empty passwords disabled
#   - Max authorization attempts securely configured
#   - Idle timeout configured
#   - Strong ciphers / MACs
#==========================================
def checkRemote():
    logging.info(f"Current Check : [ Permissions (File) ]")

    # Create dictionary
    remote_ssh_checks_dict = {}

    # Will check /etc/ssh/sshd_config
    ssh_config_file_path = "/etc/ssh/sshd_config"
    ssh_config = ingestFileToString(ssh_config_file_path)

    # Make sure ssh_config is not empty
    if ssh_config is None:
        logging.error(f"Failed to ingest ssh configuration [ {ssh_config_file_path} ]")
        return remote_ssh_checks_dict 

    #---
    # Run the checks
    #---
    root_login = remoteRootLoginDisabled(ssh_config)
    pass_auth_disabled = remotePasswordAuthDisabled(ssh_config)
    ssh_protocol_version = remoteProtocolVersion(ssh_config)
    empty_password_disabled = remoteEmptyPasswordsDisabled(ssh_config)
    max_auth_attempts = remoteMaxAuthAttempts(ssh_config)
    idle_timeout_configured = remoteIdleTimeoutConfigured(ssh_config)
    strong_cipher = remoteStrongCipher(ssh_config)

    #---
    # Update dictionary
    #---
    remote_ssh_checks_dict['root_login_disabled'] = root_login
    remote_ssh_checks_dict['password_authentication_disabled'] = pass_auth_disabled
    remote_ssh_checks_dict['ssh_protocol_version'] = ssh_protocol_version
    remote_ssh_checks_dict['empty_passwords_disabled'] = empty_password_disabled
    remote_ssh_checks_dict['max_authorization_attempts'] = max_auth_attempts
    remote_ssh_checks_dict['idle_timeout_configured'] = idle_timeout_configured
    remote_ssh_checks_dict['strong_cipher'] = strong_cipher
    
    # Quick check
    logging.debug(f"Number of Checks : {TOTAL_CHECKS} | Checks Passed : {PASSES} | Checks Failed : {FAILURES} | Warnings : {WARNINGS}")

    return remote_ssh_checks_dict 

#==========================================
# Service Minimization Check
#   - Unnecessary services
#   - Exposed network services
#   - Legaacy protocols (telnet, ftp, rsh, cups, avahi, unused web servers)
#==========================================
def checkServices():
    logging.info(f"Current Check : [ Services ]")

    # Create dictionary
    service_minimization_checks_dict = {}

    #---
    # Run the checks
    #---
    unneccessary_serv_checks = servicesUnnecessary()
    exposed_net_serv_checks servicesExposedNetworkServices()
    legacy_protocol_checks = servicesLegacyProtocols()

    #---
    # Update dictionary
    #---
    service_minimization_checks_dict['unnecessary_services'] = unneccessary_serv_checks
    service_minimization_checks_dict['exposed_network_services'] = exposed_net_serv_checks
    service_minimization_checks_dict['legacy_protocols'] = legacy_protocol_checks

    # Quick check
    logging.debug(f"Number of Checks : {TOTAL_CHECKS} | Checks Passed : {PASSES} | Checks Failed : {FAILURES} | Warnings : {WARNINGS}")

    return service_minimization_checks_dict 

#==========================================
# User-privileges Check
#   - Users with UID 0
#   - SUDO group membership
#   - Inactive accounts
#   - Empty passwords
#   - Unauthorized users
#   - Service accounts with shells
#==========================================
def checkUserPrivileges():
    logging.info(f"Current Check : [ User-Privileges ]")

    # Create dictionary
    user_priv_checks_dict = {}

    #---
    # Run the checks
    #---
    uid_0_checks = userPrivUIDUsers()
    sudo_users_checks = userPrivSUDOGroupMemberships()
    inactive_accounts_checks = userPrivInactiveAccounts()
    empty_passwords_checks = userPrivEmptyPasswords()
    unauthorized_user_checks = userPrivUnauthorizedUsers()
    service_accounts_checks = userPrivServiceAccountShell()

    #---
    # Update dictionary
    #---
    user_priv_checks_dict['uid_0_accounts'] = uid_0_checks
    user_priv_checks_dict['sudo_users'] = sudo_users_checks
    user_priv_checks_dict['inactive_accounts'] = inactive_accounts_checks
    user_priv_checks_dict['empty_passwords'] = empty_passwords_checks
    user_priv_checks_dict['unauthorized_users'] = unauthorized_user_checks
    user_priv_checks_dict['service_accounts_with_shells'] = service_accounts_checks

    # Quick check
    logging.debug(f"Number of Checks : {TOTAL_CHECKS} | Checks Passed : {PASSES} | Checks Failed : {FAILURES} | Warnings : {WARNINGS}")

    return user_priv_checks_dict 

#==============
# 'Quick' Output for Audit Checks that can be performed
#   Will also indicate if particular checks can be remediated
#==============
def outputAuditCheckInformation():
    logging.info(f"Audit Check Information")

#==============
# Wrapper for Audit Checks
#   Checks return dictionaries / arrays of dictionaries
#==============
def auditChecksFullWrapper():
    logging.info(f"Begining Audit Checks")

    overall_scan_info = {}

    #------------
    # Create initial json string
    #------------
    # Audit Test Information
    #audit_metadata_dict = metaDataGenerator()
    overall_scan_info["scan_metadata"] = metaDataGenerator()

    #------------
    # Audit Checks
    #------------
    audit_checks = {}

    # Auto-Update Checks
    auto_update_dict = checkAutoUpdates()
    audit_checks["auto_update_checks"] = auto_update_dict 

    # Credential / Password Policy Checks
    cred_dict = checkCredentialPassword()
    audit_checks["credential_policy_checks"] = cred_dict 

    # Firewall Checks
    firewall_dict = checkFirewall()
    audit_checks["firewall_checks"] = firewall_dict 

    # Kernel / System Checks
    kernel_dict = checkKernelSystem()
    audit_checks["kernel_checks"] = kernel_dict 

    # Logging Checks
    logging_dict = checkLogging()
    audit_checks["logging_configuration_checks"] = logging_dict 

    # Permissions (File) Checks
    file_perm_dict = checkPermissions()
    audit_checks["file_permission_checks"] = file_perm_dict 

    # Remote / SSH Checks
    ssh_checks_dict = checkRemote()
    audit_checks["ssh_remote_checks"] = ssh_checks_dict 

    # Services Check
    service_dict = checkServices()
    audit_checks["service_configuration_checks"] = service_dict 

    # User-privileges Check
    upriv_dict = checkUserPrivileges()
    audit_checks["user_privileges_check"] = upriv_dict 

    #------------
    # Create audit dictionary and translate to json
    #------------
    # Provide summary (total checks, total pass, total fail, total warning?)
    overall_scann_info["audit_checks"] = audit_checks

    # Create the JSON output
    audit_ouput_json = json.dumps(overall_scan_info, indent=4, sort_keys=True)

    # Quick print check
    print(audit_ouput_json)

#==============
# Wrapper for Remediation Checks and Steps
#==============
def remediateWrapper():
    logging.info(f"Begining Remediation")

#==============
# Determine Linux OS
#==============
def getOSType():

    logging.info(f"Determining operating system type")

    os_ud_ret = False
    os_rc_ret = False

    #---------
    # Define the paths of os-release for the system
    #---------
    os_release_path = "/etc/os-release"
    os_contents = ingestFileToString(os_release_path)

    #---------
    # Determine Unique Identifier if available
    #---------
    # Make sure variable is populated
    #   Determine OS 
    if os_contents is not None:
        if "ID=ubuntu" in os_contents or "ID=debian" in os_contents:
            os_ud_ret = True
            logging.debug("\tOperating System determined to be Ubuntu/Debian")
        elif "ID=rhel" in os_contents or "ID=centos" in os_contents or "ID=rocky" in os_contents or "ID=almalinux" in os_contents:
            os_rc_ret = True
            logging.debug("\tOperating System determined to be RHEL/CentOS")

    return os_ud_ret, os_rc_ret

#==============
# Function for file ingest into str
#==============
def ingestFileToString(passed_path):

    logging.debug(f"\tPreparing for file ingest [ {passed_path} ]")

    ret_str = None

    #---------
    # Define the paths of os-release for the system
    #---------
    file_path = Path(passed_path)

    #---------
    # Ingest File
    #---------
    try:
        # Open the file and consume contents
        with open(file_path, "r") as ifile:
            ret_str = file.read()
            logging.debug(f"\tReading in file [ {file_path} ]")
    except FileNotFoundError:
        logging.exception(f"Error: File was not found [ {file_path} ]")
    except PermissionError:
        logging.exception(f"Error: Permissions error for file [ {file_path} ]")
    except Exception as e:
        logging.exception(f"Unexpected error while reading uid file [ {e} ]")

    # Return the string
    return ret_str

#==============
# 'Ingest' file to search for and isolate particular line / string
#==============
def isolateStringInFile(passed_path, search_array):

    logging.debug(f"\tPreparing for string isolation in file[ {passed_path} ]")

    ret_strings = []

    #---------
    # Define the paths of os-release for the system
    #---------
    file_path = Path(passed_path)

    #---------
    # Ingest File Line by line and isolate search_string if present
    #---------
    try:
        # Open the file 
        with open(file_path, "r") as ifile:
            # Iterate line-by-line
            for line in ifile:
                # Iterate through search_array
                for search_str in search_array:
                    # Check each line for the search string
                    if search_string in line:
                        ret_str.append( line.strip())
                        break

            logging.debug(f"\tSearching file for search string [ {search_string} ]")

    except FileNotFoundError:
        logging.exception(f"Error: File was not found [ {file_path} ]")
    except PermissionError:
        logging.exception(f"Error: Permissions error for file [ {file_path} ]")
    except Exception as e:
        logging.exception(f"Unexpected error while reading uid file [ {e} ]")

    # Return the string
    return ret_strings

#==============
# Grabs system information for the test 
#==============
def metaDataGenerator()
    logging.info(f"Gathering test case metadata")

    #---------
    # Gather Info
    #---------
    # Hostname
    hostname_info = platform.node()

    # OS
    os_info = platform.platform()

    # Kernel Version
    kernel_info = platform.version()

    # Scan Timestamp
    scan_time = TIMESTAMP

    #---------
    # Create dictionary
    #---------
    metadata = {
        "hostname" : hostname_info,
        "os" : os_info,
        "kernel_version" : kernel_info,
        "scan_timestamp" : scan_time
    }

    return metadata

#==============
# Function to quickly update the running global totals
#==============
def updateSummaryCounts(passed_passes, passed_failures, passed_warnings, passed_total_checks):

    # Adjust globals
    PASSES += passed_passes
    FAILURES += passed_failures
    WARNINGS += passed_warnings
    TOTAL_CHECKS += passed_total_checks
    
    #logging.debug(f"Number of Checks : {TOTAL_CHECKS} | Checks Passed : {PASSES} | Checks Failed : {FAILURES} | Warnings : {WARNINGS}")

#==========================================================================
# Main
#==========================================================================
def main():
    
    # Grab the script version
    script_version = sys.argv[0]

    # Initial Help Menu Output
    parser = argparse.ArgumentParser(
        prog = script_version,
        description = "Linux System Secure Configuration Evaluation and Remediation",
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog = textwrap.dedent('''
            Examples:
                Show options associated with db_regen
                    => python3 %s db_regen -h
                
                Show options associated with db_regen
                    => python3 %s db_regen -h
            '''%(script_version, script_version, script_version)))

    # Start considering logging
    global verbose_logging
    verbose_logging = False

    # Set some 'global' options
    global_parser = argparse.ArgumentParser(add_help=False)
    global_parser.add_argument("-v", "--verbose", action="store_true", help="Logging output will be verbose")
    global_parser.add_argument('-p', '--print', action='store_true', help='Print results to STDOUT only')
    global_parser.add_argument('-o', '--output', help='Specify audit report path/name')

    #========================
    # Required Args - Mutually Exclusive
    #   info [Available Checks Information]
    #   full [Run full audit suite]
    #   subset [Run selected audit checks]
    #========================
    subparsers = parser.add_subparsers(title='Linux System Hardening Options', dest='subcommand')

    #-----------
    # info
    #-----------
    info_parser = subparsers.add_parser('info', help='Output to STDOUT Audit Checks Available', parents=[global_parser])

    #-----------
    # audit
    #-----------
    audit_parser = subparsers.add_parser('audit', help = 'Strictly Audit the System Configurations', parents=[global_parser])

    # Can select full OR subset
    audit_type = audit_parser.add_mutually_exclusive_group(required=True)

    # Full Audit
    audit_type.add_argument('-f', '--full', action='store_true', help='Complete all audit checks')

    # Audit Checks Info
    audit_info = """\
    Audit Checks Available:
        a : auto-updates enabled
        c : credential / password policy
        f : firewall
        k : kernel / system
        l : logging / auditing
        p : permissions (files)
        r : remote / SSH
        s : services
        u : user-privileges"""

    # Subset audit
    audit_type.add_argument(
        '-s', 
        '--subset', 
        type=str.lower,
        #metavar='CHECKS',
        choices=['a', 'c', 'f', 'k', 'l', 'p', 'r', 's', 'u'], 
        # allow multiple options to be selected
        nargs='+', 
        help=textwrap.dedent(audit_info)
    )

    #-----------
    # remediation
    #-----------
    remediation_parser = subparsers.add_parser('remediation', help = 'Test a specific test file between specified clients', parents=[global_parser])

    # Can select full OR subset
    remediation_type = remediation_parser.add_mutually_exclusive_group(required=True)

    # Full Audit
    remediation_type.add_argument('-f', '--full', action='store_true', help='Complete all audit checks')

    # Audit Remediation Info
    remediation_info = """\
    Remediation Options Available:
        a : auto-updates enabled
        c : credential / password policy
        k : kernel / system
        r : remote / SSH
        s : services
        u : user-privileges"""

    # Subset remediation
    audit_type.add_argument(
        '-s', 
        '--subset', 
        type=str.lower,
        #metavar='CHECKS',
        choices=['a', 'c', 'k', 'r', 's', 'u'], 
        # allow multiple options to be selected
        nargs='+', 
        help=textwrap.dedent(audit_info)
    )

    #========================
    # Process Passed Arguments
    #========================
    args = parser.parse_args()

    # Set logging levels
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format='%(asctime)s \t[[ %(levelname)s ]] \t%(message)s',datefmt='%Y-%m-%d %I:%M:%S %p')
    else:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s \t[[ %(levelname)s ]] \t%(message)s',datefmt='%Y-%m-%d %I:%M:%S %p')

    # Handle some global variables
    global OUTPUT
    global PRINT

    # Determine if output to STDOUT is defined
    PRINT = True if args.print else false

    # Determine output name (if defined or generated(
    OUTPUT = args.output if args.output else generateOutputName()

    #-------------
    # Run enviroment checks
    #   - Run as priv user
    #   - RHEL/CentOS vs Ubuntu/Debian
    #-------------
    # if script is running via sudo / root, euid == 0
    if os.geteuid() != 0:
        logging.error("Please run script with sudo")
        sys.exit()

    # Determine OS (UD = ubuntu/debian; RC = RHEL/CentOS)
    global OS_UD
    global OS_RC
    OS_UD, OS_RC = getOSType()

    #-------------
    # Info
    #-------------
    if args.subcommand == 'info':
        #outputAuditCheckInformation()
        print(f"PRINTING INFO")

    #-------------
    # Audit Only
    #-------------
    elif args.subcommand == 'audit':
        auditChecksFullWrapper()
        print(f"AUDIT TREE")

    #-------------
    # Audit and Remediation
    #-------------
    elif args.subcommand == 'remediate':
        print(f"REMEDIATION TREE")

if __name__="__main__":
    main()








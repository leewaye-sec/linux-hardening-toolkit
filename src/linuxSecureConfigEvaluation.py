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
        updateSummaryCounts(1, 0, 0, 1):

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
        updateSummaryCounts(0, 1, 0, 1):

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
        updateSummaryCounts(1, 0, 0, 1):

    else:
        overall_status == "FAIL"

        # Update globals
        updateSummaryCounts(0, 1, 0, 1):

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
        updateSummaryCounts(1, 0, 0, 1):

    else:
        timer_activity = "inactive"
        status = "FAILED"

        # Update globals
        updateSummaryCounts(0, 1, 0, 1):

    # Create dictionary
    timer_status_dict = {
        "expected" : "active",
        "actual" : timer_activity,
        "status" : status
    }

    return timer_status_dict


#--------------
# Credential Checks - minimum password length 
#--------------
def credentialMinLen():
    logging.debug(f"\tWorking on [ Credentials : Minimum Password Length ]")

#--------------
# Credential Checks - password complexity
#--------------
def credentialComplexity():
    logging.debug(f"\tWorking on [ Credentials : Password Complexity ]")

#--------------
# Credential Checks - password expiration
#--------------
def credentialExpiration():
    logging.debug(f"\tWorking on [ Credentials : Expiration ]")

#--------------
# Credential Checks - password reuse prevention
#--------------
def credentialReusePrevention():
    logging.debug(f"\tWorking on [ Credentials : Password Reuse Prevention ]")

#--------------
# Credential Checks - account lockout policy
#--------------
def credentialMinLen():
    logging.debug(f"\tWorking on [ Credentials : Account Lockout Policy ]")

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
# Logging Checks - Unnecessary Services
#--------------
def loggingUnnecessaryServices():
    logging.debug(f"\tWorking on [ Logging : Unnecessary Services ]")

#--------------
# Logging Checks - Exposed Network Services
#--------------
def loggingExposedNetworkServices():
    logging.debug(f"\tWorking on [ Logging : Exposed Network Services ]")

#--------------
# Logging Checks - Legacy Protocols
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

    auto_update_dict = {}

    #---
    # Run the checks
    #---
    u_up_dict = autoUpdateUpgrades()
    pkt_man_dict = autoUpdatePackageManager()
    u_timer_dict = autoUpdateTimerStatus()

    #---
    # Create dictionary
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

#==========================================
# Logging Checks
#   - Unnecessary services
#   - Exposed network services
#   - Legacy protocols
#==========================================
def checkLogging():
    logging.info(f"Current Check : [ Logging Configuration ]")

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

#==========================================
# Kernel / System Checks
#   - Disable IP-Forwarding
#   - Ignore ICMP redirects
#   - Enable SYN cookies
#   - Disable source routing
#==========================================
def checkKernelSystem():
    logging.info(f"Current Check : [ Kernel / System ]")

#==========================================
# Permissions (File) Checks
#   - World-writable files
#   - Improper SSH key permissions
#   - SUID / SGID binaries
#   - Sensitive file ownership
#==========================================
def checkPermissions():
    logging.info(f"Current Check : [ Permissions (File) ]")

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

    # Will check /etc/ssh/sshd_config
    ssh_config_file_path = "/etc/ssh/sshd_config"
    ssh_config = ingestFileToString(ssh_config_file_path)

    # Start json string
    ssh_temp = "remote_ssh_checks: {\n"

    # Make sure the file was ingested
    if ssh_config is not None:
        ssh_temp += remoteRootLoginDisabled(ssh_config)
        ssh_temp += remotePasswordAuthDisabled(ssh_config)
        ssh_temp += remoteProtocolVersion(ssh_config)
        ssh_temp += remoteEmptyPasswordsDisabled(ssh_config)
        ssh_temp += remoteMaxAuthAttempts(ssh_config)
        ssh_temp += remoteIdleTimeoutConfigured(ssh_config)
        ssh_temp += remoteStrongCipher(ssh_config)

    else:
        # If nothing in the file, mark the test as failed

    # Close the json entry
    ssh_temp += "},"

    return ssh

#==========================================
# Service Minimization Check
#   - Unnecessary services
#   - Exposed network services
#   - Legaacy protocols (telnet, ftp, rsh, cups, avahi, unused web servers)
#==========================================
def checkServices():
    logging.info(f"Current Check : [ Services ]")

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
    audit_checks["firewall_checks"] = firewall_dict 

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








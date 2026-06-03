#!/usr/local/bin/python3
#==========================================================================
#
#           File : linuxSecureconfigEvaluation.py
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
import textwrap
from datetime import datetime

import services

#--------------------
# Global Variables
#--------------------
# Timestamp
global TIMESTAMP
timestamp_dirty = datetime.now()
TIMESTAMP = timestamp_dirty.strftime("%Y%m%d_%H%M%S")

# Path Definitions
global CWD
CWD = os.path.abspath(os.getcwd())
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
                system_identifier = file.read().strip()
            #logging.debug(f"\tDetermining System UID [ {system_identifier} ]")
        except FileNotFoundError:
            logging.exception(f"Error: File was not found [ {uid_path} ]")
        except PermissionError:
            logging.exception(f"Error: Permissions error for uid file [ {uid_path} ]")
        except Exception as e:
            logging.exception(f"Unexpected error [ {e} ]")

        # Add the UID to the base name
        output_name_to_ret = f"{output_name_to_ret}_{system_identifier}.json"

    # If path check failed or opening/reading file failed, proceed without the information
    else:
        output_name_to_ret = f"{output_name_to_ret}.json"

    basename= os.path.basename(output_name_to_ret)
    logging.debug(f"\t\tOutput File Name Determined [ {basename} ]")

    return output_name_to_ret 

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
        logging.debug("\t\tPASSED")

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
        logging.debug("\t\tFAILED")

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
    overall_status = "FAIL"
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
        logging.debug("\t\tPASSED")

    else:
        overall_status == "FAIL"

        # Update globals
        updateSummaryCounts(0, 1, 0, 1)
        logging.debug("\t\tFAILED")

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
        status = "PASS"

        # Update globals
        updateSummaryCounts(1, 0, 0, 1)
        logging.debug("\t\tPASSED")

    else:
        timer_activity = "inactive"
        status = "FAILED"

        # Update globals
        updateSummaryCounts(0, 1, 0, 1)
        logging.debug("\t\tFAILED")

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

    cred_path = "/etc/security/pwquality.conf"
    search_minlen = ["minlen"]

    # First ingest the file
    min_len_ingest = isolateStringInFile(cred_path, search_minlen)

    # Check to make sure setting was found
    if len(min_len_ingest) != len(search_minlen):
        logging.debug(f"Failed to find '{search_minlen}' in file [ {cred_path} ]")
        # Update globals
        updateSummaryCounts(0, 1, 0, 1)
        failure_dict = {
            "audit_check" : "Credential Minimum Length",
            "status" : "FAIL" 
        }
        return failure_dict

    min_len = min_len_ingest[0]

    # Overall check values
    minlen_expected_int = 12
    minlen_actual_int = 0

    minlen_expected = "enabled/configured"
    minlen_actual = "enabled/configured"
    minlen_status = "PASS"

    # First check: if it's commented out
    if min_len.startswith('#'):
        # Update globals
        updateSummaryCounts(0, 1, 0, 1)
        actual_class = "disabled/not configured"
        status_class = "FAIL"

    else:
        minlen_actual_int = int(min_len.replace("minlen = ","").strip())

        if minlen_actual_int <= minlen_expected_int:
            # Update globals
            updateSummaryCounts(1, 0, 0, 1)
        else:
            # Update globals
            updateSummaryCounts(0, 1, 0, 1)
            actual_len = "enabled/not configured"
            status_len = "FAIL"


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
    complexity_path = "/etc/security/pwquality.conf"
    search_strings = ["minclass","dcredit","lcredit","ucredit","ocredit"]

    # Search the file for the strings
    found_strings = isolateStringInFile(complexity_path, search_strings)

    # Make sure results were actually returned
    if len(found_strings) != len(search_strings):
        logging.error(f"\t\tFailed to isolate password complexity configurations [ {complexity_path} ]")

        # Update globals
        updateSummaryCounts(0, len(search_strings), 0, len(search_strings))
        failure_dict = {
            "audit_check" : "Credential Complexity",
            "status" : "FAIL" 
        }
        return failure_dict

    # Process the returned strings
    comp_minclasses = found_strings[0]
    comp_mindigit = found_strings[1]
    comp_minlower = found_strings[2]
    comp_minupper = found_strings[3]
    comp_minspecial = found_strings[4]

    ######
    # Determine status
    ######
    #-----
    # Character class
    #-----
    min_class = -1 
    expected_class = "enabled/configured"
    actual_class = "enabled/configured"
    status_class = "PASS"

    # First check: if it's commented out
    if comp_minclasses.startswith('#'):
        # Update globals
        updateSummaryCounts(0, 1, 0, 1)
        actual_class = "disabled/not configured"
        status_class = "FAIL"

    else:
        setting_class = int(comp_minclasses.replace("minclass = ","").strip())

        if setting_class <= min_class:
            # Update globals
            updateSummaryCounts(1, 0, 0, 1)
        else:
            # Update globals
            updateSummaryCounts(0, 1, 0, 1)
            actual_class = "enabled/not configured"
            status_class = "FAIL"

    complex_class_dict = {
        "expected" : expected_class,
        "actual" : actual_class,
        "status" : status_class
    }

    #-----
    # Digit Required 
    #-----
    min_digit = -1

    expected_digit = "enabled/configured"
    actual_digit = "enabled/configured"
    status_digit = "PASS"

    # First check: if it's commented out
    if comp_mindigit.startswith('#'):
        # Update globals
        updateSummaryCounts(0, 1, 0, 1)
        actual_digit = "disabled/not configured"
        status_digit = "FAIL"

    else:
        setting_digit = int(comp_mindigit.replace("dcredit = ","").strip())

        if setting_digit <= min_digit:
            # Update globals
            updateSummaryCounts(1, 0, 0, 1)
        else:
            # Update globals
            updateSummaryCounts(0, 1, 0, 1)
            actual_digit = "enabled/not configured"
            status_digit = "FAIL"

    complex_digit_dict = {
        "expected" : expected_digit,
        "actual" : actual_digit,
        "status" : status_digit
    }

    #-----
    # Lowercase Letter Required 
    #-----
    min_lower = -1 
    expected_lower = "enabled/configured"
    actual_lower = "enabled/configured"
    status_lower = "PASS"

    # First check: if it's commented out
    if comp_minlower.startswith('#'):
        # Update globals
        updateSummaryCounts(0, 1, 0, 1)
        actual_lower = "disabled/not configured"
        status_lower = "FAIL"

    else:
        setting_lower = int(comp_minlower.replace("lcredit = ","").strip())

        if setting_lower <= min_lower:
            # Update globals
            updateSummaryCounts(1, 0, 0, 1)
        else:
            # Update globals
            updateSummaryCounts(0, 1, 0, 1)
            actual_lower = "enabled/not configured"
            status_lower = "FAIL"

    complex_lower_dict = {
        "expected" : expected_lower,
        "actual" : actual_lower,
        "status" : status_lower
    }

    #-----
    # Uppercase Letter Required 
    #-----
    min_upper = -1 
    expected_upper = "enabled/configured"
    actual_upper = "enabled/configured"
    status_upper = "PASS"

    # First check: if it's commented out
    if comp_minupper.startswith('#'):
        # Update globals
        updateSummaryCounts(0, 1, 0, 1)
        actual_upper = "disabled/not configured"
        status_upper = "FAIL"

    else:
        setting_upper = int(comp_minupper.replace("ucredit = ","").strip())

        if setting_upper <= min_upper:
            # Update globals
            updateSummaryCounts(1, 0, 0, 1)
        else:
            # Update globals
            updateSummaryCounts(0, 1, 0, 1)
            actual_upper = "enabled/not configured"
            status_upper = "FAIL"

    complex_upper_dict = {
        "expected" : expected_upper,
        "actual" : actual_upper,
        "status" : status_upper
    }

    #-----
    # Special Letter Required 
    #-----
    min_special = -1 
    expected_special = "enabled/configured"
    actual_special = "enabled/configured"
    status_special = "PASS"

    # First check: if it's commented out
    if comp_minspecial.startswith('#'):
        # Update globals
        updateSummaryCounts(0, 1, 0, 1)
        actual_special = "disabled/not configured"
        status_special = "FAIL"

    else:
        setting_special = int(comp_minspecial.replace("ocredit = ","").strip())

        if setting_special <= min_special:
            # Update globals
            updateSummaryCounts(1, 0, 0, 1)
        else:
            # Update globals
            updateSummaryCounts(0, 1, 0, 1)
            actual_special = "enabled/not configured"
            status_special = "FAIL"

    complex_special_dict = {
        "expected" : expected_special,
        "actual" : actual_special,
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

    #------------------
    # Define paths / strings / variables
    #------------------
    expire_path = "/etc/login.defs"
    search_pass_max = "^#? ?PASS_MAX_DAYS"
    search_cmd = ['grep', '-E', search_pass_max, expire_path]

    expected_expire = "enabled/configured"
    actual_expire = "enabled/configured"
    status_expire = "PASS"
    expire_days = 90

    #------------------
    # Search the file for the string
    #------------------
    try:
        passmax_output = subprocess.run(search_cmd, capture_output=True, text=True)
        
        # Make sure string exists in file
        if passmax_output.returncode == 0:
            # Clean up the value
            passmax_grep = passmax_output.stdout.strip() 

            # Determine if it is commented out or not (enabled vs. disabled)
            if passmax_grep.startswith('#'):
                updateSummaryCounts(0, 1, 0, 1)
                actual_expire = "disabled/not configured"
                status_expire = "FAIL" 

            else:
                # Implies setting is 'enabled'
                passmax = int(passmax_grep.replace("PASS_MAX_DAYS","").strip())

                # Check configuration
                if passmax > expire_days:
                    updateSummaryCounts(0, 1, 0, 1)
                    actual_expire = f"enabled/bad configuration [ {passmax} > {expire_days} ]"
                    status_expire = "FAIL" 
                else:
                    updateSummaryCounts(1, 0, 0, 1)
                    actual_expire = f"enabled/configured"
                    status_expire = "PASS" 

        else:
            updateSummaryCounts(0, 1, 0, 1)
            actual_expire = "disabled/not configured"
            status_expire = "FAIL" 

    except Exception as e:
        logging.exception(f"Unexpected error [ {e} ]")

    # Put it all together in a dictionary
    password_expiration_dict = {
        "expected" : expected_expire,
        "actual" : actual_expire,
        "status" : status_expire
    }

    return password_expiration_dict 

#--------------
# Credential Checks - password reuse prevention
#   Ubuntu : /etc/pam.d/common-password
#   RHEL   : /etc/pam.d/system-auth
#--------------
def credentialReusePrevention():
    logging.debug(f"\tWorking on [ Credentials : Password Reuse Prevention ]")

    #------------------
    # Define paths / strings / variables
    #------------------
    # Set path based on operating system
    if OS_UD:
        reuse_path = "/etc/pam.d/common-password"
    elif OS_RC:
        reuse_path = "/etc/pam.d/system-auth"

    search_reuse = "^#?remember="
    search_cmd = ['grep', '-E', search_reuse, reuse_path]

    expected_reuse = "enabled/configured"
    actual_reuse = "enabled/configured"
    status_reuse = "PASS"
    reuse_num = 5

    #------------------
    # Run the search
    #------------------
    try:
        reuse_output = subprocess.run(search_cmd, capture_output=True, text=True)
        
        # Make sure string exists in file
        if reuse_output.returncode == 0:
            # Clean up the value
            reuse_grep = passmax_output.stdout.strip() 

            # Determine if it is commented out or not (enabled vs. disabled)
            if reuse_grep.startswith('#'):
                updateSummaryCounts(0, 1, 0, 1)
                actual_reuse = "disabled/not configured"
                status_reuse = "FAIL" 
            else:
                # Implies setting is 'enabled'
                reuse = int(reuse_grep.replace("remember=","").strip())

                # Check configuration
                if reuse > reuse_num:
                    updateSummaryCounts(0, 1, 0, 1)
                    actual_reuse = f"enabled/bad configuration [ {reuse} > {reuse_num} ]"
                    status_reuse = "FAIL" 
                else:
                    updateSummaryCounts(1, 0, 0, 1)
                    actual_reuse = f"enabled/configured"
                    status_reuse = "PASS" 

        else:
            updateSummaryCounts(0, 1, 0, 1)
            actual_reuse = "disabled/not configured"
            status_reuse = "FAIL"

    except Exception as e:
        logging.exception(f"Unexpected error [ {e} ]")

    # Put it all together in a dictionary
    password_reuse_dict = {
        "expected" : expected_reuse,
        "actual" : actual_reuse,
        "status" : status_reuse
    }

    return password_reuse_dict 
    

#--------------
# Credential Checks - account lockout policy
#   path : /etc/security/faillock.conf
#   'deny=5' e.g. locks account after 5 failed attempts
#   'unlock_time=600' e.g. locks account for 10 mins
#--------------
def credentialLockout():
    logging.debug(f"\tWorking on [ Credentials : Account Lockout Policy ]")

    #------------------
    # Define paths / strings / variables
    #------------------
    deny_path = "/etc/security/faillock.conf"
    search_deny = "^#? ?deny"
    search_cmd = ['grep', '-E', search_deny, deny_path]

    expected_lockout = "enabled/configured"
    actual_lockout = "enabled/configured"
    status_lockout = "PASS"
    lockout_num = 3

    #------------------
    # Search for string(s) in specified file
    #------------------
    try:
        lockout_output = subprocess.run(search_cmd, capture_output=True, text=True)
        
        # Make sure string exists in file
        if lockout_output.returncode == 0:
            # Clean up the value
            lockout_grep = lockout_output.stdout.strip() 

            # Determine if it is commented out or not (enabled vs. disabled)
            if lockout_grep.startswith('#'):
                updateSummaryCounts(0, 1, 0, 1)
                actual_expire = "disabled/not configured"
                status_expire = "FAIL" 

            else:
                # Implies setting is 'enabled'
                lockout = int(lockout_grep.replace("deny =","").strip())

                # Check configuration
                if lockout > lockout_num:
                    updateSummaryCounts(0, 1, 0, 1)
                    actual_expire = f"enabled/bad configuration [ {lockout} > {lockout_num} ]"
                    status_expire = "FAIL" 
                else:
                    updateSummaryCounts(1, 0, 0, 1)
                    actual_expire = f"enabled/configured"
                    status_expire = "PASS" 

        else:
            updateSummaryCounts(0, 1, 0, 1)
            actual_expire = "disabled/not configured"
            status_expire = "FAIL" 

    except Exception as e:
        logging.exception(f"Unexpected error [ {e} ]")

    # Put it all together in a dictionary
    password_lockout_dict = {
        "expected" : expected_lockout,
        "actual" : actual_lockout,
        "status" : status_lockout
    }

    return password_lockout_dict 
    

#--------------
# Check service status via systemctl status
#--------------
def serviceEnabledActiveChecker(service):

    logging.debug(f"\t\tCheck Service [ {service} ]")
    
    #=============
    # Define variables
    #=============
    cmd_str = ['systemctl', 'status', service]

    # Enabled Variables
    enabled_expected = "enabled"
    enabled_actual = "enabled"
    enabled_status = "PASS"
    
    # Active Variables
    active_expected = "active"
    active_actual = "active"
    active_status = "PASS"
    
    #=============
    # Run Check
    #=============
    try:
        service_output = subprocess.run(cmd_str, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        #if 'enabled' in enabled_output:
        if service_output.returncode == 4:
            logging.debug(f"\t\tProcess {service} : Not Active / Not Enabled")
            # Update global
            updateSummaryCounts(0, 2, 0, 2)
            enabled_actual = "disabled"
            enabled_status = "FAIL"
            active_actual = "disabled"
            active_status = "FAIL"

        elif service_output.returncode >= 1 and service_output.returncode <= 3:
            logging.debug(f"\t\tProcess {service} : Active / Not Enabled")
            # Update global
            updateSummaryCounts(0, 1, 0, 1)
            active_actual = "disabled"
            active_status = "FAIL"

        elif service_output.returncode == 0:
            # Update global
            logging.debug(f"\t\tProcess {service} : Active / Enabled")
            updateSummaryCounts(1, 0, 0, 1)

    except Exception as e:
        logging.exception(f"Failed to determine if [ {service} ] is enabled and active [ {e} ]")
        # Update global
        updateSummaryCounts(0, 1, 0, 1)
        enabled_actual = "disabled"
        enabled_status = "FAIL"
        active_actual = "disabled"
        active_status = "FAIL"

    # Create dictionaries
    service_dict = {
        "service_enabled" : {
            "expected" : enabled_expected,
            "actual" : enabled_actual,
            "status" : enabled_status
        },
        "service_active" : {
            "expected" : active_expected,
            "actual" : active_actual,
            "status" : active_status
        }
    }

    return service_dict


#--------------
# Logging Checks - rsyslog enabled / active
#--------------
def loggingRsyslogActive():
    logging.debug(f"\tWorking on [ Logging Checks : rsyslog status ]")

    # Check if the service is enabled / active
    rsyslog_dict = serviceEnabledActiveChecker("rsyslog")
    return rsyslog_dict
    

#--------------
# Logging Checks - auditd installed/running
#--------------
def loggingAuditdActive():
    logging.debug(f"\tWorking on [ Logging Checks : auditd status ]")

    # Check if the service is enabled / active
    auditd_dict = serviceEnabledActiveChecker("auditd")
    return auditd_dict

#--------------
# Logging Checks - journald persistent logging
#--------------
def loggingJournaldPersistence():
    logging.debug(f"\tWorking on [ Logging Checks : journald persistence ]")

    # Check if the service is enabled / active
    journald_dict = serviceEnabledActiveChecker("journald")
    return journald_dict

#--------------
# Logging Checks - log rotation configured
#--------------
def loggingLogRotation():
    logging.debug(f"\tWorking on [ Logging Checks : log rotation ]")

    #===========
    # Check if the service is enabled / active
    #===========
    logrotate_ea_dict = serviceEnabledActiveChecker("logrotate.timer")

    #===========
    # Check for log rotation configuration
    #===========
    log_cmd_str = ['systemctl', 'list-timers', 'logrotate.timer']

    config_expected = "Timers configured"
    config_actual = "Timers configured"
    config_status = "PASS"

    # If the service is enabled and active, check for configuration
    if logrotate_ea_dict['service_enabled']['status'] == "PASS" and logrotate_ea_dict['service_active']['status'] == "PASS":
        # Check for timers
        try:
            logrot_output = subprocess.check_output(log_cmd_str, text=True)

            # Determine if timers are present
            if "0 timers listed." in logrot_output:
                # Update global
                updateSummaryCounts(0, 1, 0, 1)
                config_actual = "0 timers configured"
                config_status = "FAIL"
            else:
                # Update global
                updateSummaryCounts(1, 0, 0, 1)

        except Exception as e:
            logging.exception(f"Failed to determine if [ logrotate.timer ] is configured [ {e} ]")
            # Update global
            updateSummaryCounts(0, 1, 0, 1)
            config_actual = "0 timers configured"
            config_status = "FAIL"
    else:
        config_actual = "Timers configured"
        config_status = "PASS"

    # Create config dict
    log_config_dict = {
        "expected" : config_expected,
        "actual" : config_actual,
        "status" : config_status
    }

    #===========
    # Create final dict 
    #===========
    logrotate_dict = {
        "service" : 'logrotate.service',
        "enabled" : logrotate_ea_dict['service_enabled'],
        "active" : logrotate_ea_dict['service_active'],
        "configured" : log_config_dict
    }

    return logrotate_dict

#--------------
# Firewall Checks - UFW / Firewalld Enabled
#--------------
def firewallEnabled():
    logging.debug(f"\tWorking on [ Firewall : Service Enabled ]")

    #=====
    # Determine command string
    #=====
    firewall_service = None
    # ufw
    if OS_UD:
        cmd_str = ["systemctl", "status", "ufw"]
        firewall_service = "ufw"
    # firewalld
    elif OS_RC:
        cmd_str = ["systemctl", "status", "firewalld"]
        firewall_service = "firewalld"

    #=====
    # Determine if service is enabled
    #=====
    firewall_expected = "enabled"
    firewall_actual = "disabled"
    firewall_status = "FAIL"

    try:
        enabled_output = subprocess.run(cmd_str, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        #if 'enabled' in enabled_output:
        if enabled_output.returncode == 0:
            # Update global
            updateSummaryCounts(1, 0, 0, 1)
            firewall_actual = "enabled"
            firewall_status = "PASS"
        elif enabled_output.returncode >= 1 or enabled_output.returncode <= 4:
            logging.error(f"\t\tFirewall service [ {firewall_service} ] not installed on system")
            # Update global
            updateSummaryCounts(0, 1, 0, 1)
            firewall_actual = "disabled"
            firewall_status = "FAIL"

    except Exception as e:
        logging.exception(f"Failed to determine if [ {firewall_service} ] is enabled [ {e} ]")
        # Update global
        updateSummaryCounts(0, 1, 0, 1)
        firewall_actual = "disabled"
        firewall_status = "FAIL"
    
    # Create dictionary for return
    firewall_enabled = {
        'expected' : firewall_expected,
        'actual' : firewall_actual,
        'status' : firewall_status
    }

    return firewall_enabled

#--------------
# Firewall Checks - Firewall active
#--------------
def firewallActive(fw_enabled):
    logging.debug(f"\tWorking on [ Firewall : Service Active ]")

    #=====
    # If service isn't installed, skip the check
    #=====
    if not fw_enabled:
        firewall_fail = {
            'expected' : "active",
            'actual' : "not installed -- inactive",
            'status' : "FAIL"
        }

        # Update global
        updateSummaryCounts(0, 1, 0, 1)
        return firewall_fail

    #=====
    # Determine checks for OS
    #=====
    firewall_service = None
    # ufw
    if OS_UD:
        cmd_str = ["ufw", "status"]
        output_search_str = "Status: active"
        firewall_service = "ufw"

    # firewalld
    elif OS_RC:
        cmd_str = ["firewall-cmd", "--state"]
        output_search_str = "running"
        firewall_service = "firewalld"

    #=====
    # Determine if service is active
    #=====
    firewall_expected = "active"
    firewall_actual = "active"
    firewall_status = "PASS"
    try:
        active_output = subprocess.check_output(cmd_str, text=True)

        if output_search_str in active_output:
            # Update global
            updateSummaryCounts(1, 0, 0, 1)
        else:
            # Update global
            updateSummaryCounts(0, 1, 0, 1)
            firewall_actual = "inactive"
            firewall_status = "FAIL"

    except Exception as e:
        logging.exception(f"Failed to determine if [ {firewall_service} ] is active [ {e} ]")
        # Update global
        updateSummaryCounts(0, 1, 0, 1)
        firewall_actual = "inactive"
        firewall_status = "FAIL"
    
    # Create dictionary for return
    firewall_active = {
        'expected' : firewall_expected,
        'actual' : firewall_actual,
        'status' : firewall_status
    }

    return firewall_active
    

#--------------
# Firewall Checks - deny-by-default
#--------------
def firewallDenyDefault(fw_enabled):
    logging.debug(f"\tWorking on [ Firewall : Deny-by-default ]")

    #=====
    # If service isn't installed, skip the check
    #=====
    if not fw_enabled:
        firewall_fail = {
            'expected' : "deny-by-default",
            'actual' : "not installed -- no default present",
            'status' : "FAIL"
        }

        # Update global
        updateSummaryCounts(0, 1, 0, 1)
        return firewall_fail

    #=====
    # Process based on OS
    #=====
    firewall_service = None
    deny_expected = "deny-by-default"
    deny_actual = "deny-by-default"
    deny_status = "PASS"

    # ufw
    if OS_UD:
        cmd_str = ["ufw", "status", "verbose"]
        search_str = "Default: deny (incoming)"

        try:
            deny_output = subprocess.check_output(cmd_str, text=True)

            if search_str in deny_output:
                # Update global
                updateSummaryCounts(1, 0, 0, 1)
            else:
                # Update global
                updateSummaryCounts(0, 1, 0, 1)
                deny_actual = "allow-by-default"
                deny_status = "FAIL"

        except:
            logging.error("UFW not active")
            # Update global
            updateSummaryCounts(0, 1, 0, 1)
            deny_actual = "Unable to determine"
            deny_status = "FAIL"

    # firewalld
    elif OS_RC:

        zone_cmd_str = ['firewall-cmd', '--get-default-zone']
        search_strs = ['DROP', 'REJECT', '%%REJECT%%']
        try:
            # Get the default zone name
            zone = subprocess.check_output(zone_cmd_str, text=True).strip()

            cmd_str = ['firewall-cmd', f'--zone={zone}', '--get-target']

            # Check the 'target' of that default zone
            target = subprocess.check_output(cmd_str, text=True).strip()

            if target in search_strs:
                # Update global
                updateSummaryCounts(1, 0, 0, 1)
            else:
                updateSummaryCounts(0, 1, 0, 1)
                deny_actual = "allow-by-default"
                deny_status = "FAIL"

        except:
            logging.error("firewalld not active")
            # Update global
            updateSummaryCounts(0, 1, 0, 1)
            deny_actual = "Unable to determine"
            deny_status = "FAIL"

    firewall_deny_dict = {
        "expected" : deny_expected,
        "actual" : deny_actual,
        "status" : deny_status
    }

    return firewall_deny_dict

#--------------
# Firewall Checks - Provide nested dictionaries of some ports and their associated info
#--------------
def firewallGatherListeningPorts():
    logging.debug(f"\tRetrieving current system ports")

    port_cmd = ["ss", "-tulpn"]
    system_ports = []

    # Run the command, gather output, process
    try:
        ports_output = subprocess.run(port_cmd, capture_output=True, text=True)
        output_split = ports_output.stdout.strip().split('\n')

        # Process the output into dictionaries (skip the table header line)
        for line in output_split[1:]:

            # Skip lines that are not state LISTEN
            if "LISTEN" not in line:
                continue

            columns = line.split()
            # Make sure we have the proper number of columns (at least 6)
            if len(columns) >= 6:
                system_ports.append({
                    "Netid": columns[0],
                    "State": columns[1],
                    "Recv-Q": columns[2],
                    "Send-Q": columns[3],
                    "Local Address:Port": columns[4],
                    "Peer Address:Port": columns[5],
                    "Process": columns[6] if len(columns) > 6 else ""
                })

    except Exception as e:

        logging.exception(f"Failed to retreive system ports [ {e} ]")

    return system_ports

#--------------
# Firewall Checks - Unnecessary Open Ports
#--------------
def firewallListeningPorts(fw_enabled):
    logging.debug(f"\tWorking on [ Firewall : Unnecessary Open Ports ]")

    #=====
    # If service isn't installed, skip the check
    #=====
    if not fw_enabled:
        firewall_fail = {
            'expected' : "port checks available",
            'actual' : "not installed -- no port checks",
            'status' : "FAIL"
        }

        # Update global
        updateSummaryCounts(0, 1, 0, 1)
        return firewall_fail

    #=============
    # Prepare for checks
    #=============
    # Returns port dictionary with nested dictionaries keyed by port number
    ports_info = services.standardPortDefinitionInformation()
    listening_ports = firewallGatherListeningPorts()

    isolated_ports = []
    #=============
    # Prepare for checks
    #=============
    for lport in listening_ports:
        # Split to have local address and port
        laddr_split = lport['Local Address:Port'].split(':')
        isolated_ports.append(laddr_split[1])

    # Remove duplicates if present
    isolated_unique_ports = list(set(isolated_ports))

    #=============
    # Create information
    #=============
    # Grab the info from ports_info
    #   If not in ports_info, fill out as unknown
    # Define unknown ports for 
    ports_report = {}
    ports_report['status'] = "INFO"
    # Iterate the port numbers present on system
    for port in isolated_unique_ports:

        # If port has information, grab it
        if port in ports_info:
            specific_port_dict = ports_info[port]
            ports_report[port] = specific_port_dict 

        # No info on the listed port
        else:
            temp_unk = {
                "classification": "unknown",
                "port" : port,
                "service" : "unkown",
                "protocol": "unkown",
                "service": "unkown",
                "risk_level": "WARN",
                "recommended": "unknown",
                "recommendation": "Investigate unidentified listening service"
            }

            ports_report[port] = temp_unk 

    # Return dictionary
    return ports_report

#--------------
# Checks if SSH is listening / reachable
#--------------
def firewallSSHRest_listening():
    logging.debug(f"\t\tChecking Firewall SSH Restrictions [ Listening ]")

    # Grab all listening ports, then search for the ssh port
    listening_ports = firewallGatherListeningPorts()

    ssh_listen_dict = {}

    ssh_interface = None
    ssh_port = "22"

    ssh_status = "FAIL"

    # Search listening ports for ssh (22)
    for lport in listening_ports:
        # If it isn't ssh, skip
        if f":{ssh_port}" in lport['Local Address:Port']:
            ssh_interface = lport['Local Address:Port'].split(':')[0]
            ssh_status = "PASS"
            break
    
    # Populate dictionary to return
    ssh_listen_dict['status'] = ssh_status
    ssh_listen_dict['interface'] = ssh_interface
    ssh_listen_dict['status'] = ssh_port

    return ssh_listen_dict

#--------------
# Checks if ssh is restricted to specific IPs
#--------------
def firewallSSHRest_sourceRestrictions():
    logging.debug(f"\t\tChecking Firewall SSH Restrictions [ Restricted Source ]")

    #========
    # Determine OS for check parameters
    #========
    # ufw
    if OS_UD:
        cmd_str = ["ufw", "status"]
    # firewalld
    elif OS_RC:
        cmd_str = ["firewall-cmd", "--list-all"]

    #========
    # Search for port 22 / ssh rules
    #========
    ssh_source_expected = "Restricted SSH source rules"
    ssh_source_actual = "Restricted SSH source rules"
    ssh_source_status = "PASS"

    try:
        source_output = subprocess.check_output(cmd_str, text=True)

        # Check the output for 22/ssh rules
        source_output_lines = source_output.split('\n')

        restricted_rules = []
        unrestricted_rules = []

        # Check for ssh rules in firewalls
        for line in source_output_lines:
            # Isolate checks to ssh lines
            if '22' in line or 'ssh' in line or 'SSH' in line:
                # Check if ssh rule has any limits
                if 'ALLOW' in line or "accept" in line:
                    if 'Anywhere' in line or '0.0.0.0/0' in line or '0.0.0.0' in line:
                        unrestricted_rules.append(line)
                    else:
                        restricted_rules.append(line)

        # See if any unrestricted rules exist
        if len(unrestricted_rules) == 0:
            # Update global
            updateSummaryCounts(1, 0, 0, 1)
        else:
            # Update global
            updateSummaryCounts(0, 1, 0, 1)
            ssh_source_actual = "Unrestricted SSH source rules"
            ssh_source_status = "FAIL"

    except Exception as e:
        logging.exception(f"Failed to determine [ Restricted SSH Source Rules ] [ {e} ]")
        # Update global
        updateSummaryCounts(0, 1, 0, 1)
        ssh_source_actual = "Unrestricted SSH source rules"
        ssh_source_status = "FAIL"

    #========
    # Create dictionary to return
    #========
    ssh_restricted_source_dict = {
        "expected" : ssh_source_expected,
        "actual" : ssh_source_actual,
        "status" : ssh_source_status
    }

    return ssh_restricted_source_dict

#--------------
# Checks if firewall is rate limiting ssh
#--------------
def firewallSSHRest_rateLimiting():
    logging.debug(f"\t\tChecking Firewall SSH Restrictions [ Rate Limiting ]")

    #========
    # Determine OS for check parameters
    #========
    # ufw
    if OS_UD:
        cmd_str = ["ufw", "status"]
    # firewalld
    elif OS_RC:
        #cmd_str = ["firewall-cmd", "--list-all"]
        cmd_str = ["firewall-cmd", "--list-rich-rules"]

    #========
    # Search for port 22 / ssh rules
    #========
    ssh_rate_expected = "SSH rate limited"
    ssh_rate_actual = "SSH rate limited"
    ssh_rate_status = "PASS"

    try:
        rate_output = subprocess.check_output(cmd_str, text=True)

        # Check the output for 22/ssh rules
        rate_output_lines = rate_output.split('\n')

        # Check for ssh limits in firewall rules
        for line in rate_output_lines:
            # Isolate checks to ssh lines
            if '22' in line or 'ssh' in line or 'SSH' in line:
                # Check if ssh rule has any limits
                if 'LIMIT' in line or "limit" in line:
                    # Update global
                    updateSummaryCounts(1, 0, 0, 1)
                else:
                    # Update global
                    updateSummaryCounts(0, 1, 0, 1)
                    ssh_rate_actual = "NO SSH rate limit"
                    ssh_rate_status = "FAIL"

    except Exception as e:
        logging.exception(f"Failed to determine [ SSH Rate Limited ] [ {e} ]")
        # Update global
        updateSummaryCounts(0, 1, 0, 1)
        ssh_rate_actual = "NO SSH rate limit"
        ssh_rate_status = "FAIL"

    #========
    # Create dictionary
    #========
    ssh_rate_limit_dict = {
        "expected" : ssh_rate_expected,
        "actual" : ssh_rate_actual,
        "status" : ssh_rate_status
    }

    return ssh_rate_limit_dict 

#--------------
# Checks for limits on IPv6 for ssh
#--------------
def firewallSSHRest_ipv6Restrictions():
    logging.debug(f"\t\tChecking Firewall SSH Restrictions [ IPv6 Restrictions ]")

    #========
    # Determine OS for check parameters
    #========
    # ufw
    if OS_UD:
        cmd_str = ["ufw", "status"]
    # firewalld
    elif OS_RC:
        #cmd_str = ["firewall-cmd", "--list-all"]
        cmd_str = ["firewall-cmd", "--list-rich-rules"]

    #========
    # Search for ssh / v6
    #========
    ssh_v6_expected = "SSH IPv6 Restrictions"
    ssh_v6_actual = "SSH Restrictions limited"
    ssh_v6_status = "PASS"

    try:
        v6_output = subprocess.check_output(cmd_str, text=True)

        # Check the output for 22/ssh rules
        v6_output_lines = v6_output.split('\n')

        # Check for ssh limits in firewall rules
        for line in v6_output_lines:
            # Isolate checks to ssh lines
            if '22' in line or 'ssh' in line or 'SSH' in line:
                # Check if ssh rule has any limits
                if 'ALLOW' in line or "accept" in line:
                    if 'Anywhere' in line and 'v6' in line:
                        # Update global
                        updateSummaryCounts(0, 1, 0, 1)
                        ssh_v6_actual = "NO SSH IPv6 Restrictions"
                        ssh_v6_status = "FAIL"
                    else:
                        # Update global
                        updateSummaryCounts(1, 0, 0, 1)

    except Exception as e:
        logging.exception(f"Failed to determine [ SSH IPv6 Restrictions ] [ {e} ]")
        # Update global
        updateSummaryCounts(0, 1, 0, 1)
        ssh_v6_actual = "NO SSH IPv6 Restrictions"
        ssh_v6_status = "FAIL"

    #========
    # Create dictionary
    #========
    ssh_ipv6_dict = {
        "expected" : ssh_v6_expected,
        "actual" : ssh_v6_actual,
        "status" : ssh_v6_status
    }

    return ssh_ipv6_dict

#--------------
# Firewall Checks - SSH Restrictions
#   SSH Listening / firewall allowing
#   Source Restrictions
#   Rate Limiting
#   IPv6 Restrictions
#--------------
def firewallSSHRestricted(fw_enabled):
    logging.debug(f"\tWorking on [ Firewall : SSH Restrictions ]")

    #=====
    # If service isn't installed, skip the check
    #=====
    if not fw_enabled:
        firewall_fail = {
            'expected' : "SSH Restrictions Configured",
            'actual' : "not installed -- no ssh restrictions configured",
            'status' : "FAIL"
        }

        # Update global
        updateSummaryCounts(0, 4, 0, 4)
        return firewall_fail

    # Create final reporting distionary
    fw_ssh_restrictions_dict = {}

    # Call the functions
    listening_dict = firewallSSHRest_listening()
    sourceRest_dict = firewallSSHRest_sourceRestrictions()
    rateLimit_dict = firewallSSHRest_rateLimiting()
    ipv6Rest = firewallSSHRest_ipv6Restrictions()

    ######
    # Create final dictionary
    ######
    fw_ssh_restrictions_dict['listening'] = listening_dict 
    fw_ssh_restrictions_dict['source_restrictions'] = sourceRest_dict 
    fw_ssh_restrictions_dict['rate_limiting'] = rateLimit_dict 
    fw_ssh_restrictions_dict['ipv6_restrictions'] = ipv6Rest 

#--------------
# Kernel Checks - Disable IP-Forwarding
#--------------
def kernelDisableIPForward():
    logging.debug(f"\tWorking on [ Kernel : IP-Forwarding Disabled ]")

    #========
    # IPv4
    #========
    # Define cmd/search parameters
    #   0 = disabled
    #   1 = enabled
    #========
    ipv4_cmd_str = ['sysctl','net.ipv4.ip_forward']
    ipv4_expected = "disabled"
    ipv4_actual = "disabled"
    ipv4_status = "PASS"

    # Check for IPv4
    try:
        ipv4_output = subprocess.run(ipv4_cmd_str, capture_output=True, text=True)
        if ipv4_output.returncode == 0:
            # Update global
            updateSummaryCounts(1, 0, 0, 1)
        elif ipv4_output.returncode == 1:
            # Update global
            updateSummaryCounts(0, 1, 0, 1)
            ipv4_actual = "enabled"
            ipv4_status = "FAIL"

    except Exception as e:
        logging.exception(f"Failed to determine if IPv4 Forwarding is disabled [ {e} ]")
        # Update global
        updateSummaryCounts(0, 1, 0, 1)
        ipv4_actual = "Unable to determine"
        ipv4_status = "FAIL"

    # IPv4 Dict
    ipv4_forward_dict = {
        "expected" : ipv4_expected,
        "actual" : ipv4_actual,
        "status" : ipv4_status
    }
    logging.debug(f"\t\tIPv4 Forwarding Status : {ipv4_forward_dict['actual']}  [ {ipv4_forward_dict['status']} ]")

    #========
    # IPv6
    #========
    # Define cmd/search parameters
    #   0 = disabled
    #   1 = enabled
    #========
    ipv6_cmd_str = ['sysctl','net.ipv6.conf.all.forwarding']
    ipv6_expected = "disabled"
    ipv6_actual = "disabled"
    ipv6_status = "PASS"

    # Check for IPv6
    try:
        ipv6_output = subprocess.run(ipv6_cmd_str, capture_output=True, text=True)
        if ipv6_output.returncode == 0:
            # Update global
            updateSummaryCounts(1, 0, 0, 1)
        elif ipv6_output.returncode == 1:
            # Update global
            updateSummaryCounts(1, 0, 0, 1)
            ipv6_actual = "enabled"
            ipv6_status = "FAIL"
    except Exception as ee:
        logging.exception(f"Failed to determine if IPv6 Forwarding is disabled [ {ee} ]")
        # Update global
        updateSummaryCounts(0, 1, 0, 1)
        ipv6_actual = "Unable to determine"
        ipv6_status = "FAIL"

    # IPv6 Dict
    ipv6_forward_dict = {
        "expected" : ipv6_expected,
        "actual" : ipv6_actual,
        "status" : ipv6_status
    }
    logging.debug(f"\t\tIPv6 Forwarding Status : {ipv6_forward_dict['actual']}  [ {ipv6_forward_dict['status']} ]")

    #========
    # Create dictionary to return
    #========
    ip_forwarding_dict = {
        "ipv4_forwarding" : ipv4_forward_dict,
        "ipv6_forwarding" : ipv6_forward_dict
    }
    return ip_forwarding_dict 

#--------------
# Kernel Checks - Ignore ICMP Redirects
#--------------
def kernelDisableICMPRedirect():
    logging.debug(f"\tWorking on [ Kernel : ICMP Redirects Disabled]")

    #========
    # Search for 'accept_redirects' or 'send_redirects' or 'secure_redirects'
    # Define cmd/search parameters
    #   0 = disabled
    #   1 = enabled
    #========
    # Accept Redirects
    accept_cmd_str = ['sysctl','net.ipv4.conf.all.accept_redirects']
    accept_expected = "disabled"
    accept_actual = "disabled"
    accept_status = "PASS"
    try:
        accept_output = subprocess.run(accept_cmd_str, capture_output=True, text=True)
        if accept_output.returncode == 0:
            # Update global
            updateSummaryCounts(1, 0, 0, 1)
        elif accept_output.returncode == 1:
            # Update global
            updateSummaryCounts(0, 1, 0, 1)
            accept_actual = "enabled"
            accept_status = "FAIL"
    except Exception as e:
        logging.exception(f"Failed to determine if ICMP Redirects Disabled [ accept ] -- [ {e} ]")
        # Update global
        updateSummaryCounts(0, 1, 0, 1)
        accept_actual = "Unable to determine"
        accept_status = "FAIL"

    accept_dict = {
        "expected" : accept_expected,
        "actual" : accept_actual,
        "status" : accept_status
    }
    logging.debug(f"\t\tAccept ICMP Redirects Status: {accept_dict['actual']}  [ {accept_dict['status']} ]")

    #========
    # Send Redirects
    #========
    send_cmd_str = ['sysctl','net.ipv4.conf.all.send_redirects']
    send_expected = "disabled"
    send_actual = "disabled"
    send_status = "PASS"
    try:
        send_output = subprocess.run(send_cmd_str, capture_output=True, text=True)
        if send_output.returncode == 0:
            # Update global
            updateSummaryCounts(1, 0, 0, 1)
        elif send_output.returncode == 1:
            # Update global
            updateSummaryCounts(0, 1, 0, 1)
            send_actual = "enabled"
            send_status = "FAIL"
    except Exception as ee:
        logging.exception(f"Failed to determine if ICMP Redirects Disabled [ send ] -- [ {ee} ]")
        # Update global
        updateSummaryCounts(0, 1, 0, 1)
        send_actual = "Unable to determine"
        send_status = "FAIL"

    send_dict = {
        "expected" : send_expected,
        "actual" : send_actual,
        "status" : send_status
    }
    logging.debug(f"\t\tSend ICMP Redirects Status: {send_dict['actual']}  [ {send_dict['status']} ]")

    #========
    # Secure Redirects
    #========
    secure_cmd_str = ['sysctl','net.ipv4.conf.all.secure_redirects']
    secure_expected = "disabled"
    secure_actual = "disabled"
    secure_status = "PASS"
    try:
        secure_output = subprocess.run(secure_cmd_str, capture_output=True, text=True)
        if secure_output.returncode == 0:
            # Update global
            updateSummaryCounts(1, 0, 0, 1)
        elif secure_output.returncode == 1:
            # Update global
            updateSummaryCounts(0, 1, 0, 1)
            secure_actual = "enabled"
            secure_status = "FAIL"
    except Exception as eee:
        logging.exception(f"Failed to determine if ICMP Redirects Disabled [ secure ] -- [ {eee} ]")
        # Update global
        updateSummaryCounts(0, 1, 0, 1)
        secure_actual = "Unable to determine"
        secure_status = "FAIL"

    secure_dict = {
        "expected" : secure_expected,
        "actual" : secure_actual,
        "status" : secure_status
    }
    logging.debug(f"\t\tSecure ICMP Redirects Status: {secure_dict['actual']}  [ {secure_dict['status']} ]")

    #========
    # Final Dictionary to return
    #========
    icmp_redirects_dict = {
        "icmp_redirects_accept" : accept_dict,
        "icmp_redirects_send" : send_dict,
        "icmp_redirects_secure" : secure_dict
    }

    return icmp_redirects_dict

#--------------
# Kernel Checks - Enable SYN Cookies
#--------------
def kernelEnableSYNCookies():
    logging.debug(f"\tWorking on [ Kernel : SYN Cookies Enabled]")

    #========
    # Define cmd parameters
    #========
    cmd_str = ['sysctl','net.ipv4.tcp_syncookies']

    syn_expected = "disabled"
    syn_actual = "disabled"
    syn_status = "PASS"

    #========
    # Check setting
    #========
    try:
        syn_output = subprocess.run(cmd_str, capture_output=True, text=True)
        if syn_output.returncode == 0:
            # Update global
            updateSummaryCounts(1, 0, 0, 1)
        elif syn_output.returncode == 1:
            # Update global
            updateSummaryCounts(0, 1, 0, 1)
            syn_actual = "enabled"
            syn_status = "FAIL"
    except Exception as e:
        logging.exception(f"Failed to determine if SYN Cookes are enabled [ {e} ]")
        # Update global
        updateSummaryCounts(0, 1, 0, 1)
        syn_actual = "Unable to determine"
        syn_status = "FAIL"

    syn_dict = {
        "expected" : syn_expected,
        "actual" : syn_actual,
        "status" : syn_status
    }
    logging.debug(f"\t\tSYN Cookies Status: {syn_dict['actual']}  [ {syn_dict['status']} ]")

    return syn_dict

#--------------
# Kernel Checks - Disable Source Routing
#--------------
def kernelDisableSourceRouting():
    logging.debug(f"\tWorking on [ Kernel : Source Routing Disabled ]")

    #========
    # Define cmd parameters
    #========
    cmd_str = ['sysctl','net.ipv4.conf.all.accept_source_route']

    dis_source_expected = "disabled"
    dis_source_actual = "disabled"
    dis_source_status = "PASS"

    #========
    # Check setting
    #========
    try:
        dis_source_output = subprocess.run(cmd_str, capture_output=True, text=True)
        if dis_source_output.returncode == 0:
            # Update global
            updateSummaryCounts(1, 0, 0, 1)
        elif dis_source_output.returncode == 1:
            # Update global
            updateSummaryCounts(0, 1, 0, 1)
            dis_source_actual = "enabled"
            dis_source_status = "FAIL"
    except Exception as e:
        logging.exception(f"Failed to determine if Source Routing is  enabled [ {e} ]")
        # Update global
        updateSummaryCounts(0, 1, 0, 1)
        dis_source_actual = "Unable to determine"
        dis_source_status = "FAIL"

    dis_source_dict = {
        "expected" : dis_source_expected,
        "actual" : dis_source_actual,
        "status" : dis_source_status
    }

    logging.debug(f"\t\tSource Routing Status: {dis_source_dict['actual']}  [ {dis_source_dict['status']} ]")

    return dis_source_dict

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
    logging.debug(f"\tWorking on [ Permissions : World Writable Files ]")

    #==============
    # Define parameters
    #==============
    path = "/"
    cmd_str = ['find', path, '-perm', '-o+w', '-type', 'f']

    ww_perm_expected = "No world-writable files present"
    ww_perm_actual = "No world-writable files present"
    ww_perm_status = "PASS"

    #==============
    # Check for world writable  
    #==============
    try:
        ww_cmd_output = subprocess.run(cmd_str, capture_output=True, text=True)
        ww_cmd_lines = ww_cmd_output.stdout.split('\n')

        # Check for the number of world-writable files
        if len(ww_cmd_lines) < 1:
            # Update global
            updateSummaryCounts(1, 0, 0, 1)
        else:
            # Update global
            updateSummaryCounts(0, 1, 0, 1)
            ww_perm_actual = f"{len(ww_cmd_lines)} world-writable files present"
            ww_perm_status = "FAIL"

    except Exception as e:
        logging.exception(f"Failed to determine presence of world writable files [ {e} ]")
        ww_perm_actual = "Unable to check for world-writable files"
        ww_perm_status = "FAIL"

    ww_perm_dict = {
        "expected" : ww_perm_expected,
        "actual" : ww_perm_actual,
        "status" : ww_perm_status
    }

    logging.debug(f"\t\tWorld Writable Files : {ww_perm_dict['actual']} [ {ww_perm_dict['status']} ]")
    
    return ww_perm_dict

#--------------
# Retrieve permissions for passed file
#--------------
def permissionsRetriever(path):

    permissions_to_return = None

    # Determine permissions
    try:
        # Determine mode
        mode = os.stat(path).st_mode
    
        # Convert to octal
        permissions_to_return = oct(mode)[-3:]

    except FileNotFoundError:
        logging.exception(f"Exception: File was not found [ {path} ]")
    except Exception as e:
        logging.exception(f"Exception: Unable to determine permissions [ {e} ]")

    return permissions_to_return 

#--------------
# Grabs permission for passed file
#--------------
def filePermissionIsolation(file_path, expected_permissions):
    logging.debug(f"\t\tChecking Permissions For [ {file_path} ]")

    passed_file_path = file_path
    passed_file_exists = Path(passed_file_path)
    passed_file_expected = expected_permissions

    if passed_file_exists.is_file() or passed_file_exists.is_dir():
        passed_file_actual = permissionsRetriever(passed_file_path)
        passed_file_status = "PASS" if passed_file_expected == passed_file_actual else "FAIL"

        passed_file_dict = { 
            'expected' : passed_file_expected,
            'actual' : passed_file_actual,
            'status' : passed_file_status
        }

        if passed_file_status == "PASS":
            # Update global
            updateSummaryCounts(1, 0, 0, 1)
        else:
            # Update global
            updateSummaryCounts(0, 1, 0, 1)
    else:
        passed_file_dict = { 
            'expected' : passed_file_expected,
            'actual' : "File Not Present",
            'status' : "PASS"
        }

        # Update global with PASS
        updateSummaryCounts(1, 0, 0, 1)

    return passed_file_dict

#--------------
# Permissions Checks - Improper SSH Key Permission
#--------------
def permissionsImproperSSHKeyPermissions():
    logging.debug(f"\tWorking on [ Permissions : SSH Key Permissions ]")

    ssh_perm_dict = {}
    
    #================
    # Gather actual permissions
    #================
    ssh_perm_dict['~/.ssh'] = filePermissionIsolation('~/.ssh', '700')
    ssh_perm_dict['~/.ssh/id_rsa'] = filePermissionIsolation('~/.ssh/id_rsa', '600')
    ssh_perm_dict['~/.ssh/id_rsa.pub'] = filePermissionIsolation('~/.ssh/id_rsa.pub', '644')
    ssh_perm_dict['~/.ssh/authorized_keys'] = filePermissionIsolation('~/.ssh/authorized_keys', '600')
    ssh_perm_dict['~/.ssh/config'] = filePermissionIsolation('~/.ssh/config', '600')

    return ssh_perm_dict

#--------------
# Permissions Checks - SUID / SGID Binaries
#--------------
def permissionsSUIDSGIDBinaries():
    logging.debug(f"\tWorking on [ Permissions : SUID / SGID Binaries]")

    # SUID : find / -type f -perm /4000
    # SGID : find / -type f -perm /2000
    base_path = '/'

    #==============
    # Check for suid files
    #==============
    suid_cmd = ['find', base_path, '-type', 'f', '-perm', '/4000']
    suid_expected = "No SUID files present"
    suid_actual = "No SUID files present"
    suid_status = "PASS"
    try:
        suid_cmd_output = subprocess.run(suid_cmd, capture_output=True, text=True)
        suid_cmd_lines = suid_cmd_output.stdout.split('\n')

        # Check for the number of world-writable files
        if len(suid_cmd_lines) < 1:
            # Update global
            updateSummaryCounts(1, 0, 0, 1)
        else:
            # Update global
            updateSummaryCounts(0, 1, 0, 1)
            suid_actual = f"{len(suid_cmd_lines)} SUID files present"
            suid_status = "FAIL"

    except Exception as e:
        logging.exception(f"Failed to determine presence of SUID files [ {e} ]")
        suid_actual = "Unable to check for SUID files"
        suid_status = "FAIL"

    suid_dicts = {
        "expected" : suid_expected,
        "actual" : suid_actual,
        "status" : suid_status
    }

    #==============
    # Check for sgid files
    #==============
    sgid_cmd = ['find', base_path, '-type', 'f', '-perm', '/2000']
    sgid_expected = "No SGID files present"
    sgid_actual = "No SGID files present"
    sgid_status = "PASS"
    try:
        sgid_cmd_output = subprocess.run(sgid_cmd, capture_output=True, text=True)
        sgid_cmd_lines = sgid_cmd_output.stdout.split('\n')

        # Check for the number of world-writable files
        if len(sgid_cmd_lines) < 1:
            # Update global
            updateSummaryCounts(1, 0, 0, 1)
        else:
            # Update global
            updateSummaryCounts(0, 1, 0, 1)
            sgid_actual = f"{len(sgid_cmd_lines)} SUID files present"
            sgid_status = "FAIL"

    except Exception as ee:
        logging.exception(f"Failed to determine presence of SGID files [ {ee} ]")
        # Update global
        updateSummaryCounts(0, 1, 0, 1)
        sgid_actual = "Unable to check for SGID files"
        sgid_status = "FAIL"

    sgid_dicts = {
        "expected" : sgid_expected,
        "actual" : sgid_actual,
        "status" : sgid_status
    }

    #==============
    # Create final dict to return
    #==============
    suid_sgid_dict = {
        "suid_files" : suid_dicts,
        "sgid_files" : sgid_dicts,
    }

    return suid_sgid_dict 

#--------------
# Permissions Checks - Sensitive File Ownership
#   /etc/passwd
#   /etc/shadow
#   /etc/sudoers
#--------------
def permissionsSensitiveFileOwnership():
    logging.debug(f"\tWorking on [ Permissions : Sensitive File Ownership ]")

    sensitive_files_dict = {}

    #==============
    # Create / return dict
    #==============
    sensitive_files_dict['/etc/passwd'] = filePermissionIsolation('/etc/passwd', '644')
    sensitive_files_dict['/etc/shadow'] = filePermissionIsolation('/etc/shado', '600')
    sensitive_files_dict['/etc/sudoers'] = filePermissionIsolation('/etc/sudoers', '440')

    return sensitive_files_dict

#--------------
# Remote / SSH Checks - root login disabled
#   Search for 'PermitRootLogin' - commented = disabled
#--------------
def remoteRootLoginDisabled():
    logging.debug(f"\tWorking on [ Remote : Root Loging Disabled ]")

    #------------------
    # Define paths / strings / variables
    #------------------
    sshd_path = "/etc/ssh/sshd_config"
    search_rootlogin = "^#?PermitRootLogin"
    search_cmd = ['grep', '-E', search_rootlogin, sshd_path]

    # Define output variables
    root_log_enabled_expected = "disabled"
    root_log_enabled_actual = "disabled"
    root_log_enabled_status = "PASS"

    #------------------
    # Search for the string
    #------------------
    try:
        rootlogin_output = subprocess.run(search_cmd, capture_output=True, text=True)
        if rootlogin_output.returncode == 0:
            rootlogin_output_split = rootlogin_output.stdout.strip().split('\n')

            # Make sure only one thing was returned
            if len(rootlogin_output_split) > 1:
                updateSummaryCounts(0, 1, 0, 1)
                root_log_enabled_actual = "Unabled to determine status"
                root_log_enabled_status = "FAIL"

            elif len(rootlogin_output_split) == 1:
                # Check if the string started with '#'
                if rootlogin_output_split[0].startswith('#'):
                    updateSummaryCounts(1, 0, 0, 1)
                else:
                    updateSummaryCounts(0, 1, 0, 1)
                    root_log_enabled_actual = "enabled"
                    root_log_enabled_status = "FAIL"
            else:
                updateSummaryCounts(0, 1, 0, 1)
                root_log_enabled_actual = "Unabled to determine status"
                root_log_enabled_status = "FAIL"
        else:
            updateSummaryCounts(0, 1, 0, 1)
            root_log_enabled_actual = "Unabled to determine status"
            root_log_enabled_status = "FAIL"

    except Exception as e:
        logging.exception(f"Unexpected error [ {e} ]")

    #------------------
    # Create final dictionary for return
    #------------------
    root_log_dis_dict = {
        "expected" : root_log_enabled_expected,
        "actual" : root_log_enabled_actual,
        "status" : root_log_enabled_status
    }

    return root_log_dis_dict 

#--------------
# Remote / SSH Checks - password authentication disabled
#   Search for 'PasswordAuthentication'
#       If yes, then it is enabled - if commented out, then it is enabled
#--------------
def remotePasswordAuthDisabled():
    logging.debug(f"\tWorking on [ Remote : Password Authentication Disabled ]")

    #------------------
    # Define paths / strings / variables
    #------------------
    sshd_path = "/etc/ssh/sshd_config"
    search_passauth = "^#?PasswordAuthentication"
    search_cmd = ['grep', '-E', search_passauth, sshd_path]

    # Define output variables
    pass_auth_enabled_expected = "disabled"
    pass_auth_enabled_actual = "disabled"
    pass_auth_enabled_status = "PASS"

    #------------------
    # Search for the string
    #------------------
    try:
        passauth_output = subprocess.run(search_cmd, capture_output=True, text=True)
        if passauth_output.returncode == 0:
            passauth_output_split = passauth_output.stdout.strip().split('\n')

            # Make sure only one thing was returned
            if len(passauth_output_split) > 1:
                updateSummaryCounts(0, 1, 0, 1)
                pass_auth_enabled_actual = "Unabled to determine status"
                pass_auth_enabled_status = "FAIL"

            elif len(passauth_output_split) == 1:
                # Check if the string started with '#' -- disabled
                if passauth_output_split[0].startswith('#'):
                    updateSummaryCounts(1, 0, 0, 1)

                # The line is not commented out
                else:
                    # Enabled
                    if "yes" in passauth_output_split[0]:
                        updateSummaryCounts(0, 1, 0, 1)
                        pass_auth_enabled_actual = "enabled"
                        pass_auth_enabled_status = "FAIL"

                    # Disabled
                    elif "no" in passauth_output_split[0]:
                        updateSummaryCounts(1, 0, 0, 1)

            else:
                updateSummaryCounts(0, 1, 0, 1)
                pass_auth_enabled_actual = "Unabled to determine status"
                pass_auth_enabled_status = "FAIL"
        else:
            updateSummaryCounts(0, 1, 0, 1)
            pass_auth_enabled_actual = "Unabled to determine status"
            pass_auth_enabled_status = "FAIL"

    except Exception as e:
        logging.exception(f"Unexpected error [ {e} ]")

    #------------------
    # Create final dictionary for return
    #------------------
    pass_auth_dis_dict = {
        "expected" : pass_auth_enabled_expected,
        "actual" : pass_auth_enabled_actual,
        "status" : pass_auth_enabled_status
    }

    return pass_auth_dis_dict

#--------------
# Remote / SSH Checks - ssh protocol version
#   Run 'ssh -V'
#--------------
def remoteProtocolVersion():
    logging.debug(f"\tWorking on [ Remote : SSH Protocol Version]")

    version_cmd = ['ssh', '-V']

    # Define output variables
    ssh_version = "Unknown"
    ssh_version_status = "FAIL"

    #------------------
    # Search for the string
    #------------------
    try:
        version_output = subprocess.run(version_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
        if version_output.returncode == 0:
            # Versioning is output via stderr
            ssh_version = version_output.stderr.strip()
            ssh_version_status = "PASS"

            if ssh_version == "":
                ssh_version = "Unknown"
                ssh_version_status = "FAIL"

    except Exception as e:
        logging.exception(f"Unexpected error while determining ssh version [ {e} ]")

    #------------------
    # Create final dictionary for return
    #------------------
    ssh_version_dict = {
        "version" : ssh_version,
        "status" : ssh_version_status
    }

    return ssh_version_dict

#--------------
# Remote / SSH Checks - empty passwords disabled
#   Search for 'PermitEmptyPasswords'
#       If yes = enabled ||| if commented out = disabled || if uncommented and no = disabled
#--------------
def remoteEmptyPasswordsDisabled():
    logging.debug(f"\tWorking on [ Remote : Empty Password Disabled ]")

    #------------------
    # Define paths / strings / variables
    #------------------
    sshd_path = "/etc/ssh/sshd_config"
    search_empty_pass = "^#?PermitEmptyPasswords"
    search_cmd = ['grep', '-E', search_empty_pass, sshd_path]

    # Define output variables
    empty_pass_enabled_expected = "disabled"
    empty_pass_enabled_actual = "disabled"
    empty_pass_enabled_status = "PASS"

    #------------------
    # Search for the string
    #------------------
    try:
        emptypass_output = subprocess.run(search_cmd, capture_output=True, text=True)
        if emptypass_output.returncode == 0:
            emptypass_output_split = emptypass_output.stdout.strip().split('\n')

            # Make sure only one thing was returned
            if len(emptypass_output_split) > 1:
                updateSummaryCounts(0, 1, 0, 1)
                pass_auth_enabled_actual = "Unabled to determine status"
                pass_auth_enabled_status = "FAIL"

            elif len(emptypass_output_split) == 1:
                # Check if the string started with '#' -- disabled
                if emptypass_output_split[0].startswith('#'):
                    updateSummaryCounts(1, 0, 0, 1)

                # The line is not commented out
                else:
                    # Enabled
                    if "yes" in emptypass_output_split[0]:
                        updateSummaryCounts(0, 1, 0, 1)
                        empty_pass_enabled_actual = "enabled"
                        empty_pass_enabled_status = "FAIL"

                    # Disabled
                    elif "no" in emptypass_output_split[0]:
                        updateSummaryCounts(1, 0, 0, 1)

            else:
                updateSummaryCounts(0, 1, 0, 1)
                empty_pass_enabled_actual = "Unabled to determine status"
                empty_pass_enabled_status = "FAIL"
        else:
            updateSummaryCounts(0, 1, 0, 1)
            empty_pass_enabled_actual = "Unabled to determine status"
            empty_pass_enabled_status = "FAIL"

    except Exception as e:
        logging.exception(f"Unexpected error [ {e} ]")

    #------------------
    # Create final dictionary for return
    #------------------
    empty_pass_dict = {
        "expected" : empty_pass_enabled_expected,
        "actual" : empty_pass_enabled_actual,
        "status" : empty_pass_enabled_status
    }

    return empty_pass_dict


#--------------
# Remote / SSH Checks - max authorization attempts
#   Search for 'MaxAuthTries'
#--------------
def remoteMaxAuthAttempts():
    logging.debug(f"\tWorking on [ Remote : Max Authorization Attempts Configured ]")

    #------------------
    # Define paths / strings / variables
    #------------------
    sshd_path = "/etc/ssh/sshd_config"
    search_max_auth = "^#?MaxAuthTries"
    search_cmd = ['grep', '-E', search_max_auth, sshd_path]

    # Define output variables
    max_auth_enabled_expected = "<=4"
    max_auth_enabled_actual = "3"
    max_auth_enabled_status = "PASS"

    #------------------
    # Search for the string
    #------------------
    try:
        maxauth_output = subprocess.run(search_cmd, capture_output=True, text=True)
        if maxauth_output.returncode == 0:
            maxauth_output_split = maxauth_output.stdout.strip().split('\n')

            # Make sure only one thing was returned
            if len(maxauth_output_split) > 1:
                updateSummaryCounts(0, 1, 0, 1)
                max_auth_enabled_actual = "Unabled to determine status"
                max_auth_enabled_status = "FAIL"

            elif len(maxauth_output_split) == 1:

                # Check if the string started with '#' -- disabled (so default = 6)
                if maxauth_output_split[0].startswith('#'):
                    updateSummaryCounts(0, 1, 0, 1)
                    max_auth_enabled_actual = "6"
                    max_auth_enabled_status = "FAIL"

                # The line is not commented out - isolate the number
                else:
                    max_auth_config = int(maxauth_output_split[0].replace("MaxAuthTries","").strip())

                    # Configured securely 
                    if max_auth_config <= 4 :
                        updateSummaryCounts(1, 0, 0, 1)
                        max_auth_enabled_actual = max_auth_config
                        max_auth_enabled_status = "PASS"

                    # Configured insecurely 
                    else:
                        updateSummaryCounts(0, 1, 0, 1)
                        max_auth_enabled_actual = max_auth_config
                        max_auth_enabled_status = "FAIL"

            else:
                updateSummaryCounts(0, 1, 0, 1)
                max_auth_enabled_actual = "Unabled to determine status"
                max_auth_enabled_status = "FAIL"
        else:
            updateSummaryCounts(0, 1, 0, 1)
            max_auth_enabled_actual = "Unabled to determine status"
            max_auth_enabled_status = "FAIL"

    except Exception as e:
        logging.exception(f"Unexpected error [ {e} ]")

    #------------------
    # Create final dictionary for return
    #------------------
    max_auth_dict = {
        "expected" : max_auth_enabled_expected,
        "actual" : max_auth_enabled_actual,
        "status" : max_auth_enabled_status
    }

    return max_auth_dict


#--------------
# Remote / SSH Checks - idle timeout configured
#   Search for 'ClientAliveInterval'
#   If commented out = disabled
#--------------
def remoteIdleTimeoutConfigured():
    logging.debug(f"\tWorking on [ Remote : Idle Timeout Configured ]")

    #------------------
    # Define paths / strings / variables
    #------------------
    sshd_path = "/etc/ssh/sshd_config"
    search_alive = "^#?ClientAliveInterval"
    search_cmd = ['grep', '-E', search_alive, sshd_path]

    # Define output variables
    client_alive_enabled_expected = "3004"
    client_alive_enabled_actual = "3"
    client_alive_enabled_status = "PASS"

    #------------------
    # Search for the string
    #------------------
    try:
        calive_output = subprocess.run(search_cmd, capture_output=True, text=True)
        if calive_output.returncode == 0:
            calive_output_split = calive_output.stdout.strip().split('\n')

            # Make sure only one thing was returned
            if len(calive_output_split) > 1:
                updateSummaryCounts(0, 1, 0, 1)
                client_alive_enabled_actual = "Unabled to determine status"
                client_alive_enabled_status = "FAIL"

            elif len(calive_output_split) == 1:

                # Check if the string started with '#'
                if calive_output_split[0].startswith('#'):
                    updateSummaryCounts(0, 1, 0, 1)
                    client_alive_enabled_actual = "Not configured"
                    client_alive_enabled_status = "FAIL"

                # The line is not commented out - isolate the number
                else:
                    client_alive_config = int(calive_output_split[0].replace("ClientAliveInterval","").strip())

                    # Configured securely 
                    if client_alive_config <= 300:
                        updateSummaryCounts(1, 0, 0, 1)
                        client_alive_enabled_actual = client_alive_config
                        client_alive_enabled_status = "PASS"

                    # Configured insecurely 
                    else:
                        updateSummaryCounts(0, 1, 0, 1)
                        client_alive_enabled_actual = client_alive_config
                        client_alive_enabled_status = "FAIL"

            else:
                updateSummaryCounts(0, 1, 0, 1)
                client_alive_enabled_actual = "Unabled to determine status"
                client_alive_enabled_status = "FAIL"
        else:
            updateSummaryCounts(0, 1, 0, 1)
            client_alive_enabled_actual = "Unabled to determine status"
            client_alive_enabled_status = "FAIL"

    except Exception as e:
        logging.exception(f"Unexpected error [ {e} ]")

    #------------------
    # Create final dictionary for return
    #------------------
    client_alive_dict = {
        "expected" : client_alive_enabled_expected,
        "actual" : client_alive_enabled_actual,
        "status" : client_alive_enabled_status
    }

    return client_alive_dict

#--------------
# Remote / SSH Checks - Strong Cipher
#   List ciphers => ssh -Q cipher
#--------------
def remoteStrongCipher():
    logging.debug(f"\tWorking on [ Remote : Cipher Checks ]")
    
    #==================
    # Define variables
    #==================
    cipher_cmd = ['ssh', '-Q', 'cipher']

    # Define strong ciphers
    strong_ciphers = ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com", "aes128-gcm@openssh.com", "aes256-ctr", "aes192-ctr", "aes128-ctr"]
    strong_cipher_present = False
    weak_ciphers = []
    weak_ciphers_output = None

    ciphers_expected = "Strong ciphers present"
    ciphers_actual = "Strong ciphers present"
    ciphers_status = "PASS"

    #==================
    # Retrieve system cihpers
    #==================
    try:
        cipher_output = subprocess.run(cipher_cmd, capture_output=True, text=True)
        cipher_output_split = cipher_output.stdout.strip().split('\n')

        # Work through the reported ciphers
        for cipher in cipher_output_split:

            # Note if strong cipher is in reported list
            if cipher in strong_ciphers:
                strong_cipher_present = True
                updateSummaryCounts(0, 1, 0, 1)

            # Work through the weak ciphers
            else:
                weak_ciphers.append(cipher)

    except Exception as e:
        logging.exception(f"Unexpected error [ {e} ]")

    #==================
    # Create dictionary for return
    #==================
    # include weak_ciphers_found
    # recommendation "remove weak ciphers"
    if not strong_cipher_present:
        ciphers_actual = "No strong ciphers present"
        ciphers_status = "FAIL"

    # Create initial dictionary
    cipher_dict = {
        "expected" : ciphers_expected,
        "actual" : ciphers_actual,
        "status" : ciphers_status
    }

    # Process the results
    if len(weak_ciphers) > 0:
        # Create string for output
        weak_ciphers_output = ','.join(weak_ciphers)
        cipher_dict['weak_ciphers_present'] = weak_ciphers_output
        cipher_dict['recommendation'] = "Disable weak ciphers"
        

    return cipher_dict

#--------------
# Service Checks - Provide nested dictionaries of some ports and their associated info
#--------------
def servicesGatherSystemServices():
    logging.debug(f"\tRetrieving current system services")

    # Grab / Process the services on system
    system_services = []
    services_cmd = ["systemctl", "list-units", "--type=service", "--state=running"]

    # Run the command, gather output, process
    try:
        services_output = subprocess.run(services_cmd, capture_output=True, text=True)
        # Check return code for success
        if services_output.returncode == 0:
            serv_out_split = services_output.stdout.strip().split('\n')

            # Process the output into dictionaries (skip the table header line and last 4 info lines)
            for line in serv_out_split[1:-5]:
                # Isolate the columns
                columns = line.split()
                if len(columns) > 1:
                    service = {
                        "Unit": columns[0].replace('.service',''),
                        "Load": columns[1],
                        "Active": columns[2],
                        "Sub": columns[3],
                        "Description": ' '.join(columns[4:]),
                        "status": "WARN" 
                    }
                    system_services.append(service)
                    updateSummaryCounts(0, 0, 1, 1)

        else:
            logging.error("Failed to gather system services")

    except Exception as e:
        logging.exception(f"Failed to retreive system services [ {e} ]")

    return system_services

#--------------
# Service Minimalization - unnecessary services
#   Main cmd : systemctl list-units --type=service --state=running
#   Get services information from services.py
#       service_info = services.systemServicesInformation()
#--------------
def systemServicesAudit():
    logging.debug(f"\tWorking on [ Service Minimization : System Services ]")

    # Dictionary to return
    service_minimization = {}

    #=============
    # Gather current system services
    #=============
    service_array = servicesGatherSystemServices()
    
    # Make sure we get something back
    if len(service_array) == 0:
        logging.error("Failed to audit system services")
        return service_minimization

    #=============
    # Grab already defined services
    #=============
    service_info = services.systemServicesInformation()

    #=============
    # Compare to the services listed and mark unknowns
    #=============
    for service in service_array:
        service_name = service['Unit']
        # If it's in the defined services, grab the information
        if service_name in service_info:

            specific_service_dict = service_info[service_name]
            service_minimization[service_name] = specific_service_dict 

        # No info on the listed port
        else:
            temp_unk = {
                "service": service['Unit'],
                "classification": "unkown",
                "risk_level": "WARN",
                "status": "WARN",
                "recommended": "unknown",
                "recommendation": "Review necessity and exposure"
            }

            updateSummaryCounts(0, 0, 1, 1)
            service_minimization[service_name] = temp_unk 
    
    # Return dictionary
    return service_minimization

#--------------
# User-Privileges - users with UID 0
#--------------
def userPrivUIDUsers():
    logging.debug(f"\tWorking on [ User Privileges : Users with UID 0 ]")


    # Define variables
    user_zero_path = "/etc/passwd"
    user_zero_cmd = ['grep', ':0:', user_zero_path]

    uid0_users_expected = "none"
    uid0_users_actual = "none"
    uid0_users_status = "PASS"

    users_with_uid0 = []
    #------------------
    # Search for the string
    #------------------
    try:
        user_zero_output = subprocess.run(user_zero_cmd, capture_output=True, text=True)

        # Grep successful, return code = 0
        #   Grap users if successful
        if user_zero_output.returncode == 0:
            # Split into indiv entries
            user_zero_output_split = user_zero_output.stdout.strip().split('\n')

            # For each entry, split on ':'
            for user in user_zero_output_split:
                user_name = user.split(':')[0]
                # Add the username to array
                users_with_uid0.append(user_name)

            # Create string to return
            #guid0_users = ','.join(users_with_uid0)
            uid0_users_actual = ','.join(users_with_uid0)
            uid0_users_status = "WARN"

            # Update globals
            updateSummaryCounts(0, 0, 1, 1)

        else:
            # Update globals
            updateSummaryCounts(1, 0, 0, 1)

    except Exception as e:
        logging.exception(f"Unexpected error while searching {user_zero_path} [ {e} ]")

    #------------------
    # Create / return dictionary
    #------------------
    priv_uid_user_dict = {
        "expected" : uid0_users_expected,
        "actual" : uid0_users_actual,
        "status" : uid0_users_status
    }

    return priv_uid_user_dict


#--------------
# User-Privileges - sudo group memberships
#--------------
def userPrivSUDOGroupMemberships():
    logging.debug(f"\tWorking on [ User Privileges : SUDO Group Membership]")

    #------------------
    # Define paths / strings / variables
    #------------------
    group_path = "/etc/group"
    search_sudogroup = "^sudo"
    search_cmd = ['grep', '-E', search_sudogroup, group_path]

    # Define output variables
    sudo_group_expected = "none"
    sudo_group_actual = "none"
    sudo_group_status = "PASS"

    sudo_group_members = []
    #------------------
    # Search for the string
    #------------------
    try:
        sudogroup_output = subprocess.run(search_cmd, capture_output=True, text=True)
        if sudogroup_output.returncode == 0:
            # Split by line / user
            sudogroup_output_split = sudogroup_output.stdout.strip().split('\n')

            # Gather the username
            for user in sudogroup_output_split:
                username = user.split(':')[-1]
                sudo_group_members.append(username)

            sudo_group_actual = ','.join(sudo_group_members)
            sudo_group_status = "WARN"

            # Update globals
            updateSummaryCounts(0, 0, 1, 1)

        else:
            # Update globals
            updateSummaryCounts(1, 0, 0, 1)

    except Exception as e:
        logging.exception(f"Unexpected error while searching for SUDO Group Membership [ {e} ]")

    #------------------
    # Create / return dictionary
    #------------------
    sudogroup_user_dict = {
        "expected" : sudo_group_expected,
        "actual" : sudo_group_actual,
        "status" : sudo_group_status
    }

    return sudogroup_user_dict

#--------------
# User-Privileges - Check all accounts present on system
#--------------
def presentAccountsChecks():
    logging.debug(f"\tWorking on [ User Privileges : Accounts Present]")

    accounts_present = {}
    #=================
    # Prepare to gather accounts on system
    #=================
    etc_passwd_path = "/etc/passwd"
    cat_cmd = ['cat', etc_passwd_path]

    user_accts = []
    sys_accts = []

    try:
        passwd_cat_output = subprocess.run(cat_cmd, capture_output=True, text=True)

        # If the command was successful, grab the output
        if passwd_cat_output.returncode == 0:
            # Split per line
            passwd_cat_output_split = passwd_cat_output.stdout.strip().split('\n')


            # For each entry create dictionary
            for passwd_user in passwd_cat_output_split:
                user_split = passwd_user.split(':')

                if int(user_split[2]) == 0:
                    account_type = "root"
                elif int(user_split[2]) < 1000:
                    account_type = "system"
                elif int(user_split[2]) >= 1000:
                    account_type = "user"

                acct = {
                    "username" : user_split[0],
                    "password" : user_split[1],
                    "UID" : user_split[2],
                    "GID" : user_split[3],
                    "GECOS" : user_split[4],
                    "home_dir" : user_split[5],
                    "shell" : user_split[6],
                    "acct_type" : account_type
                }

                # Append the dictionaries to appropriate array
                if acct['acct_type'] == "user" or acct['acct_type'] == "root":
                    user_accts.append(acct)
                else:
                    sys_accts.append(acct)

    except Exception as e:
        logging.exception(f"Unexpected error while checking for accounts present [ {e} ]")

    #=================
    # Process User Accounts
    #   Check for account_state, last_login, password_status, root_account
    #=================
    accounts_present['user_accounts'] = auditUserAccounts(user_accts)
    
    #=================
    # Process System Accounts
    #   Check for interactive_shell, disabled_service_account
    #=================
    accounts_present['system_accounts'] = auditSystemAccounts(sys_accts) 

    return accounts_present

#--------------
# User account checks via chage
#--------------
def userAccountChageChecks(uname):
    check = "chage"
    #logging.debug(f"\tWorking on [ User Privileges : User Account Checks - {check} : {uname}]")

    # Set variables
    chage_cmd = ['chage', '-l', uname]

    acct_expir = "Unable to determine"
    last_pw_change = "Unable to determine"
    passw_expir  = "Unable to determine"

    # 'search' strings
    ls_pw_ch = "Last password change"
    pw_expir = "Password expires"
    ac_expir = "Account expires"

    # Run checks
    try:
        #chage_output = subprocess.run(chage_cmd, capture_output=True, text=True)
        chage_output = subprocess.run(chage_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # Work through the results
        if chage_output.returncode == 0:

            chage_output_split = chage_output.stdout.strip().split('\n')
            # Work through the split output and isolate results
            for info in chage_output_split:
                if ls_pw_ch in info.strip():
                    # Split the line further to isolate value
                    last_pw_change = info.split(':')[1].strip()
                elif pw_expir in info:
                    # Split the line further to isolate value
                    passw_expir = info.split(':')[1].strip()
                elif ac_expir in info:
                    # Split the line further to isolate value
                    acct_expir = info.split(':')[1].strip()

    except Exception as e:
        logging.exception(f"Unexpected error while running '{check}' checks [ {e} ]")

    return acct_expir, last_pw_change, passw_expir

#--------------
# User account checks via passwd
#--------------
def userAccountPasswdChecks(uname):
    check = "passwd"
    #logging.debug(f"\tWorking on [ User Privileges : User Account Checks - {check}]")

    # Set variables
    passwd_cmd = ['passwd', '-S', uname]
    acct_expir = "Unable to determine"

    # Run checks
    try:
        passwd_output = subprocess.run(passwd_cmd, capture_output=True, text=True)

        # Determine the state of the password
        passwd_output_split = passwd_output.stdout.strip().split()

        acct_state = passwd_output_split[1]

        match acct_state:
            case "P":
                acct_expir = "active"
            case "L":
                acct_expir = "locked"
            case "LK":
                acct_expir = "locked"
            case "NP":
                acct_expir = "empty"
            case "PS":
                acct_expir = "password set"
            case _:
                acct_expir = "unknown"

    except Exception as e:
        logging.exception(f"Unexpected error while running '{check}' checks [ {e} ]")

    return acct_expir

#--------------
# User account checks via lslogins
#--------------
def userAccountLastLoginCheck(uname):
    check = "lslogins"
    #logging.debug(f"\tWorking on [ User Privileges : User Account Checks - {check}]")

    # Set variables
    lslogins_cmd = ['lslogins', uname, '-o','LAST-LOGIN']
    last_login = "Unable to determine"

    # Run checks
    try:
        lslogins_output = subprocess.run(lslogins_cmd, capture_output=True, text=True)

        # Determine last login
        lslogins_output_split = lslogins_output.stdout.strip().split('\n')

        # Work through
        for info in lslogins_output_split:
            # Check for the info
            if "Last login:" in info:
                last_login = info.replace("Last login:","").strip()
                break

    except Exception as e:
        logging.exception(f"Unexpected error while running '{check}' checks [ {e} ]")

    return last_login

#--------------
# User-Privileges - user accounts
# Check the username (if it is active or locked) => passwd -S <username>
#   P = active password / L = locked / NP = no password (empty) / PS = password set / LK = locked
# Gather usernames on the system (lastlog -b 60)
#       If uid = 0 --> root account
#--------------
def auditUserAccounts(passed_user_accts):
    logging.debug(f"\tWorking on [ User Privileges : User Account Checks]")

    users_output_dict = {}

    #==============
    # Work through the passed users
    #==============
    for user in passed_user_accts:

        # Isolate username
        username = user['username']

        # Gather 'chage' information
        acct_expir, last_pw_change, pw_expir = userAccountChageChecks(username)

        # Gather 'passwd' information
        pw_status = userAccountPasswdChecks(username)

        # Gather 'lslogins' information
        last_log = userAccountLastLoginCheck(username)

        #==============
        # Build user dictionary
        #==============
        temp_u_dict = {
            "UID" : user['UID'],
            "GID" : user['GID'],
            "Home_dir" : user['home_dir'],
            "Comments" : user['GECOS'],
            "Account_Type" : user['acct_type'],
            "Last_password_change" : last_pw_change,
            "Account_expiration" : acct_expir,
            "Password_expiration" : pw_expir,
            "Password_status" : pw_status,
            "Last_login" : last_log,
        }

        users_output_dict[username] = temp_u_dict

    return users_output_dict

#--------------
# User-Privileges - system accounts (uid < 1000)
#--------------
def auditSystemAccounts(passed_sys_accts):
    logging.debug(f"\tWorking on [ User Privileges : System Account Checks]")

    sys_output_dict = {}

    #==============
    # Work through the passed users
    #==============
    for sys in passed_sys_accts:

        # Isolate username
        username = sys['username']

        # Gather 'passwd' information
        pw_status = userAccountPasswdChecks(username)

        warning = "PASS"
        shell = "Non-Iteractive Shell"
        # Determine if shell type is interactive
        if sys['shell'] != "/usr/sbin/nologin" and sys['shell'] != "/bin/false":
            shell = f"Iteractive Shell [ {sys['shell']} ]"
            warning = "FAIL"

        temp_s_dict = {
            "UID" : sys['UID'],
            "GID" : sys['GID'],
            "Home_dir" : sys['home_dir'],
            "Comments" : sys['GECOS'],
            "Account_Type" : sys['acct_type'],
            "Pasword_Status" : pw_status,
            "Shell_Type" : shell,
            "Shell_Status" : warning
        }

        sys_output_dict[username] = temp_s_dict

    return sys_output_dict

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
    logging_checks_dict['rsyslog_audit'] = rs_checks
    logging_checks_dict['auditd_audit'] = auditd_checks
    logging_checks_dict['journald_audit'] = journald_persistence
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

    firewall_enabled = False
    # Quick determination
    if enabled_check['actual'] == 'enabled':
        firewall_enabled = True

    active_check = firewallActive(firewall_enabled)
    deny_check = firewallDenyDefault(firewall_enabled)
    listening_ports_check = firewallListeningPorts(firewall_enabled)
    restricted_ssh_check = firewallSSHRestricted(firewall_enabled)

    #---
    # Update dictionary
    #---
    firewall_checks_dict['firewall_enabled'] = enabled_check
    firewall_checks_dict['firewall_active'] = active_check
    firewall_checks_dict['deny_by_default'] = deny_check
    firewall_checks_dict['listening_ports'] = listening_ports_check
    firewall_checks_dict['restricted_ssh'] = restricted_ssh_check

    # Quick check
    logging.debug(f"Number of Checks : {TOTAL_CHECKS} | Checks Passed : {PASSES} | Checks Failed : {FAILURES} | Warnings : {WARNINGS}")

    return firewall_checks_dict

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
    logging.info(f"Current Check : [ Remote / SSH Checks]")

    # Create dictionary
    remote_ssh_checks_dict = {}

    #---
    # Run the checks
    #---
    root_login = remoteRootLoginDisabled()
    pass_auth_disabled = remotePasswordAuthDisabled()
    ssh_protocol_version = remoteProtocolVersion()
    empty_password_disabled = remoteEmptyPasswordsDisabled()
    max_auth_attempts = remoteMaxAuthAttempts()
    idle_timeout_configured = remoteIdleTimeoutConfigured()
    strong_cipher = remoteStrongCipher()

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
    sys_serv_checks = systemServicesAudit()

    # Add fw enabled check
    enabled_check = firewallEnabled()

    firewall_enabled = False
    # Quick determination
    if enabled_check['actual'] == 'enabled':
        firewall_enabled = True
    exposed_net_serv_checks = firewallListeningPorts(firewall_enabled)


    #---
    # Update dictionary
    #---
    service_minimization_checks_dict['active_system_services'] = sys_serv_checks
    service_minimization_checks_dict['exposed_network_services'] = exposed_net_serv_checks

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
    present_accounts_checks = presentAccountsChecks()

    #---
    # Update dictionary
    #---
    user_priv_checks_dict['uid_0_accounts'] = uid_0_checks
    user_priv_checks_dict['sudo_users'] = sudo_users_checks
    user_priv_checks_dict['accounts_present'] = present_accounts_checks

    # Quick check
    logging.debug(f"Number of Checks : {TOTAL_CHECKS} | Checks Passed : {PASSES} | Checks Failed : {FAILURES} | Warnings : {WARNINGS}")

    return user_priv_checks_dict 

#==============
# 'Quick' Output for Audit Checks that can be performed
#   Will also indicate if particular checks can be remediated
#==============
def outputAuditCheckInformation():

    information_string ="""\

Script General: Python-based Linux security auditing toolkit
Script Purpose: Identify insecure system configurations and 
                validate common hardening controls
Script Restrictions: Must be run on Linux Systems

Audit Checks Available [audit -s <option>]:
    - Remote / SSH Hardening Checks <r>
    - Firewall Validation <f>
    - Logging & Auditing <l>
    - User & Privilege Auditing <u>
    - Sysctl / Kernel Hardening <k>
    - Automatic Updates <a>
    - Credential Policy Auditing <c>
    - Sensitive File Permisions <p>
    - Service Minimization <s>

Output Available:
    - JSON Report
    - Console Output
    """

    # Output the string
    print(information_string)

#==============
# Wrapper for Subset Audit Checks
#==============
def auditChecksSubsetWrapper(subset):
    logging.info(f"Begining Audit Checks [ SUBSET AUDIT ]")

    overall_scan_info = {}

    #------------
    # Create initial json string
    #------------
    # Audit Test Information
    #audit_metadata_dict = metaDataGenerator()
    overall_scan_info["scan_metadata"] = metaDataGenerator()

    #=============================================
    # Audit Checks
    #=============================================
    audit_checks = {}

    for check in subset:
        match check:
            case "a":
                # Auto-Update Checks
                auto_update_dict = checkAutoUpdates()
                audit_checks["auto_update_checks"] = auto_update_dict 
            case "c":
                # Credential / Password Policy Checks
                cred_dict = checkCredentialPassword()
                audit_checks["credential_policy_checks"] = cred_dict 
            case "f":
                # Firewall Checks
                firewall_dict = checkFirewall()
                audit_checks["firewall_checks"] = firewall_dict 
            case "k":
                # Kernel / System Checks
                kernel_dict = checkKernelSystem()
                audit_checks["kernel_checks"] = kernel_dict 
            case "l":
                # Logging Checks
                logging_dict = checkLogging()
                audit_checks["logging_configuration_checks"] = logging_dict 
            case "p":
                # Permissions (File) Checks
                file_perm_dict = checkPermissions()
                audit_checks["file_permission_checks"] = file_perm_dict 
            case "r":
                # Remote / SSH Checks
                ssh_checks_dict = checkRemote()
                audit_checks["ssh_remote_checks"] = ssh_checks_dict 
            case "s":
                # Services Check
                service_dict = checkServices()
                audit_checks["service_configuration_checks"] = service_dict 
            case "u":
                # User-privileges Check
                upriv_dict = checkUserPrivileges()
                audit_checks["user_privileges_check"] = upriv_dict 

    #=============================================
    # Create audit dictionary and translate to json
    #=============================================
    # Provide summary (total checks, total pass, total fail, total warning?)
    overall_scan_info["audit_checks"] = audit_checks

    # Create test count summary dict
    global PASSES
    global FAILURES
    global WARNINGS
    global TOTAL_CHECKS
    overall_tc_summary_dict = {
        "Total_Checks" : TOTAL_CHECKS,
        "Total_Pass" : PASSES,
        "Total_Fail" : FAILURES,
        "Total_Warn" : WARNINGS
    }

    # Add the test case summary to the overall_scan_info dict
    overall_scan_info["audit_summary"] = overall_tc_summary_dict 

    # Create the JSON output
    audit_ouput_json = json.dumps(overall_scan_info, indent=4, sort_keys=False)

    #=============================================
    # Output
    #=============================================
    # If print to stdout only
    if PRINT:
        # Once complete - output counts
        logging.info(f"Total Checks : {TOTAL_CHECKS} || Total Pass : {PASSES} || Total Fail : {FAILURES} || Total Warnings : {WARNINGS}")
        #reportOutput(overall_scan_info, 0)
        reportOutput(overall_scan_info, 0, "")

    else:
        basename = os.path.basename(OUTPUT)
        # Create output
        try:
            with open(OUTPUT, "w") as file:
                file.write(audit_ouput_json)
            logging.info(f"Writing audit report to file [ {basename} ]")
            # Once complete - output counts
            logging.info(f"Total Checks : {TOTAL_CHECKS} || Total Pass : {PASSES} || Total Fail : {FAILURES} || Total Warnings : {WARNINGS}")
        except PermissionError:
            logging.exception(f"Failed to write output to {basename} - Permissions Error")
            # Once complete - output counts
            logging.info(f"Total Checks : {TOTAL_CHECKS} || Total Pass : {PASSES} || Total Fail : {FAILURES} || Total Warnings : {WARNINGS}")
            # Print to stdout
            print(audit_ouput_json)
        except IOError as e:
            logging.exception(f"Failed to write output to {basename} - I/O Error [ {e} ]")
            # Once complete - output counts
            logging.info(f"Total Checks : {TOTAL_CHECKS} || Total Pass : {PASSES} || Total Fail : {FAILURES} || Total Warnings : {WARNINGS}")
            # Print to stdout
            print(audit_ouput_json)
        except Exception as e:
            logging.exception(f"Failed to write output to {basename} - Unexpeced Error [ {e} ]")
            # Once complete - output counts
            logging.info(f"Total Checks : {TOTAL_CHECKS} || Total Pass : {PASSES} || Total Fail : {FAILURES} || Total Warnings : {WARNINGS}")
            # Print to stdout
            print(audit_ouput_json)

#==============
# Wrapper for Full Audit Checks
#==============
def auditChecksFullWrapper():
    logging.info(f"Begining Audit Checks [ FULL AUDIT ]")

    overall_scan_info = {}

    #------------
    # Create initial json string
    #------------
    # Audit Test Information
    #audit_metadata_dict = metaDataGenerator()
    overall_scan_info["scan_metadata"] = metaDataGenerator()

    #=============================================
    # Audit Checks
    #=============================================
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

    #=============================================
    # Create audit dictionary and translate to json
    #=============================================
    # Provide summary (total checks, total pass, total fail, total warning?)
    overall_scan_info["audit_checks"] = audit_checks

    # Create test count summary dict
    global PASSES
    global FAILURES
    global WARNINGS
    global TOTAL_CHECKS
    overall_tc_summary_dict = {
        "Total_Checks" : TOTAL_CHECKS,
        "Total_Pass" : PASSES,
        "Total_Fail" : FAILURES,
        "Total_Warn" : WARNINGS
    }

    # Add the test case summary to the overall_scan_info dict
    overall_scan_info["audit_summary"] = overall_tc_summary_dict 

    # Create the JSON output
    audit_ouput_json = json.dumps(overall_scan_info, indent=4)

    #=============================================
    # Output
    #=============================================
    # If print to stdout only
    if PRINT:
        # Once complete - output counts
        logging.info(f"Total Checks : {TOTAL_CHECKS} || Total Pass : {PASSES} || Total Fail : {FAILURES} || Total Warnings : {WARNINGS}")
        #reportOutput(overall_scan_info, 0)
        reportOutput(overall_scan_info, 0, "")

    else:
        basename = os.path.basename(OUTPUT)
        # Create output
        try:
            with open(OUTPUT, "w") as file:
                file.write(audit_ouput_json)
            logging.info(f"Writing audit report to file [ {basename} ]")
            # Once complete - output counts
            logging.info(f"Total Checks : {TOTAL_CHECKS} || Total Pass : {PASSES} || Total Fail : {FAILURES} || Total Warnings : {WARNINGS}")
        except PermissionError:
            logging.exception(f"Failed to write output to {basename} - Permissions Error")
            # Once complete - output counts
            logging.info(f"Total Checks : {TOTAL_CHECKS} || Total Pass : {PASSES} || Total Fail : {FAILURES} || Total Warnings : {WARNINGS}")
            # Print to stdout if error writing
            print(audit_ouput_json)
        except IOError as e:
            logging.exception(f"Failed to write output to {basename} - I/O Error [ {e} ]")
            # Once complete - output counts
            logging.info(f"Total Checks : {TOTAL_CHECKS} || Total Pass : {PASSES} || Total Fail : {FAILURES} || Total Warnings : {WARNINGS}")
            # Print to stdout if error writing
            print(audit_ouput_json)
        except Exception as e:
            logging.exception(f"Failed to write output to {basename} - Unexpeced Error [ {e} ]")
            # Once complete - output counts
            logging.info(f"Total Checks : {TOTAL_CHECKS} || Total Pass : {PASSES} || Total Fail : {FAILURES} || Total Warnings : {WARNINGS}")
            # Print to stdout if error writing
            print(audit_ouput_json)


#==============
# Report Output to STDOUT
#==============
def reportOutput(audit_report_dict, indent_count, calling_check):

    indent_spaces = "  "
    current_indent = indent_count + 1

    if indent_count == 0:
        indent = ""
    else:
        indent = indent_spaces * current_indent

    # Iterate through the keys / values
    #   Call recursively for nested dictionaries
    for key, value in audit_report_dict.items(): 

        # Determine if there is a nested dictionary
        #   If yes - recursive call to this output function
        #   else - output
        if isinstance(value, dict):
            #print(f"{indent}{key}")
            if calling_check != "":
                new_calling_check = f"{calling_check} : {key}"
            else:
                new_calling_check = f"{key}"
            reportOutput(value, current_indent, new_calling_check)
        else:
            if key == "status":
                #print(f"{indent}{key} : {value} ")
                print(f"[{value}] {calling_check}")

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
            logging.debug("Operating System determined to be Ubuntu/Debian")
        elif "ID=rhel" in os_contents or "ID=centos" in os_contents or "ID=rocky" in os_contents or "ID=almalinux" in os_contents:
            os_rc_ret = True
            logging.debug("Operating System determined to be RHEL/CentOS")
        elif "ID_LIKE=debian" in os_contents:
            os_ud_ret = True
            logging.debug("Operating System determined to be Ubuntu/Debian")

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
            ret_str = ifile.read()
            logging.debug(f"\tReading in file [ {file_path} ]")
    except FileNotFoundError:
        logging.exception(f"Error: File was not found [ {file_path} ]")
    except PermissionError:
        logging.exception(f"Error: Permissions error for file [ {file_path} ]")
    except Exception as e:
        logging.exception(f"Unexpected error while reading file [ {e} ]")

    # Return the string
    return ret_str

#==============
# 'Ingest' file to search for and isolate particular line / string
#==============
def isolateStringInFile(passed_path, search_array):

    logging.debug(f"\t\tPreparing for string isolation in file[ {passed_path} ]")

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
                    if search_str in line:
                        ret_strings.append(line.strip())
                        break

            logging.debug(f"\t\tSearching file for search string [ {search_str} ]")

    except FileNotFoundError:
        logging.exception(f"Error: File was not found [ {file_path} ]")
    except PermissionError:
        logging.exception(f"Error: Permissions error for file [ {file_path} ]")
    except Exception as e:
        logging.exception(f"Unexpected error while reading file [ {e} ]")

    # Return the string
    return ret_strings

#==============
# Grabs system information for the test 
#==============
def metaDataGenerator():
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
    global PASSES
    global FAILURES
    global WARNINGS
    global TOTAL_CHECKS

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
        #formatter_class = argparse.RawTextHelpFormatter,
        epilog = textwrap.dedent(f'''
            Examples:
                Show options associated with script
                    => python3 {script_version} -h
                
                Run full audit suite
                    => python3 {script_version} audit -f
                
                Run selected audit checks (e.g. firewall, kernel/system, services)
                    => python3 {script_version} audit -s f k s
            '''))

    # Start considering logging
    global verbose_logging
    verbose_logging = False

    # Set some 'global' options
    global_parser = argparse.ArgumentParser(add_help=False, formatter_class = argparse.RawTextHelpFormatter)
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
    audit_parser = subparsers.add_parser('audit', help = 'Strictly Audit the System Configurations', parents=[global_parser], formatter_class=argparse.RawTextHelpFormatter)

    # Create the required group
    audit_req = audit_parser.add_argument_group("required - audit type")

    # Can select full OR subset
    audit_type = audit_req.add_mutually_exclusive_group(required=True)

    # Full Audit
    audit_type.add_argument('-f', '--full', action='store_true', help='Complete all audit checks')

    # Subset audit
    audit_type.add_argument(
        '-s', 
        '--subset', 
        type=str.lower,
        #metavar='CHECKS',
        choices=['a', 'c', 'f', 'k', 'l', 'p', 'r', 's', 'u'], 
        # allow multiple options to be selected
        nargs='+', 
        #help = '''
        help = textwrap.dedent('''\
    Audit Checks Available:
        a : auto-updates enabled
        c : credential / password policy
        f : firewall
        k : kernel / system
        l : logging / auditing
        p : permissions (files)
        r : remote / SSH
        s : services
        u : user-privileges''')
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
    PRINT = True if args.print else False

    # Determine output name (if defined or generated)
    if not PRINT:
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

    #-------------
    # Info
    #-------------
    if args.subcommand == 'info':
        outputAuditCheckInformation()

    #-------------
    # Audit Only
    #-------------
    elif args.subcommand == 'audit':

        # Determine OS (UD = ubuntu/debian; RC = RHEL/CentOS)
        global OS_UD
        global OS_RC
        OS_UD, OS_RC = getOSType()

        # Determine Audit Type
        if args.full:
            auditChecksFullWrapper()
        else:
            auditChecksSubsetWrapper(args.subset)
    
if __name__ == "__main__":
    main()








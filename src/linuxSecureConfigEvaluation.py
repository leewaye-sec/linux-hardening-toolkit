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

#==============
# 'Quick' Output for Audit Checks that can be performed
#   Will also indicate if particular checks can be remediated
#==============
def outputAuditCheckInformation():
    logging.info(f"Audit Check Information")

#==============
# Wrapper for Audit Checks
#==============
def auditChecksWrapper():
    logging.info(f"Begining Audit Checks")

#==============
# Wrapper for Remediation Checks and Steps
#==============
def remediateWrapper():
    logging.info(f"Begining Remediation")

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
    # Info
    #-------------
    if args.subcommand == 'info':
        #outputAuditCheckInformation()
        print(f"PRINTING INFO")

    #-------------
    # Audit Only
    #-------------
    elif args.subcommand == 'audit':
        #auditChecksWrapper()
        print(f"AUDIT TREE")

    #-------------
    # Audit and Remediation
    #-------------
    elif args.subcommand == 'remediate':
        print(f"REMEDIATION TREE")

if __name__="__main__":
    main()








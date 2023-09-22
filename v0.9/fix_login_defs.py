#!/usr/bin/env python

import os

# Check if the script is being run as root
if os.geteuid() != 0:
    print("This script must be run as root")
    exit(1)

# File path for login.defs
LOGIN_DEFS = "/etc/login.defs"

def fix_login_defs():
    try:
        # Check if the configuration file exists
        if not os.path.exists(LOGIN_DEFS):
            print("login.defs file does not exist.")
            exit(1)
        
        # Backup the original configuration file
        backup_file = LOGIN_DEFS + ".bak"
        os.system("cp -p {} {}".format(LOGIN_DEFS, backup_file))
        print("Backed up the original login.defs file to " + backup_file)
        
        # Open the configuration file for reading
        with open(LOGIN_DEFS, "r") as f:
            lines = f.readlines()
        
        # Modify PASS_MAX_DAYS to set the value to 90
        modified_lines = []
        for line in lines:
            if line.startswith("PASS_MAX_DAYS"):
                line = "PASS_MAX_DAYS 90\n"
            modified_lines.append(line)
        
        # Write the modified content to the configuration file
        with open(LOGIN_DEFS, "w") as f:
            f.writelines(modified_lines)
        
        print("login.defs configuration updated successfully.")
    except Exception as e:
        print("An error occurred: " + str(e))

if __name__ == "__main__":
    fix_login_defs()

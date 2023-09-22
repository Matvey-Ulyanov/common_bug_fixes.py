#!/usr/bin/env python

import os

# Check if the script is being run as root
if os.geteuid() != 0:
    print("This script must be run as root")
    exit(1)

# File path for system-auth configuration
SYSTEM_AUTH_CONF = "/etc/pam.d/system-auth"

def fix_password_reuse():
    try:
        # Check if the configuration file exists
        if not os.path.exists(SYSTEM_AUTH_CONF):
            print("system-auth configuration file does not exist.")
            exit(1)
        
        # Backup the original configuration file
        backup_file = SYSTEM_AUTH_CONF + ".bak"
        os.system("cp -p {} {}".format(SYSTEM_AUTH_CONF, backup_file))
        print("Backed up the original configuration file to " + backup_file)
        
        # Open the configuration file for reading
        with open(SYSTEM_AUTH_CONF, "r") as f:
            lines = f.readlines()
        
        # Modify password configuration to limit reuse
        modified_lines = []
        for line in lines:
            if "password sufficient" in line:
                line = line.rstrip() + " remember=5\n"
            modified_lines.append(line)
        
        # Write the modified content to the configuration file
        with open(SYSTEM_AUTH_CONF, "w") as f:
            f.writelines(modified_lines)
        
        print("Password reuse configuration updated successfully.")
    except Exception as e:
        print("An error occurred: " + str(e))

if __name__ == "__main__":
    fix_password_reuse()

#!/usr/bin/env python

import os

# Check if the script is being run as root
if os.geteuid() != 0:
    print("This script must be run as root")
    exit(1)

# File path for pwquality.conf
PWQUALITY_CONF = "/etc/security/pwquality.conf"

def fix_pwquality_conf():
    try:
        # Check if the configuration file exists
        if not os.path.exists(PWQUALITY_CONF):
            print("pwquality.conf file does not exist.")
            exit(1)
        
        # Backup the original configuration file
        backup_file = PWQUALITY_CONF + ".bak"
        os.system("cp -p {} {}".format(PWQUALITY_CONF, backup_file))
        print("Backed up the original pwquality.conf file to " + backup_file)
        
        # Open the configuration file for reading
        with open(PWQUALITY_CONF, "r") as f:
            lines = f.readlines()
        
        # Modify minclass to require at least 3 character classes
        modified_lines = []
        for line in lines:
            if line.startswith("minclass"):
                line = "minclass=3\n"
            modified_lines.append(line)
        
        # Write the modified content to the configuration file
        with open(PWQUALITY_CONF, "w") as f:
            f.writelines(modified_lines)
        
        print("pwquality.conf configuration updated successfully.")
    except Exception as e:
        print("An error occurred: " + str(e))

if __name__ == "__main__":
    fix_pwquality_conf()

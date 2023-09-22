#!/usr/bin/env python

import os

# Check if the script is being run as root
if os.geteuid() != 0:
    print("This script must be run as root")
    exit(1)

# File path for pure-ftpd configuration
PURE_FTPD_CONF = "/www/server/pure-ftpd/etc/pure-ftpd.conf"

def fix_pure_ftpd_config():
    try:
        # Check if the configuration file exists
        if not os.path.exists(PURE_FTPD_CONF):
            print("Pure-FTPd configuration file does not exist.")
            exit(1)
        
        # Backup the original configuration file
        backup_file = PURE_FTPD_CONF + ".bak"
        os.rename(PURE_FTPD_CONF, backup_file)
        print("Backed up the original configuration file to " + backup_file)
        
        # Open the backup file for reading
        with open(backup_file, "r") as f:
            lines = f.readlines()
        
        # Modify Umask value or add it if not present
        modified_lines = []
        umask_updated = False
        for line in lines:
            if line.startswith("Umask "):
                modified_lines.append("Umask 177:077\n")
                umask_updated = True
            else:
                modified_lines.append(line)
        
        if not umask_updated:
            modified_lines.append("Umask 177:077\n")
        
        # Write the modified content to the configuration file
        with open(PURE_FTPD_CONF, "w") as f:
            f.writelines(modified_lines)
        
        print("Pure-FTPd configuration updated successfully.")
    except Exception as e:
        print("An error occurred: " + str(e))

if __name__ == "__main__":
    fix_pure_ftpd_config()

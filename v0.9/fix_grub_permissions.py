#!/usr/bin/env python

import os

# Check if the script is being run as root
if os.geteuid() != 0:
    print("This script must be run as root")
    exit(1)

# File paths
GRUB_CFG = "/boot/grub2/grub.cfg"

def fix_permissions():
    try:
        # Correct permissions and ownership
        print("Fixing permissions and ownership for {}...".format(GRUB_CFG))
        os.chmod(GRUB_CFG, 0o600)
        os.chown(GRUB_CFG, 0, 0)
        print("Permissions and ownership for {} have been updated successfully.".format(GRUB_CFG))
    except Exception as e:
        print("An error occurred: {}".format(e))

if __name__ == "__main__":
    fix_permissions()

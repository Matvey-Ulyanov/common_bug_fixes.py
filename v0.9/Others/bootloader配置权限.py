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
        print(f"Fixing permissions and ownership for {GRUB_CFG}...")
        os.chmod(GRUB_CFG, 0o600)
        os.chown(GRUB_CFG, 0, 0)
        print(f"Permissions and ownership for {GRUB_CFG} have been updated successfully.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    fix_permissions()

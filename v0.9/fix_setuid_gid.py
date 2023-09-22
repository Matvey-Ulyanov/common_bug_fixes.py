#!/usr/bin/env python

import os

# Check if the script is being run as root
if os.geteuid() != 0:
    print("This script must be run as root")
    exit(1)

# List of files with sid privileges
FILES = [
    "/usr/bin/chage", "/usr/bin/gpasswd", "/usr/bin/wall",
    "/usr/bin/chfn", "/usr/bin/chsh", "/usr/bin/newgrp",
    "/usr/bin/write", "/usr/sbin/usernetctl", "/bin/mount",
    "/bin/umount", "/sbin/netreport"
]

def fix_setuid_gid():
    try:
        # Loop through files and remove sid privilege
        for file in FILES:
            if os.path.exists(file):
                print("Removing setuid/setgid privilege from {}...".format(file))
                os.system("chmod u-s {}".format(file))
                os.system("chmod g-s {}".format(file))
                print("Setuid/setgid privilege removed from {}.".format(file))
            else:
                print("File {} does not exist.".format(file))
        
        print("Fixing setuid/setgid privileges completed.")
    except Exception as e:
        print("An error occurred: {}".format(e))

if __name__ == "__main__":
    fix_setuid_gid()

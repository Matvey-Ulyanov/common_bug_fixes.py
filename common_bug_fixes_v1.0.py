#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

def add_to_hosts_allow(ip_address):
    hosts_allow_path = '/etc/hosts.allow'
    entry = 'sshd: {}'.format(ip_address)

    with open(hosts_allow_path, 'a') as f:
        f.write(entry + '\n')
    print('Added [{}] to [{}].'.format(entry, hosts_allow_path))

def main():
    ip_address = raw_input("Enter the allowed IP address: ")  # Python 2.7 uses raw_input
    add_to_hosts_allow(ip_address)

if __name__ == '__main__':
    main()

#!/usr/bin/env python
# -*- coding: utf-8 -*-

def analyze_ssh_supported_algorithms(output):
    supported_algorithms = {}

    sections = output.split('\n\n')
    for section in sections:
        lines = section.strip().split('\n')
        category = lines[0]
        algorithms = [algo.strip() for algo in lines[1:]]

        supported_algorithms[category] = algorithms

    return supported_algorithms

def main():
    # Replace this with the actual output from the vulnerability scan
    vulnerability_output = """
    ... (paste the output here)
    """

    algorithms_info = analyze_ssh_supported_algorithms(vulnerability_output)

    for category, algorithms in algorithms_info.items():
        print('The server supports the following options for {} :'.format(category))
        for algo in algorithms:
            print('  ' + algo)
        print()

if __name__ == '__main__':
    main()

#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

def enable_ssh_encryption():
    sshd_config_path = '/etc/ssh/sshd_config'
    new_sshd_config_lines = []
    protocol_line = 'Protocol 2'

    with open(sshd_config_path, 'r') as f:
        lines = f.readlines()

        protocol_line_found = False
        for line in lines:
            if line.strip().startswith('Protocol'):
                new_sshd_config_lines.append(protocol_line + '\n')
                protocol_line_found = True
            else:
                new_sshd_config_lines.append(line)

        if not protocol_line_found:
            new_sshd_config_lines.append(protocol_line + '\n')
            print('Added encryption setting to [{}].'.format(sshd_config_path))
        else:
            print('Encryption setting is already configured.')

    with open(sshd_config_path, 'w') as f:
        f.writelines(new_sshd_config_lines)

def restart_sshd_service():
    os.system('systemctl restart sshd')
    print('SSH service has been restarted.')

def main():
    enable_ssh_encryption()
    restart_sshd_service()

if __name__ == '__main__':
    main()

#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

def fix_ls_alias():
    bashrc_path = os.path.expanduser('~/.bashrc')
    new_bashrc_lines = []
    aliases = {
        'ls': 'alias ls=\'ls -alh\'',
        'rm': 'alias rm=\'rm -i\''
    }

    with open(bashrc_path, 'r') as f:
        lines = f.readlines()

        for line in lines:
            if any(line.startswith(alias) for alias in aliases):
                continue
            new_bashrc_lines.append(line)

        for alias_name, alias_command in aliases.items():
            new_bashrc_lines.append(alias_command + '\n')

    with open(bashrc_path, 'w') as f:
        f.writelines(new_bashrc_lines)
    print('Aliases have been added/updated in [{}].'.format(bashrc_path))

def apply_bashrc():
    os.system('source ~/.bashrc')
    print('bashrc changes have been applied.')

def main():
    fix_ls_alias()
    apply_bashrc()

if __name__ == '__main__':
    main()

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

#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

def fix_login_defs():
    login_defs_path = '/etc/login.defs'
    new_login_defs_lines = []
    updated_line = None

    with open(login_defs_path, 'r') as f:
        lines = f.readlines()

        for line in lines:
            if line.startswith('PASS_MIN_DAYS'):
                min_days = int(line.split()[1])
                if min_days < 7:
                    new_login_defs_lines.append('PASS_MIN_DAYS   7\n')
                    updated_line = 'PASS_MIN_DAYS'
                else:
                    new_login_defs_lines.append(line)
            else:
                new_login_defs_lines.append(line)

    if updated_line:
        with open(login_defs_path, 'w') as f:
            f.writelines(new_login_defs_lines)
        print('[{}] in [{}] has been updated.'.format(updated_line, login_defs_path))

def set_root_password_expiry():
    os.system('chage --mindays 7 root')
    print('Root password expiry has been set to 7 days.')

def main():
    fix_login_defs()
    set_root_password_expiry()

if __name__ == '__main__':
    main()

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

#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

def fix_ssh_cbc_vulnerability():
    sshd_config_path = '/etc/ssh/sshd_config'
    cbc_algorithms = [
        '3des-cbc',
        'aes128-cbc',
        'aes192-cbc',
        'aes256-cbc',
        'blowfish-cbc',
        'cast128-cbc'
    ]
    
    new_sshd_config_lines = []

    with open(sshd_config_path, 'r') as f:
        lines = f.readlines()

        for line in lines:
            if line.strip().startswith('Ciphers'):
                for algorithm in cbc_algorithms:
                    if algorithm in line:
                        line = line.replace(algorithm, '')
                if line.strip().endswith(','):
                    line = line.rstrip(',') + '\n'
            new_sshd_config_lines.append(line)

    with open(sshd_config_path, 'w') as f:
        f.writelines(new_sshd_config_lines)
    
    print('CBC mode ciphers have been disabled in [{}].'.format(sshd_config_path))
    print('Please remember to restart the SSH service for the changes to take effect.')

def main():
    fix_ssh_cbc_vulnerability()

if __name__ == '__main__':
    main()

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

#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

def fix_ssh_sha1_hmac_vulnerability():
    sshd_config_path = '/etc/ssh/sshd_config'
    sha1_hmac_algorithms = [
        'hmac-sha1',
        'hmac-sha1-etm@openssh.com'
    ]
    
    new_sshd_config_lines = []

    with open(sshd_config_path, 'r') as f:
        lines = f.readlines()

        for line in lines:
            if line.strip().startswith('MACs'):
                for algorithm in sha1_hmac_algorithms:
                    if algorithm in line:
                        line = line.replace(algorithm, '')
                if line.strip().endswith(','):
                    line = line.rstrip(',') + '\n'
            new_sshd_config_lines.append(line)

    with open(sshd_config_path, 'w') as f:
        f.writelines(new_sshd_config_lines)
    
    print('SHA-1 HMAC algorithms have been disabled in [{}].'.format(sshd_config_path))
    print('Please remember to restart the SSH service for the changes to take effect.')

def main():
    fix_ssh_sha1_hmac_vulnerability()

if __name__ == '__main__':
    main()

#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

def fix_command_timeout():
    profile_path = '/etc/profile'
    new_profile_lines = []
    added_line = 'TMOUT=300'

    with open(profile_path, 'r') as f:
        lines = f.readlines()

        timeout_line_found = False
        for line in lines:
            if line.startswith('TMOUT='):
                timeout_line_found = True
                new_profile_lines.append(added_line + '\n')
            else:
                new_profile_lines.append(line)

        if not timeout_line_found:
            new_profile_lines.append(added_line + '\n')

    with open(profile_path, 'w') as f:
        f.writelines(new_profile_lines)
    print('[{}] has been updated with command timeout setting.'.format(profile_path))

def apply_profile():
    os.system('source /etc/profile')
    print('Profile changes have been applied.')

def main():
    fix_command_timeout()
    apply_profile()

if __name__ == '__main__':
    main()

#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

def fix_weak_ssh_key_exchange():
    sshd_config_path = '/etc/ssh/sshd_config'
    weak_algorithms = [
        'diffie-hellman-group-exchange-sha1',
        'diffie-hellman-group1-sha1'
    ]
    
    new_sshd_config_lines = []

    with open(sshd_config_path, 'r') as f:
        lines = f.readlines()

        for line in lines:
            if line.strip().startswith('KexAlgorithms'):
                for algorithm in weak_algorithms:
                    if algorithm in line:
                        line = line.replace(algorithm, '')
                if line.strip().endswith(','):
                    line = line.rstrip(',') + '\n'
            new_sshd_config_lines.append(line)

    with open(sshd_config_path, 'w') as f:
        f.writelines(new_sshd_config_lines)
    
    print('Weak key exchange algorithms have been disabled in [{}].'.format(sshd_config_path))
    print('Please remember to restart the SSH service for the changes to take effect.')

def main():
    fix_weak_ssh_key_exchange()

if __name__ == '__main__':
    main()

#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

def limit_password_reuse():
    system_auth_path = '/etc/pam.d/system-auth'
    backup_path = '/etc/pam.d/system-auth.bak'
    new_system_auth_lines = []
    added_line = 'password sufficient pam_unix.so remember=5'

    # Backup the original file if not done already
    if not os.path.exists(backup_path):
        os.system('cp -p {} {}'.format(system_auth_path, backup_path))

    with open(system_auth_path, 'r') as f:
        lines = f.readlines()

        remember_line_found = False
        for line in lines:
            new_system_auth_lines.append(line)
            if line.strip().startswith('password sufficient') and 'remember=' not in line:
                new_system_auth_lines.append(added_line + '\n')
                remember_line_found = True

        if not remember_line_found:
            new_system_auth_lines.append(added_line + '\n')
            print('Added password reuse limitation to [{}].'.format(system_auth_path))
        else:
            print('Password reuse limitation is already configured.')

    with open(system_auth_path, 'w') as f:
        f.writelines(new_system_auth_lines)

def main():
    limit_password_reuse()

if __name__ == '__main__':
    main()

#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

def limit_password_reuse():
    system_auth_path = '/etc/pam.d/system-auth'
    backup_path = '/etc/pam.d/system-auth.bak'
    new_system_auth_lines = []
    added_line = 'password sufficient pam_unix.so remember=5'

    # Backup the original file if not done already
    if not os.path.exists(backup_path):
        os.system('cp -p {} {}'.format(system_auth_path, backup_path))

    with open(system_auth_path, 'r') as f:
        lines = f.readlines()

        remember_line_found = False
        for line in lines:
            new_system_auth_lines.append(line)
            if line.strip().startswith('password sufficient') and 'remember=' not in line:
                new_system_auth_lines.append(added_line + '\n')
                remember_line_found = True

        if not remember_line_found:
            new_system_auth_lines.append(added_line + '\n')
            print('Added password reuse limitation to [{}].'.format(system_auth_path))
        else:
            print('Password reuse limitation is already configured.')

    with open(system_auth_path, 'w') as f:
        f.writelines(new_system_auth_lines)

def main():
    limit_password_reuse()

if __name__ == '__main__':
    main()

#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

def limit_password_reuse():
    system_auth_path = '/etc/pam.d/system-auth'
    backup_path = '/etc/pam.d/system-auth.bak'
    new_system_auth_lines = []
    added_line = 'password sufficient pam_unix.so remember=5'

    # Backup the original file if not done already
    if not os.path.exists(backup_path):
        os.system('cp -p {} {}'.format(system_auth_path, backup_path))

    with open(system_auth_path, 'r') as f:
        lines = f.readlines()

        remember_line_found = False
        for line in lines:
            new_system_auth_lines.append(line)
            if line.strip().startswith('password sufficient') and 'remember=' not in line:
                new_system_auth_lines.append(added_line + '\n')
                remember_line_found = True

        if not remember_line_found:
            new_system_auth_lines.append(added_line + '\n')
            print('Added password reuse limitation to [{}].'.format(system_auth_path))
        else:
            print('Password reuse limitation is already configured.')

    with open(system_auth_path, 'w') as f:
        f.writelines(new_system_auth_lines)

def main():
    limit_password_reuse()

if __name__ == '__main__':
    main()

# coding=utf-8
import ntplib
from datetime import datetime
import os

def set_system_time(new_time):
    os.system("sudo date -s '{}'".format(new_time.strftime('%Y-%m-%d %H:%M:%S')))

def main():
    ntp_server = 'pool.ntp.org'  # You can change this to a different NTP server if needed

    try:
        client = ntplib.NTPClient()
        response = client.request(ntp_server, version=3)
        network_time = datetime.fromtimestamp(response.tx_time)
        print "Network time:", network_time
        
        set_system_time(network_time)
        print "System time adjusted."
    except Exception as e:
        print "An error occurred:", e

if __name__ == "__main__":
    main()

print("所有列表内安全漏洞和配置信息已更改")

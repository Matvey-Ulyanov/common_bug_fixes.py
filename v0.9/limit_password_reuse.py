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

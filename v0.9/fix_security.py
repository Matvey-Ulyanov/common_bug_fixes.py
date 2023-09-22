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

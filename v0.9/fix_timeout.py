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

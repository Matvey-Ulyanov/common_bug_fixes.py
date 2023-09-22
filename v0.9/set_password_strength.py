#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

def set_password_strength():
    pwquality_conf_path = '/etc/security/pwquality.conf'
    new_pwquality_conf_lines = []
    minclass_line = 'minclass = 3'

    with open(pwquality_conf_path, 'r') as f:
        lines = f.readlines()

        minclass_line_found = False
        for line in lines:
            if line.strip().startswith('minclass'):
                new_pwquality_conf_lines.append(minclass_line + '\n')
                minclass_line_found = True
            else:
                new_pwquality_conf_lines.append(line)

        if not minclass_line_found:
            new_pwquality_conf_lines.append(minclass_line + '\n')
            print('[{}] has been updated with password strength settings.'.format(pwquality_conf_path))
        else:
            print('Password strength settings are already configured.')

    with open(pwquality_conf_path, 'w') as f:
        f.writelines(new_pwquality_conf_lines)

def main():
    set_password_strength()

if __name__ == '__main__':
    main()

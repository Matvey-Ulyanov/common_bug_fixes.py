#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

def enable_tcp_syncookies():
    sysctl_conf_path = '/etc/sysctl.conf'
    new_sysctl_lines = []
    added_line = 'net.ipv4.tcp_syncookies=1'

    with open(sysctl_conf_path, 'r') as f:
        lines = f.readlines()

        syncookies_line_found = False
        for line in lines:
            if line.strip() == added_line:
                syncookies_line_found = True
                break

        if not syncookies_line_found:
            lines.append(added_line + '\n')
            with open(sysctl_conf_path, 'w') as f:
                f.writelines(lines)
            print('[{}] has been updated to enable TCP-SYNcookie protection.'.format(sysctl_conf_path))
        else:
            print('TCP-SYNcookie protection is already enabled.')

def apply_sysctl():
    os.system('sysctl -p')
    print('sysctl changes have been applied.')

def main():
    enable_tcp_syncookies()
    apply_sysctl()

if __name__ == '__main__':
    main()

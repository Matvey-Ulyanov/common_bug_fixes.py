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

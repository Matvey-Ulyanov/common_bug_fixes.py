#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

def set_ssh_idle_timeout():
    sshd_config_path = '/etc/ssh/sshd_config'
    new_sshd_config_lines = []
    client_alive_interval = 'ClientAliveInterval 600'

    with open(sshd_config_path, 'r') as f:
        lines = f.readlines()

        for line in lines:
            if line.strip().startswith('ClientAliveInterval'):
                new_sshd_config_lines.append(client_alive_interval + '\n')
            else:
                new_sshd_config_lines.append(line)

    with open(sshd_config_path, 'w') as f:
        f.writelines(new_sshd_config_lines)
    print('SSH idle timeout has been set in [{}].'.format(sshd_config_path))

def restart_sshd_service():
    os.system('service sshd restart')
    print('SSH service has been restarted.')

def main():
    set_ssh_idle_timeout()
    restart_sshd_service()

if __name__ == '__main__':
    main()

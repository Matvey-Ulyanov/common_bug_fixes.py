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

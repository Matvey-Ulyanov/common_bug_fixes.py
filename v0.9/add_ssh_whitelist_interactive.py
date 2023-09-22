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

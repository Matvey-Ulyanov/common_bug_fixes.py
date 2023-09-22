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

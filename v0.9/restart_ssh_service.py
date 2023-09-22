#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

def restart_ssh_service():
    os.system('systemctl restart sshd')

def main():
    print("为了确保更改的设置得到应用，可能需要重启SSH服务。")
    choice = raw_input("是否确认要进行重启？ (Y/N): ")  # Python 2.7 uses raw_input

    if choice.lower() == 'y':
        restart_ssh_service()
    elif choice.lower() == 'n':
        print("未执行任何操作。")
    else:
        print("无效的选项。")

if __name__ == '__main__':
    main()

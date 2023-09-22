#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

def main():
    print("为了确保这些操作完全进行，需要进行重启。")
    choice = raw_input("是否要现在重启？ (Y/N): ")  # Python 2.7 uses raw_input

    if choice.lower() == 'y':
        os.system('reboot')
    elif choice.lower() == 'n':
        print("未执行任何操作。")
    else:
        print("无效的选项。")

if __name__ == '__main__':
    main()

# -*- coding: utf-8 -*-
#!/usr/bin/python

import os

# 配置文件路径
sshd_config_path = '/etc/ssh/sshd_config'

# 弱密钥交换算法列表
weak_algorithms = [
    'diffie-hellman-group-exchange-sha1',
    'diffie-hellman-group1-sha1',
    'gss-gex-sha1-*',
    'gss-group1-sha1-*',
    'gss-group14-sha1-*',
    'rsa1024-sha1'
]

def disable_weak_algorithms():
    try:
        with open(sshd_config_path, 'r') as f:
            lines = f.readlines()

        with open(sshd_config_path, 'w') as f:
            for line in lines:
                # 检查每一行是否包含弱密钥交换算法
                if not any(weak_algorithm in line for weak_algorithm in weak_algorithms):
                    f.write(line)

        print("弱密钥交换算法已禁用。")
    except Exception as e:
        print("发生错误：", e)

if __name__ == '__main__':
    # 检查脚本是否以root权限运行
    if os.geteuid() == 0:
        disable_weak_algorithms()
    else:
        print("请以root权限运行此脚本以修改配置文件。")

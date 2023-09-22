# -*- coding: utf-8 -*-

import subprocess
import time

# 重启SSH服务
def restart_ssh():
    try:
        subprocess.check_call(["service", "sshd", "restart"])
        print("SSH服务已重启")
    except subprocess.CalledProcessError:
        print("无法重启SSH服务")

# 询问用户是否重启SSH服务
def ask_to_restart_ssh():
    user_input = raw_input("一些配置信息的更改需要重启SSH服务后生效，是否重启SSH服务？(Y/N): ")
    return user_input.lower() == "y"

# 等待SSH服务重启完成
def wait_for_ssh():
    max_retries = 30
    retry_count = 0
    while retry_count < max_retries:
        time.sleep(5)
        try:
            subprocess.check_call(["ssh", "-q", "localhost", "exit"])
            print("SSH服务已启动")
            break
        except subprocess.CalledProcessError:
            print("等待SSH服务启动...")
            retry_count += 1
    else:
        print("无法启动SSH服务")
        return False
    return True

# 重启服务器
def reboot_server():
    try:
        subprocess.check_call(["reboot"])
    except subprocess.CalledProcessError:
        print("无法重启服务器")

# 询问用户是否重启服务器
def ask_to_reboot_server():
    user_input = raw_input("一些配置信息的更改需要重服务器后生效，是否重启服务器？(Y/N): ")
    return user_input.lower() == "y"

if __name__ == "__main__":
    print("开始重启SSH服务...")
    
    if ask_to_restart_ssh():
        restart_ssh()
    
    if wait_for_ssh():
        print("SSH服务已重启完成")
        
        print("准备重启服务器...")
        
        if ask_to_reboot_server():
            reboot_server()
        else:
            print("未重启服务器")
    else:
        print("未能完成服务器重启操作")

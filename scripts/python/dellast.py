#!/usr/bin/python2
# -*- coding: utf-8 -*-

import subprocess
import sys

def main(num):
    # 执行utmpdump命令并将输出重定向到/var/log/wtmp.file
    utmpdump_command = "utmpdump /var/log/wtmp >/var/log/wtmp.file"
    subprocess.call(utmpdump_command, shell=True)

    # 从文件末尾删除指定行数
    with open('/var/log/wtmp.file', 'r') as file:
        lines = file.readlines()

    if len(lines) >= num:
        lines = lines[:-num]
    else:
        lines = []

    with open('/var/log/wtmp.file', 'w') as file:
        file.writelines(lines)

    # 执行utmpdump -r命令以还原文件，并删除临时文件
    utmprestore_command = "utmpdump -r < /var/log/wtmp.file > /var/log/wtmp && rm -f /var/log/wtmp.file"
    subprocess.call(utmprestore_command, shell=True)
    print("执行完成，当前最新last日志10行：\n")
    checklast_command = "last -10"
    subprocess.call(checklast_command, shell=True)


# 系统函数,为了获取输入参数
def get_script_param(key):
    input_str = 'THIS IS FOR INPUT STR TO REPLACE,DO NOT CHANGE THIS STRING'
    try:
        dict_params = json.loads(base64.b64decode(input_str))
        return dict_params.get(key)
    except Exception as E:
        return None


# main函数部分,为了确保windows的python插件能直接执行,不要放在if __name__=="__main__":函数中
num = 1
# 获取输入参数
if get_script_param('NUM') is not None:
    num = get_script_param('num')
# 开始运行
main(num)

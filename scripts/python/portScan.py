# -*- coding: utf-8 -*-

import base64
import json
import socket
import threading
import time
from socket import AF_INET, SOCK_STREAM

try:
    from queue import Queue
except Exception as E:
    import Queue


def add_port_banner(result_queue, host, port, proto):
    result_queue.put({'host': host, 'port': port, 'proto': proto})


def dqtoi(dq):
    """ip地址转数字."""
    octets = dq.split(".")
    if len(octets) != 4:
        raise ValueError
    for octet in octets:
        if int(octet) > 255:
            raise ValueError
    return (int(octets[0]) << 24) + \
           (int(octets[1]) << 16) + \
           (int(octets[2]) << 8) + \
           (int(octets[3]))


def itodq(intval):
    "Return a dotted-quad string given an integer. "
    return "%u.%u.%u.%u" % ((intval >> 24) & 0x000000ff,
                            ((intval & 0x00ff0000) >> 16),
                            ((intval & 0x0000ff00) >> 8),
                            (intval & 0x000000ff))


class Timeout(Exception):
    pass


# Scan code from here


class ScanTheard(threading.Thread):
    def __init__(self, req_queue, result_queue):
        super(ScanTheard, self).__init__()
        self.req_queue = req_queue
        self.result_queue = result_queue

    def run(self):
        while self.req_queue.empty() is not True:
            try:
                req_dict = self.req_queue.get(timeout=0.05)
            except Exception as E:
                continue

            host = itodq(req_dict.get('host'))
            port = req_dict.get('port')
            if isinstance(port, int):
                try:
                    sd = socket.socket(AF_INET, SOCK_STREAM)
                    global TIME_OUT
                    global resolv
                    sd.settimeout(TIME_OUT)
                    sd.connect((host, port))

                    sd.close()
                    add_port_banner(result_queue=self.result_queue, host=host, port=port, proto="TCP")
                except Exception as E:
                    pass
            else:
                pass


def main(startip, stopip, port_list):
    start = dqtoi(startip)
    stop = dqtoi(stopip)

    try:
        req_queue = Queue.Queue()
        result_queue = Queue.Queue()
    except Exception as E:
        try:
            req_queue = Queue()
            result_queue = Queue()
        except Exception as E:
            return
    for host in range(start, stop + 1):
        for port in port_list:
            req_queue.put({'host': host, 'port': port})

    for i in range(MAX_THREADS):
        t = ScanTheard(req_queue, result_queue)
        t.start()
    while req_queue.empty() is not True:
        time.sleep(1)
    time.sleep(TIME_OUT * 3)
    result_list = []
    while result_queue.empty() is not True:
        result_list.append(result_queue.get())

    json_str = base64.b64encode(json.dumps(result_list).encode('ascii')).decode("utf-8")
    print(json_str)


# 系统函数,为了获取输入参数
def get_script_param(key):
    input_str = 'THIS IS FOR INPUT STR TO REPLACE,DO NOT CHANGE THIS STRING'
    try:
        dict_params = json.loads(base64.b64decode(input_str))
        return dict_params.get(key)
    except Exception as E:
        return {}


# main函数部分,为了确保windows的python插件能直接执行,不要放在if __name__=="__main__":函数中
global MAX_THREADS
global TIME_OUT
global resolv
TIME_OUT = 0.05
MAX_THREADS = 10
srcip = "0.0.0.0"

# 获取输入参数
if get_script_param('max_threads') is not None:
    MAX_THREADS = get_script_param('max_threads')
if get_script_param('time_out') is not None:
    TIME_OUT = get_script_param('time_out')
startip = get_script_param('startip')
stopip = get_script_param('stopip')
port_list = get_script_param('port_list')

# 开始运行
main(startip, stopip, port_list)

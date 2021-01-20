# -*- coding: utf-8 -*-

import base64
import json
import select
import socket
import string
import threading
import time
from socket import AF_INET, SOCK_STREAM

try:
    from queue import Queue
except Exception as E:
    import Queue

if not hasattr(socket, "_no_timeoutsocket"):
    _socket = socket.socket
else:
    _socket = socket._no_timeoutsocket

import os

if os.name == "nt":
    _IsConnected = (10022, 10056)
    _ConnectBusy = (10035,)
    _AcceptBusy = (10035,)
else:
    import errno

    _IsConnected = (errno.EISCONN,)
    _ConnectBusy = (errno.EINPROGRESS, errno.EALREADY, errno.EWOULDBLOCK)
    _AcceptBusy = (errno.EAGAIN, errno.EWOULDBLOCK)
    del errno
del os

_DefaultTimeout = None

Error = socket.error


def add_port_banner(result_queue, host, port, proto):
    result_queue.put({'host': host, 'port': port, 'proto': proto})


def dqtoi(dq):
    "Return an integer value given an IP address as dotted-quad string."
    octets = string.split(dq, ".")
    if len(octets) != 4:
        raise ValueError
    for octet in octets:
        if int(octet) > 255:
            raise ValueError
    return (long(octets[0]) << 24) + \
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


#
# Factory function
#


def timeoutsocket(family=AF_INET, type=SOCK_STREAM, proto=None):
    if family != AF_INET or type != SOCK_STREAM:
        if proto:
            return _socket(family, type, proto)
        else:
            return _socket(family, type)
    return TimeoutSocket(_socket(family, type), _DefaultTimeout)


# end timeoutsocket

#
# The TimeoutSocket class definition
#
class TimeoutSocket(object):
    """TimeoutSocket object
    Implements a socket-like object that raises Timeout whenever
    an operation takes too long.
    The definition of 'too long' can be changed using the
    set_timeout() method.
    """

    _copies = 0
    _blocking = 1

    def __init__(self, sock, timeout):
        self._sock = sock
        self._timeout = timeout

    # end __init__

    def __getattr__(self, key):
        return getattr(self._sock, key)

    # end __getattr__

    def get_timeout(self):
        return self._timeout

    # end set_timeout

    def set_timeout(self, timeout=None):
        self._timeout = timeout

    # end set_timeout

    def setblocking(self, blocking):
        self._blocking = blocking
        return self._sock.setblocking(blocking)

    # end set_timeout

    def connect_ex(self, addr):
        errcode = 0
        try:
            self.connect(addr)
        except Error as why:
            errcode = why[0]
        return errcode

    # end connect_ex

    def connect(self, addr, port=None, dumbhack=None):
        # In case we were called as connect(host, port)
        if port != None:
            addr = (addr, port)

        # Shortcuts
        sock = self._sock
        timeout = self._timeout
        blocking = self._blocking

        # First, make a non-blocking call to connect
        try:
            sock.setblocking(0)
            sock.connect(addr)
            sock.setblocking(blocking)
            return
        except Error as why:
            # Set the socket's blocking mode back
            sock.setblocking(blocking)

            # If we are not blocking, re-raise
            if not blocking:
                raise

            # If we are already connected, then return success.
            # If we got a genuine error, re-raise it.
            errcode = why[0]
            if dumbhack and errcode in _IsConnected:
                return
            elif errcode not in _ConnectBusy:
                raise
        # Now, wait for the connect to happen
        # ONLY if dumbhack indicates this is pass number one.
        #   If select raises an error, we pass it on.
        #   Is this the right behavior?
        if not dumbhack:
            r, w, e = select.select([], [sock], [], timeout)
            if w:
                return self.connect(addr, dumbhack=1)

        # If we get here, then we should raise Timeout
        raise Timeout("Attempted connect to %s timed out." % str(addr))

    # end connect

    def accept(self, dumbhack=None):
        # Shortcuts
        sock = self._sock
        timeout = self._timeout
        blocking = self._blocking

        # First, make a non-blocking call to accept
        #  If we get a valid result, then convert the
        #  accept'ed socket into a TimeoutSocket.
        # Be carefult about the blocking mode of ourselves.
        try:
            sock.setblocking(0)
            newsock, addr = sock.accept()
            sock.setblocking(blocking)
            timeoutnewsock = self.__class__(newsock, timeout)
            timeoutnewsock.setblocking(blocking)
            return (timeoutnewsock, addr)
        except Error as why:
            # Set the socket's blocking mode back
            sock.setblocking(blocking)

            # If we are not supposed to block, then re-raise
            if not blocking:
                raise

            # If we got a genuine error, re-raise it.
            errcode = why[0]
            if errcode not in _AcceptBusy:
                raise

        # Now, wait for the accept to happen
        # ONLY if dumbhack indicates this is pass number one.
        #   If select raises an error, we pass it on.
        #   Is this the right behavior?
        if not dumbhack:
            r, w, e = select.select([sock], [], [], timeout)
            if r:
                return self.accept(dumbhack=1)

        # If we get here, then we should raise Timeout
        raise Timeout("Attempted accept timed out.")

    # end accept

    def send(self, data, flags=0):
        sock = self._sock
        if self._blocking:
            r, w, e = select.select([], [sock], [], self._timeout)
            if not w:
                raise Timeout("Send timed out")
        return sock.send(data, flags)

    # end send

    def recv(self, bufsize, flags=0):
        sock = self._sock
        if self._blocking:
            r, w, e = select.select([sock], [], [], self._timeout)
            if not r:
                raise Timeout("Recv timed out")
        return sock.recv(bufsize, flags)

    # end recv

    def makefile(self, flags="r", bufsize=-1):
        self._copies += 1
        return TimeoutFile(self, flags, bufsize)

    # end makefile

    def close(self):
        if self._copies <= 0:
            self._sock.close()
        else:
            self._copies -= 1
    # end close


# end TimeoutSocket


class TimeoutFile(object):
    """TimeoutFile object
    Implements a file-like object on top of TimeoutSocket.
    """

    def __init__(self, sock, mode="r", bufsize=4096):
        self._sock = sock
        self._bufsize = 4096
        if bufsize > 0:
            self._bufsize = bufsize
        if not hasattr(sock, "_inqueue"):
            self._sock._inqueue = ""

    # end __init__

    def __getattr__(self, key):
        return getattr(self._sock, key)

    # end __getattr__

    def close(self):
        self._sock.close()
        self._sock = None

    # end close

    def write(self, data):
        self.send(data)

    # end write

    def read(self, size=-1):
        _sock = self._sock
        _bufsize = self._bufsize
        while 1:
            datalen = len(_sock._inqueue)
            if datalen >= size >= 0:
                break
            bufsize = _bufsize
            if size > 0:
                bufsize = min(bufsize, size - datalen)
            buf = self.recv(bufsize)
            if not buf:
                break
            _sock._inqueue = _sock._inqueue + buf
        data = _sock._inqueue
        _sock._inqueue = ""
        if 0 < size < datalen:
            _sock._inqueue = data[size:]
            data = data[:size]
        return data

    # end read

    def readline(self, size=-1):
        _sock = self._sock
        _bufsize = self._bufsize
        while 1:
            idx = string.find(_sock._inqueue, "\n")
            if idx >= 0:
                break
            datalen = len(_sock._inqueue)
            if datalen >= size >= 0:
                break
            bufsize = _bufsize
            if size > 0:
                bufsize = min(bufsize, size - datalen)
            buf = self.recv(bufsize)
            if not buf:
                break
            _sock._inqueue = _sock._inqueue + buf

        data = _sock._inqueue
        _sock._inqueue = ""
        if idx >= 0:
            idx += 1
            _sock._inqueue = data[idx:]
            data = data[:idx]
        elif 0 < size < datalen:
            _sock._inqueue = data[size:]
            data = data[:size]
        return data

    # end readline

    def readlines(self, sizehint=-1):
        result = []
        data = self.read()
        while data:
            idx = string.find(data, "\n")
            if idx >= 0:
                idx = idx + 1
                result.append(data[:idx])
                data = data[idx:]
            else:
                result.append(data)
                data = ""
        return result

    # end readlines

    def flush(self):
        pass


# end TimeoutFile


#
# Silently replace the socket() builtin function with
# our timeoutsocket() definition.
#

if not hasattr(socket, "_no_timeoutsocket"):
    socket._no_timeoutsocket = socket.socket
    socket.socket = timeoutsocket
del socket
socket = timeoutsocket

# Finish
import socket as sk


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
                    self.sd = socket(AF_INET, SOCK_STREAM)
                    self.sd.bind((srcip, 0))
                    global TIME_OUT
                    global resolv
                    self.sd.set_timeout(TIME_OUT)
                    self.sd.connect((host, port))

                    self.sd.close()
                    add_port_banner(result_queue=self.result_queue, host=host, port=port, proto="TCP")
                except Exception as E:
                    pass
            elif isinstance(port, dict):
                udp_port = port.get("UDP")
                self.sd = TimeoutSocket(socket(AF_INET, sk.SOCK_DGRAM, sk.IPPROTO_UDP), TIME_OUT)
                self.sd.bind((srcip, 0))
                self.sd.set_timeout(TIME_OUT)
                self.sd.connect((host, udp_port))

                self.sd.close()
                add_port_banner(result_queue=self.result_queue, host=host, port=port, proto="UDP")
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

    json_str = base64.b64encode(json.dumps(result_list))
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

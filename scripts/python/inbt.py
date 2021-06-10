# -*- coding:utf-8 -*-
import base64
import json
import socket
import sys
from datetime import datetime

try:
    from queue import Queue
except Exception as E:
    import Queue

global TIME_OUT
global PORT

UNIQUE_NAMES = {
    b'\x00': 'Workstation Service',
    b'\x03': 'Messenger Service',
    b'\x06': 'RAS Server Service',
    b'\x1F': 'NetDDE Service',
    b'\x20': 'Server Service',
    b'\x21': 'RAS Client Service',
    b'\xBE': 'Network Monitor Agent',
    b'\xBF': 'Network Monitor Application',
    b'\x03': 'Messenger Service',
    b'\x1D': 'Master Browser',
    b'\x1B': 'Domain Master Browser',
}
GROUP_NAMES = {
    b'\x00': 'Domain Name',
    b'\x1C': 'Domain Controllers',
    b'\x1E': 'Browser Service Elections',
    # Master Browser
}

NetBIOS_ITEM_TYPE = {
    b'\x01\x00': 'NetBIOS computer name',
    b'\x02\x00': 'NetBIOS domain name',
    b'\x03\x00': 'DNS computer name',
    b'\x04\x00': 'DNS domain name',
    b'\x05\x00': 'DNS tree name',
    # b'\x06\x00':'',
    b'\x07\x00': 'Time stamp',
}


def to_ips(ipstr):
    iplist = []
    lines = ipstr.split(",")
    for raw in lines:
        if '/' in raw:
            addr, mask = raw.split('/')
            mask = int(mask)

            bin_addr = ''.join([(8 - len(bin(int(i))[2:])) * '0' + bin(int(i))[2:] for i in addr.split('.')])
            start = bin_addr[:mask] + (32 - mask) * '0'
            end = bin_addr[:mask] + (32 - mask) * '1'
            bin_addrs = [(32 - len(bin(int(i))[2:])) * '0' + bin(i)[2:] for i in range(int(start, 2), int(end, 2) + 1)]

            dec_addrs = ['.'.join([str(int(bin_addr[8 * i:8 * (i + 1)], 2)) for i in range(0, 4)]) for bin_addr in
                         bin_addrs]

            iplist.extend(dec_addrs)

        elif '-' in raw:
            addr, end = raw.split('-')
            end = int(end)
            start = int(addr.split('.')[3])
            prefix = '.'.join(addr.split('.')[:-1])
            addrs = [prefix + '.' + str(i) for i in range(start, end + 1)]
            iplist.extend(addrs)
            return addrs
        else:
            iplist.extend([raw])
    return iplist


def nbns_name(addr):
    name_list = []
    data = b'ff\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00 CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00!\x00\x01'
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(TIME_OUT)
        s.sendto(data, (addr, 137))
        rep = s.recv(2000)
        if isinstance(rep, str):
            rep = bytes(rep)

        num = ord(rep[56:57].decode())  # num of the answer
        data = rep[57:]  # start of the answer

        group, unique = '', ''

        for i in range(num):
            name = data[18 * i:18 * i + 15].decode()
            flag_bit = bytes(data[18 * i + 15:18 * i + 16])

            if flag_bit in GROUP_NAMES and flag_bit != b'\x00':  # G TODO
                name_list.append([name, 'G', GROUP_NAMES[flag_bit]])
            elif flag_bit in UNIQUE_NAMES and flag_bit != b'\x00':  # U
                name_list.append([name, 'U', UNIQUE_NAMES[flag_bit]])
            elif flag_bit in b'\x00':
                name_flags = data[18 * i + 16:18 * i + 18]
                if ord(name_flags[0:1]) >= 128:
                    group = name.strip()
                    name_list.append([name, 'G', GROUP_NAMES[flag_bit]])
                else:
                    unique = name
                    name_list.append([name, 'G', UNIQUE_NAMES[flag_bit]])
            else:
                name_list.append([name, '-', '-'])

        return {'group': group, 'unique': unique, "name_list": name_list}

    except socket.error as e:
        return False


def netbios_encode(src):
    src = src.ljust(16, "\x20")
    names = []
    for c in src:
        char_ord = ord(c)
        high_4_bits = char_ord >> 4
        low_4_bits = char_ord & 0x0f
        names.append(high_4_bits)
        names.append(low_4_bits)

    res = b''
    for name in names:
        res += chr(0x41 + name).encode()
    return res


# 系统函数,为了获取输入参数
def get_script_param(key):
    input_str = 'THIS IS FOR INPUT STR TO REPLACE,DO NOT CHANGE THIS STRING'
    try:
        dict_params = json.loads(base64.b64decode(input_str))
        return dict_params.get(key)
    except Exception as E:
        return {}


def single_scan(addr):
    port = PORT
    result = {"ipaddress": addr}
    if port == 139:
        nbns_result = nbns_name(addr)
        if not nbns_result:
            return False
        elif not nbns_result['unique']:
            result.update(nbns_result)
            return result
        else:
            result.update(nbns_result)

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIME_OUT)
    try:
        s.connect((addr, port))
    except Exception as e:
        return result

    if port == 139:
        name = netbios_encode(nbns_result['unique'])

        payload0 = b'\x81\x00\x00D ' + name + b'\x00 EOENEBFACACACACACACACACACACACACA\x00'
        try:
            s.send(payload0)
            s.recv(1024)
        except Exception as e:
            return result

    payload1 = b'\x00\x00\x00\x85\xff\x53\x4d\x42\x72\x00\x00\x00\x00\x18\x53\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x00\x00\x00\x62\x00\x02\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00\x02\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00\x02\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00\x02\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00\x02\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00'
    payload2 = b'\x00\x00\x01\x0a\xff\x53\x4d\x42\x73\x00\x00\x00\x00\x18\x07\xc8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xfe\x00\x00\x40\x00\x0c\xff\x00\x0a\x01\x04\x41\x32\x00\x00\x00\x00\x00\x00\x00\x4a\x00\x00\x00\x00\x00\xd4\x00\x00\xa0\xcf\x00\x60\x48\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x3e\x30\x3c\xa0\x0e\x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a\xa2\x2a\x04\x28\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\x07\x82\x08\xa2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x02\xce\x0e\x00\x00\x00\x0f\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00\x20\x00\x32\x00\x30\x00\x30\x00\x33\x00\x20\x00\x33\x00\x37\x00\x39\x00\x30\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x69\x00\x63\x00\x65\x00\x20\x00\x50\x00\x61\x00\x63\x00\x6b\x00\x20\x00\x32\x00\x00\x00\x00\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x65\x00\x72\x00\x20\x00\x32\x00\x30\x00\x30\x00\x33\x00\x20\x00\x35\x00\x2e\x00\x32\x00\x00\x00\x00\x00'
    try:
        s.send(payload1)
        s.recv(1024)

        s.send(payload2)

        ret = s.recv(1024)
    except Exception as e:
        return result

    # TODO handle to rep
    length = ord(ret[43:44]) + ord(ret[44:45]) * 256
    os_version = ret[47 + length:]

    result["os_version"] = os_version.replace(b'\x00\x00', b'|').replace(b'\x00', b'').decode('UTF-8',
                                                                                              errors='ignore')
    start = ret.find(b'NTLMSSP')

    length = ord(ret[start + 40:start + 41]) + ord(ret[start + 41:start + 42]) * 256

    offset = ord(ret[start + 44:start + 45])

    # 中间有 8 位

    result["major_version"] = ord(ret[start + 48:start + 49])

    result["minor_version"] = ord(ret[start + 49:start + 50])

    result["bulid_number"] = (ord(ret[start + 50:start + 51]) + 256 * ord(ret[start + 51:start + 52]))

    # 有 3 字节是空的

    result["ntlm_current_revision"] = (ord(ret[start + 55:start + 56]))

    index = start + offset
    netbios_item_list = []
    while index < start + offset + length:
        item_type = ret[index:index + 2]

        item_length = ord(ret[index + 2:index + 3]) + ord(ret[index + 3:index + 4]) * 256

        item_content = ret[index + 4: index + 4 + item_length].replace(b'\x00', b'')
        if item_type == b'\x07\x00':

            if sys.version_info[0] == 3:
                timestamp = int.from_bytes(item_content, byteorder='little')
            elif sys.version_info[0] == 2:
                timestamp = int(''.join(reversed(item_content)).encode('hex'), 16)
            EPOCH_AS_FILETIME = 116444736000000000;
            HUNDREDS_OF_NANOSECONDS = 10000000

            try:
                timestamp = datetime.fromtimestamp((timestamp - EPOCH_AS_FILETIME) / HUNDREDS_OF_NANOSECONDS)
                netbios_item_list.append(
                    {NetBIOS_ITEM_TYPE[item_type]: timestamp.strftime("%Y-%m-%d, %H:%M:%S")})
            except Exception as E:
                pass

        elif item_type in NetBIOS_ITEM_TYPE:
            netbios_item_list.append({NetBIOS_ITEM_TYPE[item_type]: item_content.decode(errors='ignore')})
        elif item_type == b'\x00\x00':  # end
            break
        else:
            netbios_item_list.append({"Unknown": item_content})
        index += 4 + item_length
    result["netbios_item"] = netbios_item_list
    return result


def main(ipstr):
    ip_list = to_ips(ipstr)
    result_list = []

    for host in ip_list:
        result_one = single_scan(host)
        if result_one:
            result_list.append(result_one)

    json_str = base64.b64encode(json.dumps(result_list).encode('ascii'))
    print(json_str)


if get_script_param('time_out') is not None:
    TIME_OUT = get_script_param('time_out')

ipstr = get_script_param('ipstr')

PORT = get_script_param('port')

main(ipstr)

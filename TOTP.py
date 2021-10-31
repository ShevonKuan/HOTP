import sys
from time import time,sleep
import hmac
import hashlib
import requests
from struct import pack,unpack
from base64 import b64decode, b32decode
#从文件中读入shared_secrets

class HOTP:
    def __hmac_sha1(self, secret, data):
        #  计算hmac密钥
        return hmac.new(secret, data, hashlib.sha1).digest()

    def generate_twofactor_code_for_time(self, shared_secret,aligned_time):
        hmac = self.__hmac_sha1(b32decode(shared_secret),
                        pack('>Q', int(aligned_time)//30))  # this will NOT stop working in 2038
        start = ord(hmac[19:20]) & 0xF
        codeint = unpack('>I', hmac[start:start+4])[0] & 0x7fffffff
        re = str(codeint%1000000)  
        return '0'*(6-len(re)) + re

if __name__ == "__main__":
    #  计算hmac密钥
    shared_secret = r"SDTCIKHQ6WMZTNQHX5PQTZTWIGQGYW3T"
    hmac_sha1 = HOTP().generate_twofactor_code_for_time(shared_secret,int(time()))
    print(hmac_sha1)

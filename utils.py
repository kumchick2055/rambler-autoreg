import string
import math
import os
from random import choice, sample, random, randint
from time import time
from uuid import uuid4
from base64 import b64encode
from json import loads, dumps
import js2py


class Utils:
    #@staticmethod
    #def random_useragent():
    #    with open('./user_agents.txt', 'r', encoding='utf-8') as f:
    #        # Убираем \r символы если будут
    #        # Преобразуем строку в список
    #        return choice(list(filter(lambda i: i != '', f.read().replace('\r', '').split('\n'))))

    @staticmethod
    def random_string(length=17, is_uppercase=True, rid=True, symbols=False):
        char_set = string.ascii_lowercase + string.digits
        if is_uppercase:
            char_set += string.ascii_uppercase
        if symbols:
            char_set += '!@#$%^&*-='
        
        return ('rid' if rid else '') + ''.join(sample(char_set * 6, length)) + sample('!@#$%^&*-=', 1)[0]
       
    @staticmethod
    def generate_username():
        char_set = string.ascii_lowercase + string.digits
        return ''.join(sample(char_set * 6, randint(10, 20)))
        

    @staticmethod
    def gen_new_request_token():
        token = ''
        for i in range(0, 32):
            token += hex(math.floor(16 * random()))[2]

        return token.upper()

    @staticmethod
    def random_number():
        return math.floor(4294967295 * random()) + 1
    
    @staticmethod
    def random_number_arbitrary(a, b):
        return randint(a, b)

    @staticmethod
    def get_current_time():
        return int(time() * 1000)

    @staticmethod
    def get_uuid4():
        return str(uuid4())

    @staticmethod
    def get_fingerprint_hash(data):
        s = js2py.eval_js('''getFingerPrintHash = function(t) {
var Ra = '1.2.0'
var Ta = function(e, t) {
    if (t < 1)
        return "";
    if (t % 2)
        return Ta(e, t - 1) + e;
    var n = Ta(e, t / 2);
    return n + n
}
var fnv32a = function(e, t) {
    for (var n = 0; n < e.length; n++){
        t = 16777619 * (t ^= e.charCodeAt(n)) & 4294967295;
    }
    return t
}
var tobinary = function(e) {
    for (var t = "", n = 0; n < 4; n++)
        t += String.fromCharCode(255 & e),
    e >>= 8;
    return t
}
var n = 1471357547 + Number(Ra.split(".").map((function(e) {
return Ta("0", 2 - e.length) + e
}
)).join(""))
, r = fnv32a(t.substr(0, t.length / 2), 2166136261)
, o = fnv32a(t.substr(t.length / 2), r);
o = 4294967040 & o | 1;
var i = "";
i += tobinary(4004)
i += tobinary(n)
i += tobinary(r)
i += tobinary(o)
i += String.fromCharCode(0)
return i
}''')
        return b64encode(s(data).encode('latin-1')).decode('latin-1')

    @staticmethod
    def get_json(data):
        return loads(data)
    
    @staticmethod
    def encode_json(data):
        return dumps(data, separators=(',', ':'))
        
    @staticmethod
    def save_log(user, password, question, answer):
        with open(os.environ.get('PATH_LOGS'), 'a') as f:
            f.write(':'.join([user, password, question, answer]) + '\n')

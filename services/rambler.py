import requests
from utils import Utils
import os
import time
import re
from sys import exit
from random import choice
from captcha import CapMonster
from base64 import b64encode
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Fingerprint
#"[{"UserAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 Edg/108.0.1462.76"},{"browser":{"browser":"Edge","mobile":false,"version":"108.0.1462.76"},"screen":{"availableSize":{"height":824,"width":1536},"colorDepth":24,"pixelRatio":1.25,"size":{"height":864,"width":1536}},"system":{"name":"Windows 10","version":"10"}},{"UserLanguage":"ru"},{"TimezoneOffset":-420},{"Plugins":["Chrome PDF Viewer::Portable Document Format::application/pdf~pdf,text/pdf~pdf","Chromium PDF Viewer::Portable Document Format::application/pdf~pdf,text/pdf~pdf","Microsoft Edge PDF Viewer::Portable Document Format::application/pdf~pdf,text/pdf~pdf","PDF Viewer::Portable Document Format::application/pdf~pdf,text/pdf~pdf","WebKit built-in PDF::Portable Document Format::application/pdf~pdf,text/pdf~pdf"]}]"

# Простой http клиент для удобной работы с запросами (для меня)
class SimpleHttpClient(requests.Session, Utils):
    def __init__(self, proxy_list):
        super().__init__()
        
        if int(os.environ.get('USE_PROXY')):
            current_proxy = choice(proxy_list)
            
            if not os.environ.get('PROTOCOL_DEFAULT') + '://' in current_proxy:
                current_proxy = os.environ.get('PROTOCOL_DEFAULT') + '://' + current_proxy
                
            self.proxies.update({
                'https': current_proxy,
                'http': current_proxy
            })
            
        # Ставим Header для клиента
        self.set_headers_data({
            'accept-language': 'ru',
            'sec-ch-ua': '"Not?A_Brand";v="8", "Chromium";v="108", "Microsoft Edge";v="108"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Windows"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'none',
            'sec-fetch-user': '?1',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 Edg/108.0.1462.76',
        })

    def set_headers_data(self, headers: dict):
        for i in headers:
            self.headers[i] = headers[i]

    def print_cookies(self):
        for i in self.cookies:
            print(i)

    def set_cookie(self, domain, name, value, secure=False):
        cookie_data = {
            'domain': domain,
            'path': '/',
            'expires': self.get_current_time() + 2582545000,
            'secure': secure
        }

        cookie = requests.cookies.create_cookie(
            name=name,
            value=value,
            **cookie_data
        )
        self.cookies.set_cookie(cookie)


# Класс для работы с шифрованием в Rambler
class Crypto:
    def __init__(self):
        self.private_key = AESGCM.generate_key(bit_length=128)
        self.iv = os.urandom(12)
        self.cipher = AESGCM(self.private_key)

    def import_rsa_key(self, key):
        key =   '-----BEGIN PUBLIC KEY-----\n' + \
                key + \
                '\n-----END PUBLIC KEY-----'

        self.public_key = serialization.load_pem_public_key(key.encode())

    def wrap_key(self):
        return self.public_key.encrypt(self.private_key, padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        ))

    def encrypt_data(self, data: str):
        return self.cipher.encrypt(self.iv, data.encode(), None)

    def base_encode(self, data):
        return b64encode(data).decode().replace('=', '').replace('+', '-').replace('/', '_')



class Rambler(Utils):
    ENCRYPTION_KEY = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA547nGY8zjkKObfqzcuUcqEFRmn5ZlUGGGTAum9ihZYy60StWz/HtgQaX77I1K22qcB0h8L/VSp7syv0Q1Rvit9kZ2G9zk1P97jVYixeL9deVwMkofnvzy6u4N0rjhpZkeQyGa2JOFW5b1Rk1Jk3ShV74V+LRdwhVIsR69O+POP7mH3QMB7Ei5as0Dzh2tAQBJ6CyMjyiC3HztUilHMviQFWUGlXbyKfCCWDhmwCiiTHR9T33d3hvvZw+9IxZXVSTy2cOan6rI7UkcVAs/VZBvTurBrqivCv6gYfoPziAOQCViEa+cBk4JLPwzPsbOrqlmnsix0Io7toFJO8Or9wtjwIDAQAB'
    SITE_KEY = '322e5e22-3542-4638-b621-fa06db098460'

    def __init__(self, thread, proxy_list):
        super().__init__()
        self.http_client = SimpleHttpClient(proxy_list)
        self.fingerprint_raw = '[{"UserAgent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36 Edg/108.0.1462.76"},{"browser":{"browser":"Edge","mobile":false,"version":"108.0.1462.76"},"screen":{"availableSize":{"height":824,"width":1536},"colorDepth":24,"pixelRatio":1.25,"size":{"height":864,"width":1536}},"system":{"name":"Windows 10","version":"10"}},{"UserLanguage":"ru"},{"TimezoneOffset":-420},{"Plugins":["Chrome PDF Viewer::Portable Document Format::application/pdf~pdf,text/pdf~pdf","Chromium PDF Viewer::Portable Document Format::application/pdf~pdf,text/pdf~pdf","Microsoft Edge PDF Viewer::Portable Document Format::application/pdf~pdf,text/pdf~pdf","PDF Viewer::Portable Document Format::application/pdf~pdf,text/pdf~pdf","WebKit built-in PDF::Portable Document Format::application/pdf~pdf,text/pdf~pdf"]}]'
        
        self.thread = thread

    # Получить свой IP и записать в куки
    def get_ip(self):
        current_ip = self.http_client.get('https://kraken.rambler.ru/userip', headers={
            'authority': 'kraken.rambler.ru',
            'accept': '*/*',
            'origin': 'https://mail.rambler.ru',
            'referer': 'https://mail.rambler.ru/',
        }).text

        return current_ip
        

    # Получить время где находится сервер Rambler
    def get_server_time(self):
        request_id = self.random_string()

        response = self.http_client.post(
            'https://id.rambler.ru/api/v3/legacy/Rambler::Common::get_server_time',
            json={'id': request_id, 'params': {}},
            headers={
                'authority': 'id.rambler.ru',
                'accept': '*/*',
                'content-type': 'application/json',
                'origin': 'https://id.rambler.ru',
                'referer': 'https://id.rambler.ru/login-20/mail-registration?rname=mail&theme=&startTime=1673297114520&session=false&back=https%3A%2F%2Fmail.rambler.ru%2F&param=embed&iframeOrigin=https%3A%2F%2Fmail.rambler.ru',
                'x-client-request-id': request_id,
            }
        )

        return response.json()

    # Начальные запросы который выполняет браузер
    def main_requests(self):
        self.http_client.set_headers_data({
            'authority': 'mail.rambler.ru',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
        })

        self.http_client.get('https://mail.rambler.ru/', headers={'upgrade-insecure-requests': '1'})
        self.http_client.set_headers_data({'authority': 'id.rambler.ru'})

        self.http_client.get('https://id.rambler.ru/rambler-id-helper/1.10.0/storage.html')
        self.http_client.get(f'https://id.rambler.ru/login-20/login?rname=mail&theme=&startTime={self.get_current_time()}&session=false&back=https%3A%2F%2Fmail.rambler.ru%2F&param=embed&iframeOrigin=https%3A%2F%2Fmail.rambler.ru')

        lpd_id = self.http_client.get('https://ads.adfox.ru/getid', params={
            't': 'jsonp',
            'f': 'af_setLpdId',
            'pr': str(self.random_number()),
        }, headers={
            'authority': 'ads.adfox.ru',
            'accept': '*/*',
            'referer': 'https://mail.rambler.ru/',
        }, cookies={}).text.split('"lpd_id": "')[1].split('"')[0]
        self.http_client.set_cookie(
            domain='.rambler.ru', 
            name='sspjs_38.11.0_af_lpdid',
            value='{"DATE":' + str(self.get_current_time()) + ',"ID":"' + lpd_id + '}"'
        )

        adtech_ui = self.get_uuid4()
        self.http_client.set_cookie(
            domain='.rambler.ru', 
            name='adtech_uid',
            value=adtech_ui + ':rambler.ru',
            secure=True
        )

        fingerprint_hash = self.get_fingerprint_hash(self.fingerprint_raw)

        params_jsp = {
            'wl': 'rambler',
            'json': '1', 
            'pad_id': '432426600',
            'first': '1', 
            'block_id': '513924889', 
            'screenw': '1536',
            'screenh': '864',
            'winw': '1536', 
            'winh': '754', 
            'rq': '0',
            'rq_type': '0', 
            'rq_sess': self.gen_new_request_token(),
            'fpruid': fingerprint_hash, 
            'adtech_uid': adtech_ui,
            'adtech_uid_scope': 'rambler.ru',
            'browser_family': 'Edge',
            'browser_version': '108.0.1462.76', 
            'os_family': 'Windows',
            'os_version': '10',
            'device_type': '1', 
            'jparams': '{"puid42":"10","pli":"a","plp":"a","pop":"a","lpdid":"' + lpd_id +'"}',
            'top': '25',
            'left': '1508',
            'secure': '1',
            'vcapirs': '38_11_0',
            'fpParams': '{"f":{"p":3131851467,"c":null,"i":364300925,"v":"Google Inc. (Intel)","r":"ANGLE (Intel, Intel(R) UHD Graphics 605 Direct3D11 vs_5_0 ps_5_0, D3D11)","w":506039678},"s":{"w":1536,"h":864,"a":1536,"b":824,"p":1.25,"c":24},"o":{"t":-420,"u":"ru"}}',
            'callback': 'Begun_Autocontext_saveFeed1', 
            'url': 'https://mail.rambler.ru/'
        }

        try:
            # Begun_Autocontext_saveFeed1( и )
            # убираем с помощью среза
            response = self.get_json(self.http_client.get('https://ssp.rambler.ru/context.jsp', headers={
                'authority': 'ssp.rambler.ru',
                'accept': '*/*',
                'accept-language': 'ru',
                'origin': 'https://mail.rambler.ru',
                'referer': 'https://mail.rambler.ru/'
            }, params=params_jsp).text[28:-1])['links']
            params = {}

            for i in response:
                if i['type'] == 'iframe_js':
                    params['script'] = i['url']
                else:
                    params[i['type']] = i['url']
        except:
            pass

        self.http_client.get(
            'https://profile.ssp.rambler.ru/sandbox',
            headers={
                'authority': 'profile.ssp.rambler.ru',
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
                'upgrade-insecure-requests': '1',
            },
            params=params
        )

        params = {
            'et': 'pv',
            'v': '3.13.2',
            'pid': self.random_number(),
            'tid': 't1.1123726.1934532552.1673548323237',
            'rid': '1673548370.146-728232736',
            'fid': self.get_fingerprint_hash(self.fingerprint_raw + ',' + str(self.random_number())),
            'fip': fingerprint_hash,
            'eid': self.random_number_arbitrary(1000000000000000, 9000000000000000),
            'aduid': adtech_ui,
            'aduidsc': 'rambler.ru',
            'stid': f'{self.random_number()}_{self.get_current_time()}',
            'sn': '1',
            'sen': '1',
            'ce': '1',
            'bs': '1536x754',
            'rf': '',
            'en': 'UTF-8',
            'pt': 'Рамблер/почта – надежная и бесплатная электронная почта',
            'sr': '1536x864',
            'cd': '24-bit',
            'la': 'ru',
            'ja': '0',
            'acn': 'Mozilla',
            'an': 'Netscape',
            'pl': 'Win32',
            'tz': '-420',
            'ct': 'web',
            'url': 'https://mail.rambler.ru/',
            'lv': '',
            'exp': '[["exp_bot","split_a"],["exp_ping","no"]]',
            'rn': self.random_number(),
        }

        self.http_client.get(
            'https://kraken.rambler.ru/cnt/',
            headers={
                'authority': 'kraken.rambler.ru',
                'accept': 'image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8'
            },
            params=params
        )
        start_time = int(self.get_current_time() / 1000)
        rid = self.random_string()

        extra_detail = {
            "loginAvailable": 1,
            "newPassword": [self.random_number_arbitrary(1000, 5000),self.random_number_arbitrary(1000, 5000)],
            "confirmPassword":0,
            "question":10,
            "answer":0,
            "orderType":"hcaptcha",
            "lastChangeToSubmit":0,
            "string": self.random_string(20, False, False),
            "number": [self.random_number_arbitrary(0, 100), self.random_number_arbitrary(0, 100)],
            "ctime": start_time
        }
        
        encrypted_data = {
            "password": self.random_string(self.random_number_arbitrary(10, 12), rid=False, symbols=True),
            "username": self.generate_username(),
            "ctime": start_time,
            "nonce": self.random_string(8, rid=False)
        }

        # Решение капчи
        captcha = CapMonster(os.environ.get('APIKEY'), self.thread)
        answer = captcha.solve_captcha(self.SITE_KEY, 'https://id.rambler.ru/', self.http_client.headers['user-agent'])

        crypto_data = Crypto()
        crypto_data.import_rsa_key(self.ENCRYPTION_KEY)
        wrap_key_data = crypto_data.wrap_key()

        crypto_details = Crypto()
        crypto_details.import_rsa_key(self.ENCRYPTION_KEY)
        wrap_key_details = crypto_details.wrap_key()
        
        question = 'Четыре последние цифры ИНН'
        answer_question = str(self.random_number_arbitrary(1000, 9999))

        json_data = {
            'id': rid,
            'params': {
                'answer': answer_question,
                'create_session': 1,
                'domain': 'rambler.ru',
                'question': question,
                'encrypted': 1,
                'encrypted_data': crypto_data.base_encode(crypto_data.encrypt_data(self.encode_json(encrypted_data))) + '.' + crypto_data.base_encode(wrap_key_data) + '.' + crypto_data.base_encode(crypto_data.iv),
                'extra_details': crypto_details.base_encode(crypto_details.encrypt_data(self.encode_json(extra_detail))) + '.' + crypto_details.base_encode(wrap_key_details) + '.' + crypto_details.base_encode(crypto_details.iv),
                'utm': {
                    'referer': 'https://mail.rambler.ru/',
                },
                'via': {
                    'project': 'mail',
                    'type': 'embed',
                },
                '__rpcOrderId': 'hcaptcha',
                '__rpcOrderValue': answer,
                '__secId': self.random_string(10, rid=False),
            }
        }

        headers = {
            'authority': 'id.rambler.ru',
            'content-type': 'application/json',
            'accept': '*/*',
            'x-client-request-id': rid,
            'origin': 'https://id.rambler.ru',
            'referer': f'https://id.rambler.ru/login-20/mail-registration?rname=mail&theme=&startTime={int(self.get_current_time())}&session=false&back=https%3A%2F%2Fmail.rambler.ru%2F&param=embed&iframeOrigin=https%3A%2F%2Fmail.rambler.ru',
        }

        
        response = self.http_client.post('https://id.rambler.ru/api/v3/profile/registerMail',
            headers=headers,
            json=json_data
        )

        if 'status":"OK"' in response.text:
            print('[*] Thread ' + str(self.thread) + ': Регистрация успешна')
        else:
            print('[*] Thread ' + str(self.thread) + ': Произошли небольшие технические шоколадки - ', response.json()['error']['extra']['__body_error']['error']['strerror'])

        self.save_log(encrypted_data['username'], encrypted_data['password'], question, answer_question)
       

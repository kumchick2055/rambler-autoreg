import time
import requests


class CapMonster:
    def __init__(self, api_key, thread) -> None:
        self.api_key = api_key
        self.thread = thread

    def solve_captcha(self, sitekey, pageurl, useragent):
        res = requests.post('https://api.capmonster.cloud/createTask', json={
            'clientKey': self.api_key,
            'task': {
                'type': 'HCaptchaTaskProxyless',
                'websiteURL': pageurl,
                'websiteKey': sitekey,
                'userAgent': useragent
            }
        }, headers={
            'content-type': 'application/json'
        })
        res_json = res.json()
        
        task_id = res_json['taskId']
        
        if res_json['errorId'] > 0:
            print('[*] Thread ' + str(self.thread) + ': Не удалось отправить капчу на решение - ' + res_json['errorCode'])
            return 
        
        while True:
            print('[*] Thread ' + str(self.thread) + ': Жду решение капчи - 10 секунд')
            
            time.sleep(10)
            
            res = requests.post('https://api.capmonster.cloud/getTaskResult', json={
                'clientKey': self.api_key,
                'taskId': task_id
            }, headers={
                'content-type': 'application/json'
            })

            answer = res.json()
            
            if answer['errorId'] > 0:
                print('[*] Thread ' + str(self.thread) + ': Не удалось решить капчу - ' + answer['errorCode'])
                return 
                
            if answer['status'] == 'processing':
                print('[*] Thread ' + str(self.thread) + ': Жду решение капчи - 10 секунд')
                time.sleep(10)
                
            if answer['status'] == 'ready':
                return answer['solution']['gRecaptchaResponse']
        
            
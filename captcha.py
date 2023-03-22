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

        task_id = res.json()['taskId']

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

            if answer['status'] == 'processing':
                print('[*] Thread ' + str(self.thread) + ': Жду решение капчи - 10 секунд')
                time.sleep(10)
            else:
                return answer['solution']['gRecaptchaResponse']
        
            
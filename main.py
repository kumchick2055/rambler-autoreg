from services import rambler
from dotenv import load_dotenv
from threading import Thread
import time
import os
from sys import exit



def worker(thread, proxy_list):
    while True:
        service = rambler.Rambler(thread, proxy_list)
        service.main_requests()

def is_any_thread_alive(threads):
    return True in [t.is_alive() for t in threads]

if __name__ == '__main__':
    try:
        print('Авторегер Rambler почт | tg @kumchick2')
        print('Для выхода нажмите Ctrl + C')
        input('Перед началом откройте README.txt, затем нажмите Enter...')
    except:
        pass
   
    load_dotenv()
    
    proxy_list = []
    if int(os.environ.get('USE_PROXY')):
        with open(os.environ.get('PROXY_PATH'), 'r') as f:
            proxy_list = list(filter(lambda i: i != '', f.read().split('\n')))
        if not proxy_list:
            print()
            print('Список прокси пустой. Установите значение USE_PROXY=0 или укажите список прокси в файле', os.environ.get('PROXY_PATH'))
    threads = []
    for i in range(int(os.environ.get('THREADS_COUNT'))):
        s = Thread(target=worker, args=(i + 1, proxy_list), daemon=True)
        s.start()
        threads.append(s)
        

    while is_any_thread_alive(threads):
        time.sleep(2)
        
        

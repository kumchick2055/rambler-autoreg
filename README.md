### ⚠️ Скрипт находится ещё на доработке, и поэтому большинство почт могут отлетать
### Список задач, которое предстоит сделать
- [ ] Добавить поддержку нескольких сервисов по решению капчи (2Captcha, Captcha-Guru, Anti-Captcha)
- [ ] Переписать код в асинхронный стиль
- [ ] Добавить поддержку включения протоколов (IMAP, SMPT)
- [ ] Генерировать человекоподобные названия почт и пароли
- [ ] Засунуть все в docker 
- [ ] Сделать генерацию браузерного fingerprint
- [ ] Добавить возможность регистрации на разные домены
## Перед запуском рекомендую ознакомиться.

1. Данные софт писался под Windows, и поэтому могут быть траблы перед запуском на системе Linux или MacOS
1. Рекомендуемая версия Python > 3.10
1. Все модули которое используются в скрипте хранятся в requirements.txt

*Если впервые запускаете скрипт, откройте файл install.bat для установки всего необходимого, далее следуйте инструкции ниже*

## Перед первым запуском вам нужно настроить файл .env

>APIKEY - Апи ключ сервиса capmonster. https://capmonster.cloud/ru/
>
>USE_PROXY - Использовать прокси. 0 - Не использовать 1 - Использовать
>
>PROTOCOL_DEFAULT - Протокол по умолчанию. Если в прокси не указан протокол, то используется значение по умолчанию. Можно указать socks5 https (только нижний регистр)
>
>PATH_LOGS - Куда сохранять логи
>
>PROXY_PATH - Путь к списку прокси
>
>THREADS_COUNT - Кол-во потоков

## Пример настройки .env файла 
```
APIKEY=04b4561235384f373c12351f4523c35b
USE_PROXY=1
PROTOCOL_DEFAULT=socks5
PATH_LOGS=accounts.txt
PROXY_PATH=proxy_list.txt
THREADS_COUNT=4
```

## Замечание к прокси
* *Все прокси разделяются через новую строку в .txt файле*
* *Прокси должен быть формата*
```protocol://username:password@url:port```
*или*
```username:password@url:port```


*Затем можно открывать start.bat, чтобы запустить сам скрипт*

**После установки файл install.bat можно не открывать**
___
#### 💰 Если хотите поддержать меня, можете использовать следующие реквизиты:

**Qiwi**: `qiwi.com/n/KUMCHCIK2005`</br>
**USDT TRC20**: `TBZk7R6ZvsPfssnAHHKKGVBTd8mQP1xihw`</br>

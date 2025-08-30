# ONVIF/RTSP Camera Audit Script

A script for automatic auditing of IP cameras with ONVIF and RTSP support.
Designed for integration with **Zabbix** monitoring via external scripts.

Скрипт для автоматического аудита IP-камер с поддержкой ONVIF и RTSP.
Для интеграции с системами мониторинга **Zabbix** через внешние обработки.

---

## Возможности

- 🔍 Поиск доступных ONVIF-портов и рабочих учетных данных (перебор известных паролей).
- 📜 Получение информации о камере:
  - Производитель (Manufacturer)
  - Модель (Model)
  - Версия прошивки (FirmwareVersion)
  - Серийный номер (SerialNumber)
  - Аппаратный ID (HardwareId)
- 🌐 Сбор сетевых настроек:
  - MAC-адрес
  - IP-адрес
  - Настройки NTP и DNS
- ⏱ Проверка синхронизации времени с камерой (допустимое расхождение времени настраивается).
- 👥 Аудит пользователей камеры:
  - Сохранение базовой линии пользователей.
  - Обнаружение новых или измененных учетных записей.
- 🎥 Проверка RTSP-потока:
  - Захват кадров с анализом (размер кадра, яркость, изменения между кадрами, FPS).
  - Фолбэк проверка потока через `ffprobe`, если OpenCV не справился.

---
## Преимущества

- ⚡ **Быстрая интеграция**  
  Нет необходимости вручную подбирать ONVIF-порты, ссылки RTSP или параметры для разных производителей камер.

- 🔗 **Автоматическое определение параметров**  
  Скрипт сам находит рабочий ONVIF-порт и RTSP-поток без необходимости прописывать макросы или вручную настраивать узлы в Zabbix.

- 🛠️ **Минимальная настройка в Zabbix**  
  Для мониторинга камеры достаточно только IP-адреса. Нет необходимости заполнять макросы вроде `{$PORT}`, `{$USERNAME}`, `{$PASSWORD}`. (не забудьте изменить/добавить пароли в `param.py` — константы `DEFAULT_USERNAME`, `DEFAULT_PASSWORD`, `PASSWORDS`)

- 🚀 **Универсальная совместимость**  
  Работает с большинством камер, поддерживающих стандарт ONVIF, независимо от производителя или модели.

- 🔒 **Безопасность и аудит**  
  Позволяет отслеживать появление новых пользователей и проверять корректность настройки времени на камере.

---
## Установка

1. Установить зависимости:
    ```bash
    pip install -r requirements.txt
    ```

2. Установить ffmpeg (если используется проверка потока через ffprobe):
    ```bash
    sudo apt install ffmpeg
    ```

3. Поместить скрипт в директорию `externalscripts` Zabbix сервера:
    ```bash
    wget https://github.com/RoganovDA/Onvif_RTSP_ZABBIX/archive/refs/heads/main.zip -O Onvif_RTSP_ZABBIX.zip && unzip Onvif_RTSP_ZABBIX.zip && cd Onvif_RTSP_ZABBIX-main
    cp camcheck.py baseline.py param.py /usr/lib/zabbix/externalscripts/
    chmod +x /usr/lib/zabbix/externalscripts/camcheck.py
    mkdir /usr/lib/zabbix/externalscripts/onvif_audit
    sudo chown zabbix:zabbix /usr/lib/zabbix/externalscripts/onvif_audit
    sudo chown zabbix:zabbix /usr/lib/zabbix/externalscripts/camcheck.py /usr/lib/zabbix/externalscripts/baseline.py /usr/lib/zabbix/externalscripts/param.py
    ```

---

## Использование

```bash
./camcheck.py <IP-адрес камеры> [--logfile /path/to/log] [--debug] [--username USERNAME] [--password PASSWORD] [--ping-timeout SECONDS]
```

Опции:
- `--logfile` — путь для записи логов (только для отладки);
- `--debug` — включить подробное логирование;
- `--username` — имя пользователя для камеры;
- `--password` — пароль пользователя;
- `--ping-timeout` — таймаут проверки доступности, сек.



На выходе скрипт возвращает JSON, например:

```json
{
    "Manufacturer": "ActiveCam",
    "Model": "AC-D8111IR2",
    "FirmwareVersion": "IPCAM_V2.46.170906",
    "SerialNumber": "D8111IR2M07Z031870873",
    "HardwareId": "600110002-BV-H1002",
    "HwAddress": "f0:23:b9:45:33:69",
    "Address": "10.0.6.101",
    "DNSname": null,
    "TimeSyncOK": true,
    "TimeDifferenceSeconds": 0,
    "NewUsersDetected": false,
    "NewUsernames": [],
    "BaselineCreated": false,
    "UserCount": 1,
    "RTSPPort": 101,
    "RTSPPath": "/live/main",
    "status": "ok",
    "frames_read": 53,
    "avg_frame_size_kb": 3600.0,
    "width": 1280,
    "height": 960,
    "avg_brightness": 131.98,
    "frame_change_level": 0.1,
    "real_fps": 17.67,
    "note": ""
}
```

---

## Базовая линия пользователей

Скрипт сохраняет найденных пользователей, пароль и параметры подключения в каталог
`onvif_audit`. Для каждой камеры создаются файлы `<IP>_users.json` и
`<IP>_progress.json`, позволяющие отслеживать изменения учётных записей и не
повторять уже проверенные пароли.

---

## Интеграция с Zabbix

- Тип элемента данных: `External Check`
- Ключ вызова:  
  ```bash
  camcheck.py["{HOST.IP}"]
  ```
- Тип данных: **Текст**
- Предобработка на элементе:
  - **JSONPath** для извлечения нужных полей (например, `$.status`, `$.TimeSyncOK`).

На основе полей можно строить триггеры:
- "Камера недоступна по ONVIF"
- "Ошибка подключения RTSP-потока"
- "Обнаружен новый пользователь на камере"
- "Сильное расхождение времени"

---

## Параметры

| Параметр | Описание | Значение по умолчанию |
|:--------|:---------|:---------------------|
| `DEFAULT_USERNAME` | Имя пользователя по умолчанию | `admin` |
| `DEFAULT_PASSWORD` | Пароль по умолчанию для начальных попыток | `000000` |
| `PASSWORDS` | Список известных паролей для подбора | `["admin", "12345678", "000000"]` |
| `ALLOWED_TIME_DIFF_SECONDS` | Допустимое расхождение времени UTC, сек | `120` |
| `PORTS_TO_CHECK` | Список портов для проверки ONVIF | `[80, 8000, 8080, 8899, 10554, 10080, 554, 37777, 5000, 443]` |
| `MAX_PASSWORD_ATTEMPTS` | Максимальное число попыток подбора пароля | `5` |
| `MAX_MAIN_ATTEMPTS` | Максимальное число основных попыток соединения | `3` |
| `RTSP_PATH_CANDIDATES` | Список типовых RTSP-путей при отсутствии данных от ONVIF | `["/Streaming/Channels/101", "/h264", "/live", "/stream1"]` |
| `DEFAULT_RTSP_PORT` | RTSP-порт по умолчанию | `554` |
| `CV2_OPEN_TIMEOUT_MS` | Таймаут открытия RTSP в OpenCV, мс | `5000` |
| `CV2_READ_TIMEOUT_MS` | Таймаут чтения кадра в OpenCV, мс | `5000` |

---

## Требования

**Все зависимости обязательны!**

- Python 3.11+
- Установленные библиотеки Python (см. `requirements.txt`):
  - `onvif` (пакет `onvif-zeep`)
  - `opencv-python`
  - `numpy`
  - `zeep`
- Установленные системные утилиты `ffmpeg` и `ffprobe`
---

## TODO

- ✅ Базовая поддержка ONVIF и RTSP камер.
- ✅ Проверка времени и аудит пользователей.
- ✅ Интеграция в Zabbix через внешние обработки.
- [ ] Шаблон для Zabbix 7.0, 7.2
- [ ] Поддержка аутентификации через Digest (для некоторых моделей камер).
- [ ] Добавление опции асинхронной проверки нескольких камер одновременно.
- [ ] Автоматическая регистрация новых устройств через Zabbix LLD.
- ✅ Расширенная диагностика RTSP потока: битрейт, кодек, аудио-потоки.
- [ ] Добавить поддержку шифрованного подключения через HTTPS для ONVIF.
- [ ] Улучшение обработки ошибок и логирование в отдельный файл.


---

## Лицензия

MIT License — свободное использование и модификация с сохранением авторства.

---

## Авторы

- [RoganovDA](https://github.com/RoganovDA)

---



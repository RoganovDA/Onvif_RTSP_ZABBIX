# ONVIF/RTSP Camera Audit Script

📷 Скрипт для автоматического аудита IP-камер с поддержкой ONVIF и RTSP.  
Разработан для интеграции с системами мониторинга, такими как **Zabbix** через внешние обработки.

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

## Установка

1. Установить зависимости:
    ```bash
    pip install onvif-zeep opencv-python numpy
    ```

2. Установить ffmpeg (если используется проверка потока через ffprobe):
    ```bash
    sudo apt install ffmpeg
    ```

3. Поместить скрипт в директорию `externalscripts` Zabbix сервера:
    ```bash
    cp camera_audit.py /usr/lib/zabbix/externalscripts/
    chmod +x /usr/lib/zabbix/externalscripts/camera_audit.py
    ```

---

## Использование

```bash
./camera_audit.py <IP-адрес камеры>
```

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

## Интеграция с Zabbix

- Тип элемента данных: `External Check`
- Ключ вызова:  
  ```bash
  camera_audit.py["{HOST.IP}"]
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
| `ALLOWED_TIME_DIFF_SECONDS` | Допустимое расхождение времени UTC, сек | `120` |
| `PORTS_TO_CHECK` | Список портов для проверки ONVIF | `[80, 8000, 8080, 8899, 10554, 10080, 554, 37777, 5000, 443]` |
| `PASSWORDS` | Список известных паролей для подбора | `["admin", "12345678", "PASS3"]` |

---

## Требования

**Все зависимости обязательны!**

- Python 3.6+
- Установленные библиотеки Python:
  - `onvif` (пакет `onvif-zeep`)
  - `opencv-python`
  - `numpy`
  - `zeep`
- Установленный `ffmpeg` (для опции fallback-проверки RTSP через ffprobe)


---

## Лицензия

MIT License.

---

## Авторы

- [RoganovDA](https://github.com/RoganovDA)

---



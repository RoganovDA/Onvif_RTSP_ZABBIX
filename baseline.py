import os
import json
import logging

if os.name == "nt":
    try:
        import portalocker

        LOCK_EX = portalocker.LOCK_EX
        LOCK_UN = portalocker.LOCK_UN

        def flock(f, flag):
            if flag == LOCK_UN:
                portalocker.unlock(f)
            else:
                portalocker.lock(f, flag)
    except ImportError:
        import msvcrt

        LOCK_EX = msvcrt.LK_LOCK
        LOCK_UN = msvcrt.LK_UNLCK

        def flock(f, flag):
            size = os.path.getsize(f.name)
            try:
                if size == 0:
                    raise OSError("Cannot lock empty file")
                msvcrt.locking(f.fileno(), flag, size)
            except OSError as e:
                logging.warning("Locking failed for %s: %s", f.name, e)
else:
    import fcntl
    LOCK_EX = fcntl.LOCK_EX
    LOCK_UN = fcntl.LOCK_UN

    def flock(f, flag):
        fcntl.flock(f, flag)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AUDIT_DIR = os.path.join(BASE_DIR, "onvif_audit")


def load_progress(ip):
    path = os.path.join(AUDIT_DIR, f"{ip}_progress.json")
    if not os.path.exists(path):
        return {"tried_passwords": [], "next_allowed": None}
    try:
        with open(path, "r+", encoding="utf-8") as f:
            flock(f, LOCK_EX)
            try:
                data = json.load(f)
            finally:
                flock(f, LOCK_UN)
        if not isinstance(data, dict):
            raise ValueError
        data.setdefault("tried_passwords", [])
        if not isinstance(data.get("next_allowed"), str):
            data["next_allowed"] = None
        return data
    except Exception:
        try:
            os.remove(path)
        except OSError:
            pass
        return {"tried_passwords": [], "next_allowed": None}


def save_progress(ip, data):
    os.makedirs(AUDIT_DIR, exist_ok=True)
    path = os.path.join(AUDIT_DIR, f"{ip}_progress.json")
    tmp_path = f"{path}.tmp"
    try:
        with open(path, "a+", encoding="utf-8") as lock_file:
            flock(lock_file, LOCK_EX)
            try:
                lock_file.seek(0)
                try:
                    existing = json.load(lock_file)
                    if not isinstance(existing, dict):
                        existing = {}
                except Exception:
                    existing = {}
                existing.update({k: v for k, v in data.items() if v is not None})
                if "next_allowed" in data and data.get("next_allowed") is None:
                    existing.pop("next_allowed", None)
                with open(tmp_path, "w", encoding="utf-8") as f:
                    json.dump(existing, f, indent=2, ensure_ascii=False)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp_path, path)
            finally:
                flock(lock_file, LOCK_UN)
    except Exception:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise


def remove_progress(ip):
    path = os.path.join(AUDIT_DIR, f"{ip}_progress.json")
    if os.path.exists(path):
        os.remove(path)


def load_baseline(ip):
    path = os.path.join(AUDIT_DIR, f"{ip}_users.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r+", encoding="utf-8") as f:
            flock(f, LOCK_EX)
            try:
                data = json.load(f)
            finally:
                flock(f, LOCK_UN)
    except json.JSONDecodeError:
        remove_baseline(ip)
        return None
    if isinstance(data, list):
        upgraded = {
            "users": data,
            "password": "",
            "port": None,
            "rtsp_port": None,
            "rtsp_path": None,
            "open_methods": [],
            "protected_methods": [],
            "unsupported_methods": [],
            "method_status": {},
            "last_auth_status": None,
            "lockout_until": None,
            "lockout_message": None,
            "last_endpoints": {},
            "last_good_stream_uri": None,
            "rtsp_best_path": None,
            "cooldown_until": None,
            "rtsp_attempts": [],
            "rtsp_color_analysis": None,
            "rtsp_color_channels": None,
            "rtsp_color_balance": None,
            "rtsp_color_ratios": None,
            "rtsp_color_variance": None,
        }
        save_baseline(ip, upgraded)
        logging.info("Upgraded old baseline format for %s", ip)
        return upgraded
    required_keys = {"users", "password", "port", "rtsp_port", "rtsp_path"}
    if not required_keys.issubset(data.keys()):
        remove_baseline(ip)
        return None
    defaults = {
        "open_methods": [],
        "protected_methods": [],
        "unsupported_methods": [],
        "method_status": {},
        "last_auth_status": None,
        "lockout_until": None,
        "lockout_message": None,
        "last_endpoints": {},
        "last_good_stream_uri": None,
        "rtsp_best_path": None,
        "cooldown_until": None,
        "rtsp_attempts": [],
        "rtsp_color_analysis": None,
        "rtsp_color_channels": None,
        "rtsp_color_balance": None,
        "rtsp_color_ratios": None,
        "rtsp_color_variance": None,
    }
    for key, default in defaults.items():
        if key not in data or data[key] is None:
            data[key] = default
    if not isinstance(data.get("last_endpoints"), dict):
        data["last_endpoints"] = {}
    if not isinstance(data.get("rtsp_attempts"), list):
        data["rtsp_attempts"] = []
    return data


def save_baseline(ip, data):
    os.makedirs(AUDIT_DIR, exist_ok=True)
    path = os.path.join(AUDIT_DIR, f"{ip}_users.json")
    tmp_path = f"{path}.tmp"
    try:
        with open(path, "a+", encoding="utf-8") as lock_file:
            flock(lock_file, LOCK_EX)
            try:
                with open(tmp_path, "w", encoding="utf-8") as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp_path, path)
            finally:
                flock(lock_file, LOCK_UN)
    except Exception:
        try:
            os.remove(tmp_path)
        except OSError:
            pass
        raise


def remove_baseline(ip):
    path = os.path.join(AUDIT_DIR, f"{ip}_users.json")
    if os.path.exists(path):
        os.remove(path)

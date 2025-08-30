import datetime
import logging
import socket
import time
from urllib.parse import urlparse, quote

from onvif import ONVIFCamera
from onvif.exceptions import ONVIFError
from zeep.exceptions import Fault

from baseline import (
    load_baseline,
    save_baseline,
    remove_baseline,
    load_progress,
    save_progress,
)
from rtsp_utils import fallback_ffprobe
# Parameter constants
from param import (
    PASSWORDS,
    MAX_PASSWORD_ATTEMPTS,
    RTSP_PATH_CANDIDATES,
    DEFAULT_RTSP_PORT,
    DEFAULT_USERNAME,
    DEFAULT_PASSWORD,
)


def safe_call(service, method_name, params=None):
    try:
        method = getattr(service, method_name)
        return method(params) if params else method()
    except Exception as e:
        return {"error": str(e)}


def parse_datetime(dt_info):
    try:
        utc_date = dt_info.UTCDateTime.Date
        utc_time = dt_info.UTCDateTime.Time
        return datetime.datetime(
            year=utc_date.Year,
            month=utc_date.Month,
            day=utc_date.Day,
            hour=utc_time.Hour,
            minute=utc_time.Minute,
            second=utc_time.Second,
        )
    except Exception:
        return None


def error_matches(err, keywords):
    for attr in ("code", "detail"):
        val = getattr(err, attr, None)
        if val and any(k in str(val).lower() for k in keywords):
            return True
        if getattr(err, "args", None):
            for arg in err.args:
                if any(k in str(arg).lower() for k in keywords):
                    return True
    return False


def try_onvif_connection(ip, port, username=DEFAULT_USERNAME, password=DEFAULT_PASSWORD):
    try:
        camera = ONVIFCamera(ip, port, username, password)
        devicemgmt_service = camera.create_devicemgmt_service()
        users = devicemgmt_service.GetUsers()
        if users:
            return True
    except (Fault, ONVIFError) as err:
        if error_matches(err, ["notauthorized", "unauthorized"]):
            return "unauthorized"
        if error_matches(err, ["locked", "devicelocked", "passwordlocked", "accountlocked"]):
            return "locked"
        msg = str(err)
        msg_lower = msg.lower()
        if any(x in msg_lower for x in ["401", "unauthorized", "not authorized"]):
            return "unauthorized"
        if "lock" in msg_lower:
            return "locked"
        logging.error("ONVIF connection error on %s:%s - %s", ip, port, msg)
    except Exception as err:
        if error_matches(err, ["locked", "devicelocked", "passwordlocked", "accountlocked"]):
            return "locked"
        msg = str(err)
        if "lock" in msg.lower():
            return "locked"
        logging.error("ONVIF connection error on %s:%s - %s", ip, port, msg)
    return False


def find_onvif_port(ip, ports, username=DEFAULT_USERNAME, password=DEFAULT_PASSWORD, timeout=2):
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                status = try_onvif_connection(ip, port, username, password)
                if status is True:
                    return port
                if status == "unauthorized":
                    return "unauthorized"
                if status == "locked":
                    return "locked"
        except Exception:
            continue
    return None


def find_working_credentials(ip, ports, username=DEFAULT_USERNAME):
    baseline = load_baseline(ip)
    progress = load_progress(ip)
    tried_passwords = progress.get("tried_passwords", [])
    attempts_this_run = 0

    def mark_tried(pw):
        nonlocal attempts_this_run
        if pw not in tried_passwords:
            tried_passwords.append(pw)
            attempts_this_run += 1
            save_progress(ip, {"tried_passwords": tried_passwords})

    if baseline:
        password = baseline.get("password")
        port = baseline.get("port")
        if password and password not in tried_passwords:
            if attempts_this_run >= MAX_PASSWORD_ATTEMPTS:
                return None, None
            mark_tried(password)
            if port:
                status = try_onvif_connection(ip, port, username, password)
                if status is True:
                    return port, password
                if status == "locked":
                    remove_baseline(ip)
                    return None, None
                if status == "unauthorized":
                    remove_baseline(ip)
                    baseline = None
                    password = None
                    port = None
            if password:
                port = find_onvif_port(ip, ports, username=username, password=password)
                if port == "locked":
                    remove_baseline(ip)
                    return None, None
                if port == "unauthorized":
                    remove_baseline(ip)
                    baseline = None
                    password = None
                elif port:
                    return port, password
        remove_baseline(ip)
        baseline = None
        password = None
        port = None

    for password in PASSWORDS:
        if attempts_this_run >= MAX_PASSWORD_ATTEMPTS:
            break
        if password in tried_passwords:
            continue
        mark_tried(password)
        port = find_onvif_port(ip, ports, username=username, password=password)
        if port == "locked":
            return None, None
        if port == "unauthorized":
            continue
        if port:
            return port, password
    remaining = [p for p in PASSWORDS if p not in tried_passwords]
    if not remaining:
        remove_baseline(ip)
    return None, None


def normalize_rtsp_path(path):
    if not path:
        return None
    return '/' + path.lstrip('/')


def get_rtsp_info(camera, ip, username, password):
    try:
        media_service = camera.create_media_service()
        profiles = media_service.GetProfiles()
        if profiles:
            profile_token = profiles[0].token
            stream_uri_request = media_service.create_type('GetStreamUri')
            stream_uri_request.StreamSetup = {
                'Stream': 'RTP-Unicast',
                'Transport': {'Protocol': 'RTSP'}
            }
            stream_uri_request.ProfileToken = profile_token
            uri_info = media_service.GetStreamUri(stream_uri_request)
            parsed_uri = urlparse(uri_info.Uri)
            path = parsed_uri.path or ""
            if parsed_uri.query:
                path += "?" + parsed_uri.query
            return parsed_uri.port, normalize_rtsp_path(path)
    except Exception:
        logging.error("ONVIF GetStreamUri failed", exc_info=True)

    start = time.time()
    port = DEFAULT_RTSP_PORT
    for path in RTSP_PATH_CANDIDATES:
        if time.time() - start > 5:
            break
        u = quote(username, safe='')
        p = quote(password, safe='')
        path_enc = quote(path, safe='/?:=&')
        test_url = f"rtsp://{u}:{p}@{ip}:{port}{path_enc}"
        logging.info("Trying candidate RTSP path %s", path)
        probe = fallback_ffprobe(test_url, timeout=1)
        status = probe.get("status")
        if status == "unauthorized":
            logging.error("RTSP path %s unauthorized", path)
            return None, None
        if status == "ok":
            logging.info("RTSP path %s successful", path)
            return port, path
    logging.error("No RTSP path candidates succeeded for %s", ip)
    return None, None

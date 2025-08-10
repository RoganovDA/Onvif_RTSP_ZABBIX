#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
import json
import datetime
import socket
import os
import subprocess
import time
import contextlib
import argparse
import logging
import shutil
import select
import fcntl

pre_parser = argparse.ArgumentParser(add_help=False)
pre_parser.add_argument("--logfile")
pre_args, _ = pre_parser.parse_known_args()

logging.basicConfig(
    level=logging.INFO,
    filename=pre_args.logfile,
    filemode="a" if pre_args.logfile else None,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

try:
    import cv2
    if hasattr(cv2, "utils") and hasattr(cv2.utils, "logging"):
        cv2.utils.logging.setLogLevel(cv2.utils.logging.LOG_LEVEL_SILENT)
except Exception as e:
    logging.error("Failed to import cv2: %s", e)
    print(json.dumps({"error": "OpenCV (cv2) library not installed"}))
    sys.exit(2)

try:
    import numpy as np
except Exception as e:
    logging.error("Failed to import numpy: %s", e)
    print(json.dumps({"error": "NumPy library not installed"}))
    sys.exit(3)

from urllib.parse import urlparse
from onvif import ONVIFCamera
from onvif.exceptions import ONVIFError
from zeep.exceptions import Fault

# === Новый фикс ===
os.environ["HOME"] = "/tmp"
os.environ["TMPDIR"] = "/tmp"
# ==================

ALLOWED_TIME_DIFF_SECONDS = 120
PORTS_TO_CHECK = [80, 8000, 8080, 8899, 10554, 10080, 554, 37777, 5000, 443]
PASSWORDS = ["admin", "12345678", "123456"]
MAX_PASSWORD_ATTEMPTS = 5
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AUDIT_DIR = os.path.join(BASE_DIR, "onvif_audit")

# Configurable timeouts for OpenCV RTSP handling (milliseconds)
CV2_OPEN_TIMEOUT_MS = 5000
CV2_READ_TIMEOUT_MS = 5000

# Limit main loop to avoid infinite retries
MAX_MAIN_ATTEMPTS = 3


# progress.json format: {"tried_passwords": ["pwd1", "pwd2", ...]}
def load_progress(ip):
    path = os.path.join(AUDIT_DIR, f"{ip}_progress.json")
    if not os.path.exists(path):
        return {"tried_passwords": []}
    try:
        with open(path, "r+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                data = json.load(f)
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
        if not isinstance(data, dict):
            raise ValueError
        data.setdefault("tried_passwords", [])
        return data
    except Exception:
        try:
            os.remove(path)
        except OSError:
            pass
        return {"tried_passwords": []}


def save_progress(ip, data):
    os.makedirs(AUDIT_DIR, exist_ok=True)
    path = os.path.join(AUDIT_DIR, f"{ip}_progress.json")
    tmp_path = f"{path}.tmp"
    try:
        with open(path, "a+") as lock_file:
            fcntl.flock(lock_file, fcntl.LOCK_EX)
            try:
                with open(tmp_path, "w") as f:
                    json.dump(data, f, indent=2)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp_path, path)
            finally:
                fcntl.flock(lock_file, fcntl.LOCK_UN)
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
            second=utc_time.Second
        )
    except Exception:
        return None


def try_onvif_connection(ip, port, username='admin', password='000000'):
    try:
        camera = ONVIFCamera(ip, port, username, password)
        devicemgmt_service = camera.create_devicemgmt_service()
        users = devicemgmt_service.GetUsers()
        if users:
            return True
    except (Fault, ONVIFError) as err:
        msg = str(err)
        msg_lower = msg.lower()
        if '401' in msg_lower or 'unauthorized' in msg_lower or 'not authorized' in msg_lower:
            return "unauthorized"
        if 'device is locked' in msg_lower:
            return "locked"
        logging.error("ONVIF connection error on %s:%s - %s", ip, port, msg)
    except Exception as e:
        msg = str(e)
        if 'device is locked' in msg.lower():
            return "locked"
        logging.error("ONVIF connection error on %s:%s - %s", ip, port, msg)
    return False


def find_onvif_port(ip, ports, username='admin', password='000000', timeout=2):
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


def load_baseline(ip):
    path = os.path.join(AUDIT_DIR, f"{ip}_users.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r+") as f:
            fcntl.flock(f, fcntl.LOCK_EX)
            try:
                data = json.load(f)
            finally:
                fcntl.flock(f, fcntl.LOCK_UN)
    except json.JSONDecodeError:
        remove_baseline(ip)
        return None
    if isinstance(data, list):
        # Auto-upgrade very old format (list of usernames) to new format
        upgraded = {
            "users": data,
            "password": "",
            "port": None,
            "rtsp_port": None,
            "rtsp_path": None,
        }
        save_baseline(ip, upgraded)
        logging.info("Upgraded old baseline format for %s", ip)
        return upgraded

    required_keys = {"users", "password", "port", "rtsp_port", "rtsp_path"}
    if not required_keys.issubset(data.keys()):
        remove_baseline(ip)
        return None
    return data


def save_baseline(ip, data):
    os.makedirs(AUDIT_DIR, exist_ok=True)
    path = os.path.join(AUDIT_DIR, f"{ip}_users.json")
    tmp_path = f"{path}.tmp"
    try:
        with open(path, "a+") as lock_file:
            fcntl.flock(lock_file, fcntl.LOCK_EX)
            try:
                with open(tmp_path, "w") as f:
                    json.dump(data, f, indent=2)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp_path, path)
            finally:
                fcntl.flock(lock_file, fcntl.LOCK_UN)
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


def find_working_credentials(ip, ports, username='admin'):
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
            return parsed_uri.port, normalize_rtsp_path(parsed_uri.path)
    except Exception:
        logging.error("ONVIF GetStreamUri failed", exc_info=True)

    # Fallback candidate paths
    candidates = ["/Streaming/Channels/101", "/h264", "/live", "/stream1"]
    start = time.time()
    port = 554
    for path in candidates:
        if time.time() - start > 5:
            break
        test_url = f"rtsp://{username}:{password}@{ip}:{port}{path}"
        logging.info("Trying candidate RTSP path %s", path)
        probe = fallback_ffprobe(test_url, timeout=1)
        if probe.get("status") == "ok":
            logging.info("RTSP path %s successful", path)
            return port, path
    logging.error("No RTSP path candidates succeeded for %s", ip)
    return None, None



@contextlib.contextmanager
def suppress_stderr():
    with open(os.devnull, 'w') as devnull:
        stderr_fd = sys.stderr.fileno()
        saved_stderr_fd = os.dup(stderr_fd)
        os.dup2(devnull.fileno(), stderr_fd)
        try:
            yield
        finally:
            os.dup2(saved_stderr_fd, stderr_fd)
            os.close(saved_stderr_fd)

def check_rtsp_stream(url, timeout=5, duration=5.0):
    start_time = time.time()
    result = {
        "status": "error",
        "frames_read": 0,
        "avg_frame_size_kb": 0.0,
        "width": None,
        "height": None,
        "avg_brightness": 0.0,
        "frame_change_level": 0.0,
        "real_fps": 0.0,
        "note": "Failed to open stream",
    }

    with suppress_stderr():
        cap = cv2.VideoCapture(url, cv2.CAP_FFMPEG)

        if not cap.isOpened():
            cap.release()
            cmd = [
                "ffprobe", "-v", "error",
                "-rtsp_transport", "tcp",
                "-timeout", str(int(timeout * 1e6)),
                "-i", url,
            ]
            try:
                p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
                err_out = (p.stderr or "") + (p.stdout or "")
                err_lower = err_out.lower()
                if "401" in err_lower or "unauthorized" in err_lower or "not authorized" in err_lower:
                    return {"status": "unauthorized"}
            except Exception:
                pass
            return result

        frames, sizes, brightness, change_levels = 0, [], [], []
        prev_gray = None
        width = height = None

        while time.time() - start_time < duration:
            ret, frame = cap.read()
            if not ret or frame is None or frame.size == 0:
                continue

            frames += 1
            sizes.append(frame.nbytes)
            height, width = frame.shape[:2]

            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            brightness.append(np.mean(gray))

            if prev_gray is not None:
                delta = np.mean(np.abs(gray.astype("int16") - prev_gray.astype("int16")))
                change_levels.append(delta)

            prev_gray = gray

        cap.release()

    if frames > 0:
        result.update({
            "status": "ok",
            "frames_read": frames,
            "avg_frame_size_kb": round(sum(sizes) / len(sizes) / 1024, 2),
            "width": width,
            "height": height,
            "avg_brightness": round(np.mean(brightness), 2),
            "frame_change_level": round(np.mean(change_levels), 2) if change_levels else 0.0,
            "real_fps": round(frames / duration, 2),
            "note": "",
        })
    else:
        result["note"] = "Connected but no valid frames"

    return result


def fallback_ffprobe(url, timeout=5, transport="tcp"):
    timeout_us = str(int(timeout * 1e6))
    logging.info("ffprobe stimeout=%s", timeout_us)
    cmd = [
        "ffprobe", "-v", "error",
        "-rtsp_transport", transport,
        "-stimeout", timeout_us,
        "-i", url,
        "-select_streams", "v:0",
        "-show_entries", "stream=width,height,codec_name",
        "-of", "json",
    ]
    try:
        with suppress_stderr():
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
        err_out = (p.stderr or "") + (p.stdout or "")
        err_lower = err_out.lower()
        if "401" in err_lower or "unauthorized" in err_lower or "not authorized" in err_lower:
            return {"status": "unauthorized"}
        info = json.loads(p.stdout or "{}")
        if info.get("streams"):
            stream = info["streams"][0]
            return {
                "status": "ok",
                "width": stream.get("width"),
                "height": stream.get("height"),
            }
    except Exception as e:
        logging.error("ffprobe error: %s", e, exc_info=True)
    return {"status": "error"}


def read_exact(stream, size, poller, timeout):
    data = bytearray()
    while len(data) < size:
        if not poller.poll(timeout * 1000):
            break
        chunk = stream.read(size - len(data))
        if not chunk:
            break
        data.extend(chunk)
    return bytes(data)


def check_rtsp_stream_with_fallback(url, timeout=5, duration=5.0):
    def _append_transport(u, transport):
        return f"{u}{'&' if '?' in u else '?'}rtsp_transport={transport}"

    def _attempt(full_url, transport):
        result = {
            "status": "error",
            "frames_read": 0,
            "avg_frame_size_kb": 0.0,
            "width": None,
            "height": None,
            "avg_brightness": 0.0,
            "frame_change_level": 0.0,
            "real_fps": 0.0,
            "note": "Failed to open stream",
        }
        start_time = time.time()
        frames, sizes, brightness, change_levels = 0, [], [], []
        prev_gray = None
        with suppress_stderr():
            cap = cv2.VideoCapture(full_url, cv2.CAP_FFMPEG)
            if hasattr(cv2, "CAP_PROP_OPEN_TIMEOUT"):
                if not cap.set(cv2.CAP_PROP_OPEN_TIMEOUT, CV2_OPEN_TIMEOUT_MS):
                    logging.warning("Failed to set CAP_PROP_OPEN_TIMEOUT")
            else:
                logging.warning("CAP_PROP_OPEN_TIMEOUT not supported")
            if hasattr(cv2, "CAP_PROP_READ_TIMEOUT"):
                if not cap.set(cv2.CAP_PROP_READ_TIMEOUT, CV2_READ_TIMEOUT_MS):
                    logging.warning("Failed to set CAP_PROP_READ_TIMEOUT")
            else:
                logging.warning("CAP_PROP_READ_TIMEOUT not supported")

            if not cap.isOpened():
                logging.error("OpenCV could not open stream %s", full_url)
                cap.release()
            else:
                while time.time() - start_time < duration:
                    ret, frame = cap.read()
                    if not ret or frame is None or frame.size == 0:
                        continue
                    frames += 1
                    sizes.append(frame.nbytes)
                    h, w = frame.shape[:2]
                    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                    brightness.append(np.mean(gray))
                    if prev_gray is not None:
                        delta = np.mean(np.abs(gray.astype("int16") - prev_gray.astype("int16")))
                        change_levels.append(delta)
                    prev_gray = gray
                cap.release()

        if frames > 0:
            result.update({
                "status": "ok",
                "frames_read": frames,
                "avg_frame_size_kb": round(sum(sizes) / len(sizes) / 1024, 2),
                "width": w,
                "height": h,
                "avg_brightness": round(np.mean(brightness), 2),
                "frame_change_level": round(np.mean(change_levels), 2) if change_levels else 0.0,
                "real_fps": round(frames / duration, 2),
                "note": "Read via OpenCV",
            })
            return result

        probe = fallback_ffprobe(full_url, timeout, transport)
        if probe.get("status") == "unauthorized":
            return {"status": "unauthorized"}

        width = probe.get("width")
        height = probe.get("height")

        if width is None or height is None:
            with suppress_stderr():
                cap_dim = cv2.VideoCapture(full_url, cv2.CAP_FFMPEG)
                if cap_dim.isOpened():
                    tmp_w = int(cap_dim.get(cv2.CAP_PROP_FRAME_WIDTH))
                    tmp_h = int(cap_dim.get(cv2.CAP_PROP_FRAME_HEIGHT))
                    if tmp_w > 0 and tmp_h > 0:
                        width = width or tmp_w
                        height = height or tmp_h
                    else:
                        ret_dim, frame_dim = cap_dim.read()
                        if ret_dim and frame_dim is not None and frame_dim.size > 0:
                            height, width = frame_dim.shape[:2]
                cap_dim.release()

        width = width or 1280
        height = height or 720

        try:
            cmd = [
                "ffmpeg", "-rtsp_transport", transport, "-i", full_url,
                "-loglevel", "error", "-an", "-c:v", "rawvideo",
                "-pix_fmt", "bgr24", "-f", "rawvideo", "-",
            ]
            with suppress_stderr():
                pipe = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=10**8)

            fcntl.fcntl(pipe.stdout.fileno(), fcntl.F_SETFL, os.O_NONBLOCK)
            poller = select.poll()
            poller.register(pipe.stdout, select.POLLIN)

            frames, sizes, brightness, change_levels = 0, [], [], []
            prev_gray = None
            start_time = time.time()
            expected_len = width * height * 3

            while time.time() - start_time < duration:
                raw = read_exact(pipe.stdout, expected_len, poller, timeout)
                actual_len = len(raw)
                if actual_len != expected_len:
                    logging.warning(
                        "Expected frame size %d bytes, got %d", expected_len, actual_len
                    )
                    break
                frame = np.frombuffer(raw, np.uint8).reshape((height, width, 3))
                frames += 1
                sizes.append(frame.nbytes)
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                brightness.append(np.mean(gray))
                if prev_gray is not None:
                    delta = np.mean(np.abs(gray.astype("int16") - prev_gray.astype("int16")))
                    change_levels.append(delta)
                prev_gray = gray

            poller.unregister(pipe.stdout)
            pipe.terminate()
            try:
                pipe.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pipe.kill()
                pipe.wait()
            stderr_data = pipe.stderr.read().decode(errors="ignore") if pipe.stderr else ""
            if pipe.stdout:
                pipe.stdout.close()
            if pipe.stderr:
                pipe.stderr.close()
            if "401" in stderr_data or "Unauthorized" in stderr_data:
                return {"status": "unauthorized"}

            if frames > 0:
                result.update({
                    "status": "ok",
                    "frames_read": frames,
                    "avg_frame_size_kb": round(sum(sizes) / len(sizes) / 1024, 2),
                    "width": width,
                    "height": height,
                    "avg_brightness": round(np.mean(brightness), 2),
                    "frame_change_level": round(np.mean(change_levels), 2) if change_levels else 0.0,
                    "real_fps": round(frames / duration, 2),
                    "note": "Read via ffmpeg pipe",
                })
            else:
                result["note"] = "Connected but no valid frames from ffmpeg"

        except Exception as e:
            logging.error("ffmpeg fallback error: %s", e, exc_info=True)
            result["note"] = f"ffmpeg error: {e}"

        return result

    last = None
    for transport in ("tcp", "udp"):
        full = _append_transport(url, transport)
        logging.info("Attempting RTSP with transport %s", transport)
        last = _attempt(full, transport)
        if last.get("status") in ("ok", "unauthorized"):
            return last
    return last






def main():
    parser = argparse.ArgumentParser(description="ONVIF/RTSP Camera Audit Script")
    parser.add_argument("address", nargs="?", help="Camera IP address")
    parser.add_argument("--logfile", help="Path to log file")
    args = parser.parse_args()

    if not args.address:
        print(json.dumps({"error": "Usage: camcheck.py <ADDRESS>"}))
        sys.exit(1)

    address = args.address
    username = 'admin'

    missing_bins = [b for b in ("ffprobe", "ffmpeg") if shutil.which(b) is None]
    if missing_bins:
        msg = f"Missing executables: {', '.join(missing_bins)}"
        logging.error(msg)
        print(json.dumps({"error": msg}))
        sys.exit(4)

    for attempt in range(MAX_MAIN_ATTEMPTS):
        port, password = find_working_credentials(address, PORTS_TO_CHECK, username=username)
        if port is None:
            remove_progress(address)
            print(json.dumps({"error": f"Unable to find working credentials for {address}"}))
            sys.exit(1)

        try:
            camera = ONVIFCamera(address, port, username, password)
            devicemgmt_service = camera.create_devicemgmt_service()

            device_info = safe_call(devicemgmt_service, "GetDeviceInformation")
            datetime_info = safe_call(devicemgmt_service, "GetSystemDateAndTime")
            users = safe_call(devicemgmt_service, "GetUsers")
            interfaces = safe_call(devicemgmt_service, "GetNetworkInterfaces")
            ntp_info = safe_call(devicemgmt_service, "GetNTP")
            dns_info = safe_call(devicemgmt_service, "GetDNS")
            scopes = safe_call(devicemgmt_service, "GetScopes")

            output = {}

            if device_info and not isinstance(device_info, dict):
                output['Manufacturer'] = getattr(device_info, 'Manufacturer', None)
                output['Model'] = getattr(device_info, 'Model', None)
                output['FirmwareVersion'] = getattr(device_info, 'FirmwareVersion', None)
                output['SerialNumber'] = getattr(device_info, 'SerialNumber', None)
                output['HardwareId'] = getattr(device_info, 'HardwareId', None)

            if isinstance(interfaces, list) and interfaces:
                interface = interfaces[0]
                info = getattr(interface, 'Info', None)
                ipv4 = getattr(interface, 'IPv4', None)
                config = getattr(ipv4, 'Config', None) if ipv4 else None
                from_dhcp = getattr(config, 'FromDHCP', None) if config else None
                output['HwAddress'] = getattr(info, 'HwAddress', None) if info else None
                output['Address'] = getattr(from_dhcp, 'Address', None) if from_dhcp else None

            output['DNSname'] = None

            if ntp_info and not isinstance(ntp_info, dict):
                for key in ('NTPManual', 'NTPFromDHCP'):
                    entries = getattr(ntp_info, key, [])
                    if isinstance(entries, list):
                        for entry in entries:
                            for attr in ('DNSname', 'IPv4Address'):
                                val = getattr(entry, attr, None)
                                if val:
                                    output['DNSname'] = val
                                    break
                            if output['DNSname']:
                                break
                    if output['DNSname']:
                        break

            now_utc = datetime.datetime.utcnow()
            camera_utc = parse_datetime(datetime_info)
            if camera_utc:
                delta = abs((now_utc - camera_utc).total_seconds())
                output['TimeSyncOK'] = delta <= ALLOWED_TIME_DIFF_SECONDS
                output['TimeDifferenceSeconds'] = int(delta)
            else:
                output['TimeSyncOK'] = False
                output['TimeDifferenceSeconds'] = None

            usernames = [user.Username for user in users] if isinstance(users, list) else []

            baseline = load_baseline(address)

            rtsp_port = baseline.get("rtsp_port") if baseline else None
            rtsp_path = normalize_rtsp_path(baseline.get("rtsp_path")) if baseline else None
            if not (rtsp_port and rtsp_path):
                rtsp_port, rtsp_path = get_rtsp_info(camera, address, username, password)
            rtsp_path = normalize_rtsp_path(rtsp_path)

            if baseline is None:
                save_baseline(address, {
                    "users": usernames,
                    "password": password,
                    "port": port,
                    "rtsp_port": rtsp_port,
                    "rtsp_path": rtsp_path,
                })
                output['NewUsersDetected'] = False
                output['BaselineCreated'] = True
            else:
                new_users = list(set(usernames) - set(baseline.get("users", [])))
                output['NewUsersDetected'] = len(new_users) > 0
                output['NewUsernames'] = new_users
                output['BaselineCreated'] = False
                updated = False
                if (
                    baseline.get("password") != password
                    or baseline.get("port") != port
                    or baseline.get("rtsp_port") != rtsp_port
                    or baseline.get("rtsp_path") != rtsp_path
                ):
                    baseline.update({
                        "password": password,
                        "port": port,
                        "rtsp_port": rtsp_port,
                        "rtsp_path": rtsp_path,
                    })
                    updated = True
                if baseline.get("users") != usernames:
                    baseline["users"] = usernames
                    updated = True
                if updated:
                    save_baseline(address, baseline)

            output['UserCount'] = len(usernames)

            output['RTSPPort'] = rtsp_port
            output['RTSPPath'] = rtsp_path

            if rtsp_port and rtsp_path:
                rtsp_url = f"rtsp://{username}:{password}@{address}:{rtsp_port}{rtsp_path}"
                rtsp_info = check_rtsp_stream_with_fallback(rtsp_url)
                if rtsp_info["status"] == "unauthorized":
                    remove_baseline(address)
                    continue
                if rtsp_info["status"] != "ok":
                    probe_status = fallback_ffprobe(rtsp_url)
                    if probe_status.get("status") == "unauthorized":
                        remove_baseline(address)
                        continue
                    if probe_status.get("status") == "ok":
                        rtsp_info["status"] = "ok"
                        rtsp_info["note"] += " | Metadata via ffprobe"
                        if not rtsp_info.get("width") and probe_status.get("width"):
                            rtsp_info["width"] = probe_status.get("width")
                            rtsp_info["height"] = probe_status.get("height")
                output.update(rtsp_info)
            else:
                output.update({
                    "status": "no_rtsp",
                    "frames_read": 0,
                    "avg_frame_size_kb": 0,
                    "width": None,
                    "height": None,
                    "avg_brightness": 0,
                    "frame_change_level": 0,
                    "real_fps": 0,
                    "note": "No RTSP URI found",
                })

            print(json.dumps(output, indent=4, ensure_ascii=False, default=str))
            remove_progress(address)
            break

        except Fault as fault:
            logging.error("ONVIF Fault: %s", fault, exc_info=True)
            print(json.dumps({"error": f"ONVIF Fault: {fault}"}))
            sys.exit(1)
        except Exception as e:
            logging.error("General Error: %s", e, exc_info=True)
            print(json.dumps({"error": f"General Error: {e}"}))
            sys.exit(1)

    else:
        remove_progress(address)
        print(json.dumps({"error": "Maximum attempts exceeded"}))
        sys.exit(1)


if __name__ == "__main__":
    main()

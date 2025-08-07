#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
import json
import datetime
import socket
import os
import subprocess
import time
import cv2
import numpy as np
import contextlib

from urllib.parse import urlparse
from onvif import ONVIFCamera
from zeep.exceptions import Fault

# === Новый фикс ===
os.environ["HOME"] = "/tmp"
os.environ["TMPDIR"] = "/tmp"
# ==================

ALLOWED_TIME_DIFF_SECONDS = 120
PORTS_TO_CHECK = [80, 8000, 8080, 8899, 10554, 10080, 554, 37777, 5000, 443]
PASSWORDS = ["admin", "12345678", "123456"]
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
AUDIT_DIR = os.path.join(BASE_DIR, "onvif_audit")


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
        device_info = devicemgmt_service.GetDeviceInformation()
        if device_info:
            return True
    except Exception:
        pass
    return False


def find_onvif_port(ip, ports, username='admin', password='000000', timeout=2):
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                if try_onvif_connection(ip, port, username, password):
                    return port
        except Exception:
            continue
    return None


def load_baseline(ip):
    path = os.path.join(AUDIT_DIR, f"{ip}_users.json")
    if not os.path.exists(path):
        return None
    with open(path, "r") as f:
        data = json.load(f)
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
            print(f"[INFO] Upgraded old baseline format for {ip}")
            return upgraded

        # Ensure all keys exist for forward compatibility
        data.setdefault("users", [])
        data.setdefault("password", "")
        data.setdefault("port", None)
        data.setdefault("rtsp_port", None)
        data.setdefault("rtsp_path", None)
        return data


def save_baseline(ip, data):
    os.makedirs(AUDIT_DIR, exist_ok=True)
    path = os.path.join(AUDIT_DIR, f"{ip}_users.json")
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def remove_baseline(ip):
    path = os.path.join(AUDIT_DIR, f"{ip}_users.json")
    if os.path.exists(path):
        os.remove(path)


def find_working_credentials(ip, ports, username='admin'):
    baseline = load_baseline(ip)
    if baseline:
        password = baseline.get("password")
        port = baseline.get("port")
        if password and port and try_onvif_connection(ip, port, username, password):
            return port, password
        if password:
            port = find_onvif_port(ip, ports, username=username, password=password)
            if port:
                return port, password
        # Baseline credentials didn't work; remove stale baseline
        remove_baseline(ip)

    for password in PASSWORDS:
        port = find_onvif_port(ip, ports, username=username, password=password)
        if port:
            return port, password
    # Nothing worked, ensure baseline is removed
    remove_baseline(ip)
    return None, None


def get_rtsp_info(camera):
    try:
        media_service = camera.create_media_service()
        profiles = media_service.GetProfiles()
        if not profiles:
            return None, None
        profile_token = profiles[0].token
        stream_uri_request = media_service.create_type('GetStreamUri')
        stream_uri_request.StreamSetup = {
            'Stream': 'RTP-Unicast',
            'Transport': {'Protocol': 'RTSP'}
        }
        stream_uri_request.ProfileToken = profile_token
        uri_info = media_service.GetStreamUri(stream_uri_request)
        parsed_uri = urlparse(uri_info.Uri)
        return parsed_uri.port, parsed_uri.path
    except Exception:
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
    cap = cv2.VideoCapture(url, cv2.CAP_FFMPEG)
    result = {
        "status": "error",
        "frames_read": 0,
        "avg_frame_size_kb": 0.0,
        "width": None,
        "height": None,
        "avg_brightness": 0.0,
        "frame_change_level": 0.0,
        "real_fps": 0.0,
        "note": "Failed to open stream"
    }

    if not cap.isOpened():
        cap.release()
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
            "note": ""
        })
    else:
        result["note"] = "Connected but no valid frames"

    return result

def fallback_ffprobe(url, timeout=5):
    cmd = [
        "ffprobe", "-v", "error",
        "-rtsp_transport", "tcp",
        "-timeout", str(int(timeout * 1e6)),
        "-i", url,
        "-select_streams", "v:0",
        "-show_entries", "stream=width,height,codec_name",
        "-of", "json"
    ]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+2)
        info = json.loads(p.stdout)
        if info.get("streams"):
            return True
    except Exception:
        pass
    return False



def check_rtsp_stream_with_fallback(url, timeout=5, duration=5.0, width=1280, height=960):
    import subprocess
    import numpy as np
    import cv2
    import time

    result = {
        "status": "error",
        "frames_read": 0,
        "avg_frame_size_kb": 0.0,
        "width": None,
        "height": None,
        "avg_brightness": 0.0,
        "frame_change_level": 0.0,
        "real_fps": 0.0,
        "note": "Failed to open stream"
    }

    start_time = time.time()
    cap = cv2.VideoCapture(url, cv2.CAP_FFMPEG)
    frames, sizes, brightness, change_levels = 0, [], [], []
    prev_gray = None

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
            "note": "Read via OpenCV"
        })
        return result

    # Если не получили кадры — пробуем через ffmpeg
    try:
        cmd = [
            "ffmpeg", "-rtsp_transport", "tcp", "-i", url,
            "-loglevel", "quiet", "-an", "-c:v", "rawvideo",
            "-pix_fmt", "bgr24", "-f", "rawvideo", "-"
        ]
        pipe = subprocess.Popen(cmd, stdout=subprocess.PIPE, bufsize=10**8)

        frames, sizes, brightness, change_levels = 0, [], [], []
        prev_gray = None
        start_time = time.time()

        while time.time() - start_time < duration:
            raw = pipe.stdout.read(width * height * 3)
            if len(raw) != width * height * 3:
                continue
            frame = np.frombuffer(raw, np.uint8).reshape((height, width, 3))
            frames += 1
            sizes.append(frame.nbytes)
            gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
            brightness.append(np.mean(gray))
            if prev_gray is not None:
                delta = np.mean(np.abs(gray.astype("int16") - prev_gray.astype("int16")))
                change_levels.append(delta)
            prev_gray = gray

        pipe.terminate()

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
                "note": "Read via ffmpeg pipe"
            })
        else:
            result["note"] = "Connected but no valid frames from ffmpeg"

    except Exception as e:
        result["note"] = f"ffmpeg error: {e}"

    return result


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Usage: script.py <ADDRESS>"}))
        sys.exit(1)

    address = sys.argv[1]
    username = 'admin'

    port, password = find_working_credentials(address, PORTS_TO_CHECK, username=username)
    if port is None:
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
        rtsp_path = baseline.get("rtsp_path") if baseline else None
        if not (rtsp_port and rtsp_path):
            rtsp_port, rtsp_path = get_rtsp_info(camera)

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
            if rtsp_info["status"] != "ok":
                if fallback_ffprobe(rtsp_url):
                    rtsp_info["status"] = "ok"
                    rtsp_info["note"] += " | Metadata via ffprobe"
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
                "note": "No RTSP URI found"
            })

        print(json.dumps(output, indent=4, ensure_ascii=False, default=str))

    except Fault as fault:
        print(json.dumps({"error": f"ONVIF Fault: {fault}"}))
        sys.exit(1)
    except Exception as e:
        print(json.dumps({"error": f"General Error: {e}"}))
        sys.exit(1)


if __name__ == "__main__":
    main()

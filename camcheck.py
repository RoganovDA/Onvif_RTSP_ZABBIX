#!/usr/bin/python3
# -*- coding: utf-8 -*-

import sys
import json
import datetime
import os
import shutil
import logging
import socket
import ipaddress
import re
from urllib.parse import quote

from onvif import ONVIFCamera
from zeep.exceptions import Fault
from onvif.exceptions import ONVIFError

# ensure temp dirs
os.environ["HOME"] = "/tmp"
os.environ["TMPDIR"] = "/tmp"

# Constants are centralized in param.py
from param import (
    ALLOWED_TIME_DIFF_SECONDS,
    PORTS_TO_CHECK,
    MAX_MAIN_ATTEMPTS,
    DEFAULT_USERNAME,
)

# check dependencies
try:
    import cv2
    if hasattr(cv2, "utils") and hasattr(cv2.utils, "logging"):
        cv2.utils.logging.setLogLevel(cv2.utils.logging.LOG_LEVEL_SILENT)
except Exception:
    print(json.dumps({"error": "OpenCV (cv2) library not installed"}))
    sys.exit(2)

try:
    import numpy as np  # noqa: F401
except Exception:
    print(json.dumps({"error": "NumPy library not installed"}))
    sys.exit(3)

from cli import parse_args
from baseline import (
    load_baseline,
    save_baseline,
    remove_baseline,
    remove_progress,
)
from onvif_utils import (
    safe_call,
    parse_datetime,
    find_working_credentials,
    get_rtsp_info,
    normalize_rtsp_path,
)
from rtsp_utils import (
    check_rtsp_stream_with_fallback,
    fallback_ffprobe,
)


HOSTNAME_RE = re.compile(r"^[A-Za-z0-9.-]+$")


def validate_address(address, timeout=5):
    """Validate IP address or resolvable hostname."""
    try:
        ipaddress.ip_address(address)
        return True, None
    except ValueError:
        if not HOSTNAME_RE.fullmatch(address or ""):
            return False, "Invalid address"
        try:
            original = socket.getdefaulttimeout()
            socket.setdefaulttimeout(timeout)
            socket.gethostbyname(address)
            return True, None
        except socket.gaierror:
            return False, "DNS resolution failed"
        finally:
            socket.setdefaulttimeout(original)


def is_reachable(address, timeout):
    for port in (80, 554):
        try:
            with socket.create_connection((address, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def main():
    args = parse_args()

    log_kwargs = {
        "level": logging.DEBUG if args.debug else logging.INFO,
        "format": "%(asctime)s - %(levelname)s - %(message)s",
        "force": True,
    }
    if args.logfile:
        log_kwargs["filename"] = args.logfile
        log_kwargs["filemode"] = "a"
    elif args.debug:
        log_kwargs["stream"] = sys.stderr
    else:
        log_kwargs["filename"] = os.devnull
    logging.basicConfig(**log_kwargs)

    if not args.address:
        print(json.dumps({"error": "Usage: camcheck.py <ADDRESS>"}))
        sys.exit(1)

    address = args.address
    valid, err_msg = validate_address(address, args.ping_timeout)
    if not valid:
        print(json.dumps({"error": err_msg or "Invalid address"}))
        sys.exit(1)
    if not is_reachable(address, args.ping_timeout):
        print(json.dumps({"error": "Host unreachable"}))
        sys.exit(5)
    username = args.username or DEFAULT_USERNAME

    missing_bins = [b for b in ("ffprobe", "ffmpeg") if shutil.which(b) is None]
    if missing_bins:
        msg = f"Missing executables: {', '.join(missing_bins)}"
        logging.error(msg)
        print(json.dumps({"error": msg}))
        sys.exit(4)

    try:
        for attempt in range(MAX_MAIN_ATTEMPTS):
            port, password = find_working_credentials(
                address, PORTS_TO_CHECK, username=username, password=args.password
            )
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

                if isinstance(device_info, dict) and "error" in device_info:
                    logging.error("GetDeviceInformation error: %s", device_info["error"])
                    output["DeviceInfoError"] = device_info["error"]
                elif device_info:
                    output['Manufacturer'] = getattr(device_info, 'Manufacturer', None)
                    output['Model'] = getattr(device_info, 'Model', None)
                    output['FirmwareVersion'] = getattr(device_info, 'FirmwareVersion', None)
                    output['SerialNumber'] = getattr(device_info, 'SerialNumber', None)
                    output['HardwareId'] = getattr(device_info, 'HardwareId', None)

                if isinstance(interfaces, dict) and "error" in interfaces:
                    logging.error("GetNetworkInterfaces error: %s", interfaces["error"])
                    output["InterfacesError"] = interfaces["error"]
                    interfaces = []
                if isinstance(interfaces, list) and interfaces:
                    interface = interfaces[0]
                    info = getattr(interface, 'Info', None)
                    ipv4 = getattr(interface, 'IPv4', None)
                    config = getattr(ipv4, 'Config', None) if ipv4 else None
                    from_dhcp = getattr(config, 'FromDHCP', None) if config else None
                    output['HwAddress'] = getattr(info, 'HwAddress', None) if info else None
                    output['Address'] = getattr(from_dhcp, 'Address', None) if from_dhcp else None

                output['DNSname'] = None

                if isinstance(ntp_info, dict) and "error" in ntp_info:
                    logging.error("GetNTP error: %s", ntp_info["error"])
                    output["NTPError"] = ntp_info["error"]
                else:
                    for key in ('NTPManual', 'NTPFromDHCP'):
                        entries = getattr(ntp_info, key, []) if ntp_info else []
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

                if isinstance(dns_info, dict) and "error" in dns_info:
                    logging.error("GetDNS error: %s", dns_info["error"])
                    output["DNSError"] = dns_info["error"]

                if isinstance(scopes, dict) and "error" in scopes:
                    logging.error("GetScopes error: %s", scopes["error"])
                    output["ScopesError"] = scopes["error"]

                now_utc = datetime.datetime.utcnow()
                camera_utc = None
                if isinstance(datetime_info, dict) and "error" in datetime_info:
                    logging.error("GetSystemDateAndTime error: %s", datetime_info["error"])
                    output["DateTimeError"] = datetime_info["error"]
                else:
                    camera_utc = parse_datetime(datetime_info)
                if camera_utc:
                    delta = abs((now_utc - camera_utc).total_seconds())
                    output['TimeSyncOK'] = delta <= ALLOWED_TIME_DIFF_SECONDS
                    output['TimeDifferenceSeconds'] = int(delta)
                else:
                    output['TimeSyncOK'] = False
                    output['TimeDifferenceSeconds'] = None

                if isinstance(users, dict) and "error" in users:
                    logging.error("GetUsers error: %s", users["error"])
                    output["UsersError"] = users["error"]
                    usernames = []
                else:
                    usernames = [user.Username for user in users] if isinstance(users, list) else []

                baseline = load_baseline(address)

                rtsp_port = baseline.get("rtsp_port") if baseline else None
                rtsp_path = normalize_rtsp_path(baseline.get("rtsp_path")) if baseline else None
                if not (rtsp_port and rtsp_path):
                    rtsp_port, rtsp_path = get_rtsp_info(camera, address, username, password)
                rtsp_path = normalize_rtsp_path(rtsp_path)

                if "UsersError" not in output:
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
                else:
                    output['NewUsersDetected'] = False
                    output['BaselineCreated'] = False

                output['UserCount'] = len(usernames)

                output['RTSPPort'] = rtsp_port
                output['RTSPPath'] = rtsp_path

                if rtsp_port and rtsp_path:
                    u = quote(username, safe='')
                    p = quote(password, safe='')
                    path_enc = quote(rtsp_path, safe='/?:=&')
                    rtsp_url = f"rtsp://{u}:{p}@{address}:{rtsp_port}{path_enc}"
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
                break

            except Fault as fault:
                logging.error("ONVIF Fault: %s", fault, exc_info=True)
                print(json.dumps({"error": f"ONVIF Fault: {fault}"}))
                sys.exit(6)
            except ONVIFError as err:
                logging.error("ONVIF Error: %s", err, exc_info=True)
                print(json.dumps({"error": f"ONVIF Error: {err}"}))
                sys.exit(6)
            except socket.error as err:
                logging.error("Socket Error: %s", err, exc_info=True)
                print(json.dumps({"error": f"Socket Error: {err}"}))
                sys.exit(5)
            except Exception as e:
                logging.critical("Unexpected Error: %s", e, exc_info=True)
                print(json.dumps({"error": f"Unexpected Error: {e}"}))
                sys.exit(7)

        # continue loop on exception

        else:
            print(json.dumps({"error": "Maximum attempts exceeded"}))
            sys.exit(1)
    finally:
        remove_progress(address)


if __name__ == "__main__":
    main()

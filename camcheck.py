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
    load_progress,
    save_progress,
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

    progress = load_progress(address)
    next_allowed = progress.get("next_allowed")
    if next_allowed:
        try:
            na_dt = datetime.datetime.fromisoformat(next_allowed)
            if datetime.datetime.utcnow() < na_dt:
                print(
                    json.dumps(
                        {
                            "error": "Camera locked, retry later",
                            "next_allowed": next_allowed,
                        }
                    )
                )
                sys.exit(1)
            else:
                save_progress(
                    address,
                    {
                        "tried_passwords": progress.get("tried_passwords", []),
                        "next_allowed": None,
                    },
                )
        except Exception:
            pass

    missing_bins = [b for b in ("ffprobe", "ffmpeg") if shutil.which(b) is None]
    if missing_bins:
        msg = f"Missing executables: {', '.join(missing_bins)}"
        logging.error(msg)
        print(json.dumps({"error": msg}))
        sys.exit(4)

    try:
        for attempt in range(MAX_MAIN_ATTEMPTS):
            port, password, auth_report = find_working_credentials(
                address, PORTS_TO_CHECK, username=username, password=args.password
            )
            if port is None:
                progress = load_progress(address)
                err = {"error": f"Unable to find working credentials for {address}"}
                if progress.get("next_allowed"):
                    err["next_allowed"] = progress["next_allowed"]
                print(json.dumps(err))
                sys.exit(1)

            try:
                camera = ONVIFCamera(address, port, username, password)
                devicemgmt_service = camera.create_devicemgmt_service()

                method_status = (auth_report or {}).get("method_status", {})
                raw_results = dict((auth_report or {}).get("raw_results", {}).get("authenticated", {}))
                unsupported_reported = set((auth_report or {}).get("unsupported_methods", []))
                open_methods = sorted(set((auth_report or {}).get("open_methods", [])))
                protected_methods = sorted(set((auth_report or {}).get("protected_methods", [])))

                if auth_report:
                    open_methods_log = ", ".join(open_methods) or "none"
                    logging.debug("Open ONVIF methods: %s", open_methods_log)

                def fetch_method(service_name, method_name, service_obj):
                    key = f"{service_name}.{method_name}"
                    status_info = method_status.get(key, {}).get("authenticated")
                    if status_info and status_info.get("category") == "not_supported":
                        logging.debug("Skipping unsupported method %s", key)
                        result = {
                            "success": False,
                            "status": status_info.get("status"),
                            "status_group": status_info.get("status_group"),
                            "category": "not_supported",
                            "error": status_info.get("error"),
                            "result": None,
                        }
                        raw_results.setdefault(key, result)
                        unsupported_reported.add(key)
                        return result
                    cached = raw_results.get(key)
                    if cached:
                        return cached
                    result = safe_call(service_obj, method_name)
                    raw_results[key] = result
                    if result.get("category") == "not_supported":
                        unsupported_reported.add(key)
                    return result

                device_info = fetch_method("devicemgmt", "GetDeviceInformation", devicemgmt_service)
                datetime_info = fetch_method("devicemgmt", "GetSystemDateAndTime", devicemgmt_service)
                users = fetch_method("devicemgmt", "GetUsers", devicemgmt_service)
                interfaces = fetch_method("devicemgmt", "GetNetworkInterfaces", devicemgmt_service)
                ntp_info = fetch_method("devicemgmt", "GetNTP", devicemgmt_service)
                dns_info = fetch_method("devicemgmt", "GetDNS", devicemgmt_service)
                scopes = fetch_method("devicemgmt", "GetScopes", devicemgmt_service)

                unsupported_methods = sorted(unsupported_reported)

                output = {
                    "ONVIFStatus": (auth_report or {}).get("status"),
                    "MediaAvailable": (auth_report or {}).get("media_available"),
                    "OpenMethods": open_methods,
                    "ProtectedMethods": protected_methods,
                    "UnsupportedMethods": unsupported_methods,
                }

                auth_status = output["ONVIFStatus"]
                if auth_status == "insufficient_role":
                    output["AuthNote"] = "Authenticated but media access denied"
                elif auth_status == "limited_onvif":
                    output["AuthNote"] = "Media service not advertised by camera"

                if not device_info.get("success"):
                    if device_info.get("category") == "not_supported":
                        logging.debug("GetDeviceInformation unsupported: %s", device_info.get("error"))
                    else:
                        logging.error("GetDeviceInformation error: %s", device_info.get("error"))
                        output["DeviceInfoError"] = device_info.get("error")
                else:
                    info = device_info.get("result")
                    output['Manufacturer'] = getattr(info, 'Manufacturer', None)
                    output['Model'] = getattr(info, 'Model', None)
                    output['FirmwareVersion'] = getattr(info, 'FirmwareVersion', None)
                    output['SerialNumber'] = getattr(info, 'SerialNumber', None)
                    output['HardwareId'] = getattr(info, 'HardwareId', None)

                interfaces_data = interfaces.get("result") if interfaces.get("success") else []
                if not interfaces.get("success"):
                    if interfaces.get("category") == "not_supported":
                        logging.debug("GetNetworkInterfaces unsupported: %s", interfaces.get("error"))
                    else:
                        logging.error("GetNetworkInterfaces error: %s", interfaces.get("error"))
                        output["InterfacesError"] = interfaces.get("error")
                        interfaces_data = []
                if isinstance(interfaces_data, list) and interfaces_data:
                    interface = interfaces_data[0]
                    info = getattr(interface, 'Info', None)
                    ipv4 = getattr(interface, 'IPv4', None)
                    config = getattr(ipv4, 'Config', None) if ipv4 else None
                    from_dhcp = getattr(config, 'FromDHCP', None) if config else None
                    output['HwAddress'] = getattr(info, 'HwAddress', None) if info else None
                    output['Address'] = getattr(from_dhcp, 'Address', None) if from_dhcp else None

                output['DNSname'] = None

                ntp_data = ntp_info.get("result") if ntp_info.get("success") else None
                if not ntp_info.get("success"):
                    if ntp_info.get("category") == "not_supported":
                        logging.debug("GetNTP unsupported: %s", ntp_info.get("error"))
                    else:
                        logging.error("GetNTP error: %s", ntp_info.get("error"))
                        output["NTPError"] = ntp_info.get("error")
                else:
                    for key in ('NTPManual', 'NTPFromDHCP'):
                        entries = getattr(ntp_data, key, []) if ntp_data else []
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

                if not dns_info.get("success"):
                    if dns_info.get("category") == "not_supported":
                        logging.debug("GetDNS unsupported: %s", dns_info.get("error"))
                    else:
                        logging.error("GetDNS error: %s", dns_info.get("error"))
                        output["DNSError"] = dns_info.get("error")

                if not scopes.get("success"):
                    if scopes.get("category") == "not_supported":
                        logging.debug("GetScopes unsupported: %s", scopes.get("error"))
                    else:
                        logging.error("GetScopes error: %s", scopes.get("error"))
                        output["ScopesError"] = scopes.get("error")

                now_utc = datetime.datetime.utcnow()
                camera_utc = None
                if not datetime_info.get("success"):
                    if datetime_info.get("category") == "not_supported":
                        logging.debug("GetSystemDateAndTime unsupported: %s", datetime_info.get("error"))
                    else:
                        logging.error("GetSystemDateAndTime error: %s", datetime_info.get("error"))
                        output["DateTimeError"] = datetime_info.get("error")
                else:
                    camera_utc = parse_datetime(datetime_info.get("result"))
                if camera_utc:
                    delta = abs((now_utc - camera_utc).total_seconds())
                    output['TimeSyncOK'] = delta <= ALLOWED_TIME_DIFF_SECONDS
                    output['TimeDifferenceSeconds'] = int(delta)
                else:
                    output['TimeSyncOK'] = False
                    output['TimeDifferenceSeconds'] = None

                if not users.get("success"):
                    if users.get("category") == "not_supported":
                        logging.debug("GetUsers unsupported: %s", users.get("error"))
                        output["UsersUnsupported"] = True
                    else:
                        logging.error("GetUsers error: %s", users.get("error"))
                        output["UsersError"] = users.get("error")
                    usernames = []
                else:
                    result_users = users.get("result") or []
                    usernames = [user.Username for user in result_users] if isinstance(result_users, list) else []

                baseline = load_baseline(address)

                rtsp_port = baseline.get("rtsp_port") if baseline else None
                rtsp_path = normalize_rtsp_path(baseline.get("rtsp_path")) if baseline else None
                if not (rtsp_port and rtsp_path):
                    rtsp_port, rtsp_path = get_rtsp_info(camera, address, username, password)
                rtsp_path = normalize_rtsp_path(rtsp_path)

                if users.get("success"):
                    if baseline is None:
                        save_baseline(address, {
                            "users": usernames,
                            "password": password,
                            "port": port,
                            "rtsp_port": rtsp_port,
                            "rtsp_path": rtsp_path,
                            "open_methods": open_methods,
                            "protected_methods": protected_methods,
                            "unsupported_methods": unsupported_methods,
                            "method_status": method_status,
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
                        if baseline.get("open_methods") != open_methods:
                            baseline["open_methods"] = open_methods
                            updated = True
                        if baseline.get("protected_methods") != protected_methods:
                            baseline["protected_methods"] = protected_methods
                            updated = True
                        if baseline.get("unsupported_methods") != unsupported_methods:
                            baseline["unsupported_methods"] = unsupported_methods
                            updated = True
                        if baseline.get("method_status") != method_status:
                            baseline["method_status"] = method_status
                            updated = True
                        if updated:
                            save_baseline(address, baseline)
                else:
                    output['NewUsersDetected'] = False
                    output['BaselineCreated'] = False

                    if baseline is not None:
                        updated = False
                        if baseline.get("open_methods") != open_methods:
                            baseline["open_methods"] = open_methods
                            updated = True
                        if baseline.get("protected_methods") != protected_methods:
                            baseline["protected_methods"] = protected_methods
                            updated = True
                        if baseline.get("unsupported_methods") != unsupported_methods:
                            baseline["unsupported_methods"] = unsupported_methods
                            updated = True
                        if baseline.get("method_status") != method_status:
                            baseline["method_status"] = method_status
                            updated = True
                        if updated:
                            save_baseline(address, baseline)

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
                        output.update(rtsp_info)
                        output.setdefault(
                            "note",
                            "RTSP stream requires different credentials or permissions",
                        )
                        output["status"] = "unauthorized"
                        print(json.dumps(output, indent=4, ensure_ascii=False, default=str))
                        break
                    if rtsp_info["status"] != "ok":
                        probe_status = fallback_ffprobe(rtsp_url)
                        if probe_status.get("status") == "unauthorized":
                            output.update(rtsp_info)
                            output["status"] = "unauthorized"
                            output["note"] = "RTSP probe unauthorized"
                            print(json.dumps(output, indent=4, ensure_ascii=False, default=str))
                            break
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

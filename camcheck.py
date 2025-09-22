import datetime
import json
import logging
import os
import re
import shutil
import socket
import sys
from typing import Any, Dict, List, Optional
from urllib.parse import quote

from onvif import ONVIFCamera
from onvif.exceptions import ONVIFError
from zeep.exceptions import Fault

from baseline import load_baseline, load_progress, save_baseline, save_progress, remove_progress
from cli import parse_args
from onvif_utils import (
    find_working_credentials,
    get_rtsp_info,
    normalize_rtsp_path,
    parse_datetime,
    safe_call,
    try_onvif_connection,
)
from param import (
    ALLOWED_TIME_DIFF_SECONDS,
    DEFAULT_RTSP_PORT,
    DEFAULT_USERNAME,
    MAX_MAIN_ATTEMPTS,
    PORTS_TO_CHECK,
    RTSP_PATH_CANDIDATES,
)
from rtsp_utils import check_rtsp_stream_with_fallback


HOSTNAME_RE = re.compile(r"^[A-Za-z0-9.-]+$")


def emit_json(data: Any, *, default=None) -> None:
    print(
        json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
            default=default or str,
        )
    )


def validate_address(address, timeout=5):
    """Validate IP address or resolvable hostname."""
    try:
        socket.inet_pton(socket.AF_INET, address)
        return True, None
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, address)
            return True, None
        except OSError:
            if not HOSTNAME_RE.fullmatch(address or ""):
                return False, "Invalid address"
            original = socket.getdefaulttimeout()
            try:
                socket.setdefaulttimeout(timeout)
                result = socket.getaddrinfo(address, None, socket.AF_UNSPEC)
                if result:
                    return True, None
                return False, "DNS resolution failed"
            except socket.gaierror:
                return False, "DNS resolution failed"
            except OSError:
                return False, "DNS resolution failed"
            finally:
                socket.setdefaulttimeout(original)


def is_reachable(address, timeout, ports=None):
    port_list = []
    if ports:
        for value in ports:
            try:
                port = int(value)
            except (TypeError, ValueError):
                continue
            if port <= 0:
                continue
            port_list.append(port)
    port_list.extend([80, 554])
    seen = set()
    for port in port_list:
        if port in seen:
            continue
        seen.add(port)
        try:
            with socket.create_connection((address, port), timeout=timeout):
                return True
        except OSError:
            continue
    return False


def _parse_iso(value):
    if not value:
        return None
    try:
        return datetime.datetime.fromisoformat(value)
    except Exception:
        return None


def _summarize_rtsp_result(result):
    attempts = result.get("attempts", [])
    counts = {key: 0 for key in ("OK", "UNAUTHORIZED", "TIMEOUT", "REFUSED", "DNS_FAIL", "ERROR")}

    def _normalize_attempt_status(value):
        if not value:
            return None
        normalized = str(value).strip().upper().replace("-", "_")
        aliases = {
            "AUTH_REQUIRED": "UNAUTHORIZED",
            "UNAUTHORISED": "UNAUTHORIZED",
            "401": "UNAUTHORIZED",
            "403": "UNAUTHORIZED",
            "CONNECTION_REFUSED": "REFUSED",
            "REFUSE": "REFUSED",
            "CONN_REFUSED": "REFUSED",
            "TIMED_OUT": "TIMEOUT",
            "TIMEOUT": "TIMEOUT",
            "ERR_TIMEOUT": "TIMEOUT",
            "DNS_FAILURE": "DNS_FAIL",
            "DNS_ERROR": "DNS_FAIL",
            "DNS": "DNS_FAIL",
        }
        normalized = aliases.get(normalized, normalized)
        if normalized in counts:
            return normalized
        for key in counts:
            if normalized.endswith(key):
                return key
        return None

    def _select_status(status_value, probe_value):
        status = _normalize_attempt_status(status_value)
        probe_status = _normalize_attempt_status(probe_value)

        if probe_status and probe_status != status:
            if status in (None, "ERROR"):
                status = probe_status
            elif probe_status in {"UNAUTHORIZED", "TIMEOUT", "REFUSED", "DNS_FAIL"}:
                status = probe_status

        if not status:
            status = "ERROR"

        return status

    summarized_attempts = []
    for attempt in attempts:
        attempt_dict = dict(attempt or {})
        status = _select_status(attempt_dict.get("status"), attempt_dict.get("probe_status"))
        attempt_dict["normalized_status"] = status
        summarized_attempts.append(attempt_dict)
        counts[status] += 1

    counts["TOTAL"] = len(summarized_attempts)
    best_attempt = result.get("best_attempt")
    if best_attempt:
        best_attempt = dict(best_attempt)
        best_attempt["normalized_status"] = _select_status(
            best_attempt.get("status"), best_attempt.get("probe_status")
        )

    summary = {
        "counts": counts,
        "best_attempt": best_attempt,
        "status": result.get("status"),
        "note": result.get("note"),
    }

    payload = {
        "status": result.get("status"),
        "note": result.get("note"),
        "frames_read": result.get("frames_read"),
        "avg_frame_size_kb": result.get("avg_frame_size_kb"),
        "width": result.get("width"),
        "height": result.get("height"),
        "avg_brightness": result.get("avg_brightness"),
        "frame_change_level": result.get("frame_change_level"),
        "real_fps": result.get("real_fps"),
        "attempts": summarized_attempts,
        "best_attempt": best_attempt,
        "summary": summary,
        "avg_color_channels": result.get("avg_color_channels"),
        "color_channel_variance": result.get("color_channel_variance"),
        "color_channel_ratios": result.get("color_channel_ratios"),
        "color_channel_balance": result.get("color_channel_balance"),
        "color_analysis": result.get("color_analysis"),
    }
    return payload


def _normalize_call_status(call_result):
    if not isinstance(call_result, dict):
        return None
    if call_result.get("success"):
        return "OK"
    category = call_result.get("category")
    mapping = {
        "unauthorized": "AUTH_REQUIRED",
        "timeout": "TIMEOUT",
        "locked": "LOCKED",
        "not_supported": "NOT_SUPPORTED",
        "redirect": "REDIRECT",
    }
    if category in mapping:
        return mapping[category]
    if call_result.get("status") in (401, 403):
        return "AUTH_REQUIRED"
    return "ERROR"


def _apply_call_status(snapshot, prefix, call_result, warnings, description):
    status = _normalize_call_status(call_result)
    if not status or status == "OK":
        return
    key = f"{prefix}_auth" if status == "AUTH_REQUIRED" else f"{prefix}_status"
    snapshot[key] = status
    error_text = call_result.get("error")
    if error_text:
        warnings.append(f"{description}: {error_text}")


def _unique_preserve(values):
    seen = set()
    ordered = []
    for value in values:
        if value is None:
            continue
        if value in seen:
            continue
        ordered.append(value)
        seen.add(value)
    return ordered


def _standardize_rtsp_result(result, default_status="error", default_note=""):
    return {
        "status": result.get("status", default_status),
        "note": result.get("note") or default_note,
        "frames_read": result.get("frames_read", 0),
        "avg_frame_size_kb": result.get("avg_frame_size_kb", 0.0),
        "width": result.get("width"),
        "height": result.get("height"),
        "avg_brightness": result.get("avg_brightness", 0.0),
        "frame_change_level": result.get("frame_change_level", 0.0),
        "real_fps": result.get("real_fps", 0.0),
        "attempts": result.get("attempts", []),
        "best_attempt": result.get("best_attempt"),
        "avg_color_channels": result.get("avg_color_channels"),
        "color_channel_variance": result.get("color_channel_variance"),
        "color_channel_ratios": result.get("color_channel_ratios"),
        "color_channel_balance": result.get("color_channel_balance"),
        "color_analysis": result.get("color_analysis"),
    }


def _map_final_verdict(verdict: Optional[str]) -> str:
    if verdict is None:
        return "unknown"
    mapping = {
        "AUTH_OK": "success",
        "WRONG_CREDS": "unauthorized",
        "LOCKED": "locked",
        "LIMITED_ONVIF": "limited",
        "INSUFFICIENT_ROLE": "insufficient_role",
    }
    normalized = mapping.get(str(verdict).upper())
    if normalized:
        return normalized
    return str(verdict).lower()


def _build_legacy_payload(
    address: str,
    payload: Dict[str, Any],
    *,
    rtsp_port: Optional[int] = None,
    rtsp_path: Optional[str] = None,
    baseline_created: bool,
):
    camera = payload.get("camera") or {}
    device = camera.get("device") or {}
    network = camera.get("network") or {}
    time_info = camera.get("time") or {}
    users = camera.get("users") or {}
    user_changes = users.get("changes") or {}
    new_users = user_changes.get("new") or []
    removed_users = user_changes.get("removed") or []
    rtsp_phase = (payload.get("phase") or {}).get("rtsp_fallback", {}) or {}
    best_attempt = rtsp_phase.get("best_attempt") or {}
    best_port = rtsp_port or best_attempt.get("port")
    best_path = rtsp_path or payload.get("rtsp_best_path") or best_attempt.get("path")
    color_analysis = rtsp_phase.get("color_analysis") or {}
    dns_value = network.get("dns") or network.get("ntp")
    ip_value = network.get("ipv4") or address
    legacy = {
        "Manufacturer": device.get("manufacturer"),
        "Model": device.get("model"),
        "FirmwareVersion": device.get("firmware"),
        "SerialNumber": device.get("serial"),
        "HardwareId": device.get("hardware_id"),
        "HwAddress": network.get("hw_address"),
        "Address": ip_value,
        "DNSname": dns_value,
        "TimeSyncOK": time_info.get("in_sync"),
        "TimeDifferenceSeconds": time_info.get("offset_seconds"),
        "ONVIFStatus": _map_final_verdict(payload.get("final_verdict")),
        "NewUsersDetected": bool(new_users),
        "NewUsernames": new_users,
        "RemovedUsernames": removed_users,
        "BaselineCreated": baseline_created,
        "UserCount": users.get("count"),
        "RTSPPort": best_port,
        "RTSPPath": best_path,
        "RTSPTransport": best_attempt.get("transport"),
        "RTSPBestURI": payload.get("rtsp_best_uri") or best_attempt.get("url"),
        "status": rtsp_phase.get("status"),
        "frames_read": rtsp_phase.get("frames_read"),
        "avg_frame_size_kb": rtsp_phase.get("avg_frame_size_kb"),
        "width": rtsp_phase.get("width"),
        "height": rtsp_phase.get("height"),
        "avg_brightness": rtsp_phase.get("avg_brightness"),
        "frame_change_level": rtsp_phase.get("frame_change_level"),
        "real_fps": rtsp_phase.get("real_fps"),
        "note": rtsp_phase.get("note"),
        "ColorDiagnosis": color_analysis.get("diagnosis"),
        "ColorConfidence": color_analysis.get("confidence"),
        "ColorStability": color_analysis.get("stability"),
        "ColorDominantChannel": color_analysis.get("dominant_channel"),
        "ColorTriggeredMetrics": color_analysis.get("triggered_metrics"),
        "ColorMaxVariance": color_analysis.get("max_variance"),
        "ColorMaxRatio": color_analysis.get("max_ratio"),
        "ColorFrameCount": color_analysis.get("frame_count"),
        "ColorReason": color_analysis.get("reason"),
        "ColorRatios": rtsp_phase.get("color_channel_ratios"),
        "ColorBalance": rtsp_phase.get("color_channel_balance"),
        "ColorChannels": rtsp_phase.get("avg_color_channels"),
        "Notes": list(payload.get("notes") or []),
        "NextAttemptAfter": payload.get("next_attempt_after"),
    }
    return legacy


def _run_rtsp_candidate_fallback(address, username, password, port_candidates, path_candidates):
    attempts = []
    best_payload = None
    best_attempt = None

    for port in port_candidates:
        for path in path_candidates:
            normalized_path = normalize_rtsp_path(path)
            if not normalized_path:
                continue
            encoded_path = quote(normalized_path, safe="/?:=&")
            url = (
                f"rtsp://{quote(username, safe='')}:{quote(password, safe='')}@"
                f"{address}:{port}{encoded_path}"
            )
            result = check_rtsp_stream_with_fallback(url)
            result_attempts = result.get("attempts", [])
            for attempt in result_attempts:
                attempt_copy = dict(attempt or {})
                attempt_copy["path"] = normalized_path
                attempt_copy["port"] = port
                attempts.append(attempt_copy)
            candidate_best = result.get("best_attempt")
            if candidate_best:
                candidate_best = dict(candidate_best)
                candidate_best["path"] = normalized_path
                candidate_best["port"] = port
            standardized = _standardize_rtsp_result(result)
            if candidate_best:
                standardized["best_attempt"] = candidate_best
            status = (standardized.get("status") or "").lower()
            if status in {"ok", "unauthorized"}:
                standardized["attempts"] = list(attempts)
                if candidate_best:
                    standardized["best_attempt"] = candidate_best
                elif attempts:
                    standardized["best_attempt"] = attempts[-1]
                return standardized
            if best_payload is None:
                best_payload = standardized
                if candidate_best:
                    best_attempt = candidate_best

    if best_payload is None:
        best_payload = _standardize_rtsp_result(
            {"status": "not_available", "note": "No RTSP fallback attempts executed"}
        )
    best_payload["attempts"] = list(attempts)
    if best_attempt:
        best_payload["best_attempt"] = best_attempt
    elif attempts:
        best_payload["best_attempt"] = attempts[-1]
    return best_payload


def _collect_device_snapshot(camera):
    snapshot = {
        "device": {},
        "network": {},
        "time": {},
        "users": {},
    }
    warnings = []
    usernames: List[str] = []
    try:
        devicemgmt_service = camera.create_devicemgmt_service()
    except Exception as exc:
        warnings.append(f"Failed to create devicemgmt service: {exc}")
        return snapshot, usernames, warnings

    device_info = safe_call(devicemgmt_service, "GetDeviceInformation")
    if device_info.get("success"):
        info = device_info.get("result")
        snapshot["device"] = {
            "manufacturer": getattr(info, "Manufacturer", None),
            "model": getattr(info, "Model", None),
            "firmware": getattr(info, "FirmwareVersion", None),
            "serial": getattr(info, "SerialNumber", None),
            "hardware_id": getattr(info, "HardwareId", None),
        }
    else:
        _apply_call_status(snapshot, "device", device_info, warnings, "GetDeviceInformation")

    interfaces = safe_call(devicemgmt_service, "GetNetworkInterfaces")
    if interfaces.get("success"):
        entries = interfaces.get("result") or []
        if isinstance(entries, list) and entries:
            entry = entries[0]
            info = getattr(entry, "Info", None)
            ipv4 = getattr(entry, "IPv4", None)
            config = getattr(ipv4, "Config", None) if ipv4 else None
            from_dhcp = getattr(config, "FromDHCP", None) if config else None
            manual = getattr(config, "Manual", None) if config else None
            dhcp_address = getattr(from_dhcp, "Address", None) if from_dhcp else None
            manual_address = None
            if not dhcp_address and manual:
                manual_entries = manual if isinstance(manual, list) else [manual]
                for manual_entry in manual_entries:
                    manual_address = getattr(manual_entry, "Address", None)
                    if manual_address:
                        break
            snapshot["network"] = {
                "hw_address": getattr(info, "HwAddress", None) if info else None,
                "ipv4": dhcp_address or manual_address,
            }
    else:
        _apply_call_status(snapshot, "network_interfaces", interfaces, warnings, "GetNetworkInterfaces")

    datetime_info = safe_call(devicemgmt_service, "GetSystemDateAndTime")
    if datetime_info.get("success"):
        camera_dt = parse_datetime(datetime_info.get("result"))
        if camera_dt:
            delta = abs((datetime.datetime.utcnow() - camera_dt).total_seconds())
            snapshot["time"] = {
                "offset_seconds": int(delta),
                "in_sync": delta <= ALLOWED_TIME_DIFF_SECONDS,
            }
        else:
            snapshot["time_status"] = "ERROR"
            warnings.append("GetSystemDateAndTime: Unable to parse camera time")
    else:
        _apply_call_status(snapshot, "time", datetime_info, warnings, "GetSystemDateAndTime")

    ntp_info = safe_call(devicemgmt_service, "GetNTP")
    if ntp_info.get("success"):
        ntp_data = ntp_info.get("result")
        dnsname = None
        for key in ("NTPManual", "NTPFromDHCP"):
            entries = getattr(ntp_data, key, []) if ntp_data else []
            if not isinstance(entries, list):
                continue
            for entry in entries:
                for attr in ("DNSname", "IPv4Address"):
                    value = getattr(entry, attr, None)
                    if value:
                        dnsname = value
                        break
                if dnsname:
                    break
            if dnsname:
                break
        if dnsname:
            snapshot["network"]["ntp"] = dnsname
    else:
        _apply_call_status(snapshot, "ntp", ntp_info, warnings, "GetNTP")

    users_call = safe_call(devicemgmt_service, "GetUsers")
    if users_call.get("success"):
        entries = users_call.get("result") or []
        if isinstance(entries, list):
            for entry in entries:
                username = getattr(entry, "Username", None)
                if username:
                    usernames.append(username)
        snapshot["users"] = {
            "count": len(usernames),
            "usernames": usernames,
        }
    else:
        _apply_call_status(snapshot, "users", users_call, warnings, "GetUsers")

    return snapshot, usernames, warnings


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
        emit_json({"error": "Usage: camcheck.py <ADDRESS>"})
        sys.exit(1)

    address = args.address
    valid, err_msg = validate_address(address, args.ping_timeout)
    if not valid:
        emit_json({"error": err_msg or "Invalid address"})
        sys.exit(1)

    baseline = load_baseline(address)
    baseline_created_flag = baseline is None
    reachability_hints = []
    if baseline:
        reachability_hints.extend(
            value for value in (baseline.get("port"), baseline.get("rtsp_port"))
        )
    reachability_hints.extend(PORTS_TO_CHECK)
    reachability_hints.append(DEFAULT_RTSP_PORT)
    reachability_ports = _unique_preserve(reachability_hints)
    if not is_reachable(address, args.ping_timeout, ports=reachability_ports):
        emit_json({"error": "Host unreachable"})
        sys.exit(5)

    username = args.username or DEFAULT_USERNAME
    progress = load_progress(address)
    now = datetime.datetime.utcnow()

    if baseline:
        lockout_until = _parse_iso(baseline.get("lockout_until"))
        if lockout_until and now < lockout_until:
            payload = {
                "status": "skipped_due_to_lockout",
                "lockout_until": baseline.get("lockout_until"),
            }
            if baseline.get("lockout_message"):
                payload["reason"] = baseline.get("lockout_message")
            emit_json(payload)
            return
        cooldown_until = _parse_iso(baseline.get("cooldown_until"))
        if cooldown_until and now < cooldown_until:
            emit_json(
                {
                    "status": "skipped_due_to_backoff",
                    "cooldown_until": baseline.get("cooldown_until"),
                }
            )
            return
        if baseline.get("lockout_until") and lockout_until and now >= lockout_until:
            baseline["lockout_until"] = None
            baseline["lockout_message"] = None
        if baseline.get("cooldown_until") and cooldown_until and now >= cooldown_until:
            baseline["cooldown_until"] = None

    next_allowed = _parse_iso(progress.get("next_allowed"))
    if next_allowed and now < next_allowed:
        emit_json(
            {
                "status": "skipped_due_to_lockout",
                "next_attempt_after": progress.get("next_allowed"),
            }
        )
        return
    if progress.get("next_allowed"):
        save_progress(
            address,
            {"tried_passwords": progress.get("tried_passwords", []), "next_allowed": None},
        )

    missing_bins = [b for b in ("ffprobe", "ffmpeg") if shutil.which(b) is None]
    if missing_bins:
        msg = f"Missing executables: {', '.join(missing_bins)}"
        logging.error(msg)
        emit_json({"error": msg})
        sys.exit(4)

    notes: List[str] = []
    port = None
    password = args.password
    auth_report = None
    should_clear_progress = False

    try:
        for _ in range(MAX_MAIN_ATTEMPTS):
            port, password_candidate, report_candidate = find_working_credentials(
                address, PORTS_TO_CHECK, username=username, password=password
            )
            if port is not None:
                password = password_candidate
                auth_report = report_candidate
                break
        if port is None:
            err = {
                "status": "credentials_not_found",
                "error": f"Unable to find working credentials for {address}",
            }
            progress = load_progress(address)
            if progress.get("next_allowed"):
                err["next_attempt_after"] = progress["next_allowed"]
            emit_json(err)
            return

        if auth_report is None:
            auth_report = try_onvif_connection(address, port, username, password)

        final_verdict = auth_report.get("final_verdict")

        try:
            camera = ONVIFCamera(address, port, username, password)
        except Exception as exc:
            emit_json({"status": "onvif_error", "error": str(exc)})
            return

        device_snapshot, usernames, warnings = _collect_device_snapshot(camera)
        notes.extend(warnings)

        rtsp_port, rtsp_path = get_rtsp_info(camera, address, username, password)
        if rtsp_port is None and baseline:
            rtsp_port = baseline.get("rtsp_port")
        if rtsp_path is None and baseline:
            rtsp_path = baseline.get("rtsp_path")

        port_candidates = _unique_preserve([
            rtsp_port,
            (baseline or {}).get("rtsp_port") if baseline else None,
            DEFAULT_RTSP_PORT,
        ])
        if not port_candidates:
            port_candidates = [DEFAULT_RTSP_PORT]

        path_candidates = _unique_preserve([
            rtsp_path,
            (baseline or {}).get("rtsp_path") if baseline else None,
            *RTSP_PATH_CANDIDATES,
        ])

        if path_candidates:
            rtsp_result = _run_rtsp_candidate_fallback(
                address,
                username,
                password,
                port_candidates,
                path_candidates,
            )
        else:
            rtsp_result = _standardize_rtsp_result(
                {"status": "not_available", "note": "No RTSP path candidates available"}
            )

        best_url = (rtsp_result.get("best_attempt") or {}).get("url")
        rtsp_phase = _summarize_rtsp_result(rtsp_result)

        best_attempt = rtsp_phase.get("best_attempt") or {}
        best_path = best_attempt.get("path")
        attempt_port = best_attempt.get("port")
        if rtsp_port is None and isinstance(attempt_port, int):
            rtsp_port = attempt_port
        if rtsp_path is None and best_path:
            rtsp_path = best_path
        if rtsp_path:
            rtsp_path = normalize_rtsp_path(rtsp_path)

        color_analysis = rtsp_phase.get("color_analysis") or {}
        diagnosis = color_analysis.get("diagnosis")
        if diagnosis and diagnosis not in {"balanced", "unknown"}:
            confidence = color_analysis.get("confidence")
            if isinstance(confidence, (int, float)):
                notes.append(
                    f"Color cast detected: {diagnosis} (confidence {confidence:.2f})"
                )
            else:
                notes.append(f"Color cast detected: {diagnosis}")

        baseline_users = (baseline or {}).get("users", [])
        user_changes = {}
        if baseline_users:
            new_users = sorted(set(usernames) - set(baseline_users))
            removed_users = sorted(set(baseline_users) - set(usernames))
            if new_users:
                user_changes["new"] = new_users
            if removed_users:
                user_changes["removed"] = removed_users
        else:
            user_changes["new"] = usernames
        if user_changes.get("new"):
            notes.append("New users detected: " + ", ".join(user_changes["new"]))
        if user_changes.get("removed"):
            notes.append("Users removed: " + ", ".join(user_changes["removed"]))
        device_snapshot.setdefault("users", {})["changes"] = user_changes

        lock_seconds = auth_report.get("lock_seconds")
        next_attempt_after = None
        if final_verdict == "LOCKED" and lock_seconds:
            next_attempt_after = (datetime.datetime.utcnow() + datetime.timedelta(seconds=lock_seconds)).isoformat()

        baseline_data = baseline or {
            "users": [],
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
        baseline_data["users"] = usernames
        baseline_data["password"] = password
        baseline_data["port"] = port
        baseline_data["rtsp_port"] = rtsp_port
        baseline_data["rtsp_path"] = rtsp_path
        baseline_data["last_auth_status"] = final_verdict
        baseline_data["last_endpoints"] = auth_report.get("services", {})
        baseline_data["last_good_stream_uri"] = best_url
        baseline_data["rtsp_best_path"] = best_path
        baseline_data["rtsp_attempts"] = rtsp_phase.get("attempts", [])
        baseline_data["cooldown_until"] = None
        baseline_data["rtsp_color_analysis"] = rtsp_phase.get("color_analysis")
        baseline_data["rtsp_color_channels"] = rtsp_phase.get("avg_color_channels")
        baseline_data["rtsp_color_balance"] = rtsp_phase.get("color_channel_balance")
        baseline_data["rtsp_color_ratios"] = rtsp_phase.get("color_channel_ratios")
        baseline_data["rtsp_color_variance"] = rtsp_phase.get("color_channel_variance")

        if final_verdict == "LOCKED" and lock_seconds:
            lock_until_dt = datetime.datetime.utcnow() + datetime.timedelta(seconds=lock_seconds)
            baseline_data["lockout_until"] = lock_until_dt.isoformat()
            baseline_data["lockout_message"] = "Camera reported lockout"
            if next_attempt_after is None:
                next_attempt_after = baseline_data["lockout_until"]
        else:
            baseline_data["lockout_until"] = None
            baseline_data["lockout_message"] = None

        save_baseline(address, baseline_data)

        anonymous_phase = auth_report.get("phase", {}).get("anonymous", {})
        auth_phase = auth_report.get("phase", {}).get("authenticated", {})
        payload = {
            "final_verdict": final_verdict,
            "phase": {
                "anonymous_audit": anonymous_phase,
                "auth_check": auth_phase,
                "rtsp_fallback": rtsp_phase,
            },
            "services": auth_report.get("services", {}),
            "critical": auth_report.get("critical", {}),
            "anonymous_exposure": {
                "verdict": anonymous_phase.get("summary", {}).get("verdict"),
                "open_methods": auth_report.get("anonymous_exposure", []),
            },
            "media_denied": auth_report.get("media_denied"),
            "camera": device_snapshot,
            "rtsp_best_path": best_path,
            "notes": notes,
            "next_attempt_after": next_attempt_after,
        }
        if best_url:
            payload["rtsp_best_uri"] = best_url

        if args.full_output:
            emit_json(payload, default=str)
        else:
            legacy_payload = _build_legacy_payload(
                address,
                payload,
                rtsp_port=rtsp_port,
                rtsp_path=rtsp_path,
                baseline_created=baseline_created_flag,
            )
            emit_json(legacy_payload, default=str)
        should_clear_progress = next_attempt_after is None

    except Fault as fault:
        logging.error("ONVIF Fault: %s", fault, exc_info=True)
        emit_json({"error": f"ONVIF Fault: {fault}"})
        sys.exit(6)
    except ONVIFError as err:
        logging.error("ONVIF Error: %s", err, exc_info=True)
        emit_json({"error": f"ONVIF Error: {err}"})
        sys.exit(6)
    except socket.error as err:
        logging.error("Socket Error: %s", err, exc_info=True)
        emit_json({"error": f"Socket Error: {err}"})
        sys.exit(5)
    except Exception as exc:
        logging.critical("Unexpected Error: %s", exc, exc_info=True)
        emit_json({"error": f"Unexpected Error: {exc}"})
        sys.exit(7)
    finally:
        if should_clear_progress:
            progress_state = load_progress(address)
            next_allowed_dt = _parse_iso(progress_state.get("next_allowed"))
            if next_allowed_dt and datetime.datetime.utcnow() < next_allowed_dt:
                logging.debug(
                    "Keeping progress for %s due to active backoff until %s",
                    address,
                    progress_state.get("next_allowed"),
                )
            else:
                remove_progress(address)


if __name__ == "__main__":
    main()

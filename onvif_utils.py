import datetime
import logging
import re
import socket
import time
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import quote, urlparse

from onvif import ONVIFCamera
from onvif.exceptions import ONVIFError
from zeep.exceptions import Fault, TransportError

from baseline import (
    load_baseline,
    load_progress,
    remove_baseline,
    save_progress,
)
from param import (
    DEFAULT_PASSWORD,
    DEFAULT_RTSP_PORT,
    DEFAULT_USERNAME,
    MAX_PASSWORD_ATTEMPTS,
    ONVIF_PRIORITY_METHODS,
    PASSWORDS,
    RTSP_PATH_CANDIDATES,
)
from rtsp_utils import fallback_ffprobe


STATUS_RE = re.compile(r"(?:HTTP\s*)?(?P<code>[1-5]\d{2})")
REDIRECT_RE = re.compile(r"location[:=]\s*(?P<url>\S+)", re.IGNORECASE)
LOCK_RE = re.compile(r"after\s+(\d+)\s*(second|minute|hour)", re.IGNORECASE)
LOCK_KEYWORDS = (
    "devicelocked",
    "locked",
    "accountlocked",
    "passwordlocked",
    "too many attempts",
    "too many failures",
)


def _method_key(service: str, method: str) -> str:
    return f"{service}.{method}"


def _status_group(status: Optional[int]) -> Optional[int]:
    if status is None:
        return None
    try:
        return int(status) // 100
    except Exception:
        return None


def _extract_status_code(exc: Any) -> Optional[int]:
    if isinstance(exc, int):
        return exc
    status = getattr(exc, "status_code", None)
    if status:
        try:
            return int(status)
        except (TypeError, ValueError):
            pass
    message = str(exc) if exc is not None else ""
    match = STATUS_RE.search(message)
    if match:
        try:
            return int(match.group("code"))
        except (TypeError, ValueError):
            return None
    return None


def _extract_redirect(exc: Any) -> Optional[str]:
    message = str(exc) if exc is not None else ""
    match = REDIRECT_RE.search(message)
    if match:
        return match.group("url").strip("'\"")
    content = getattr(exc, "content", None)
    if isinstance(content, (bytes, bytearray)):
        try:
            decoded = content.decode("utf-8", errors="ignore")
        except Exception:
            decoded = ""
        if decoded:
            match = REDIRECT_RE.search(decoded)
            if match:
                return match.group("url").strip("'\"")
    elif isinstance(content, str):
        match = REDIRECT_RE.search(content)
        if match:
            return match.group("url").strip("'\"")
    return None


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


def parse_lock_time(message: str) -> Optional[int]:
    match = LOCK_RE.search(message or "")
    if not match:
        return None
    value = int(match.group(1))
    unit = match.group(2).lower()
    factors = {"second": 1, "minute": 60, "hour": 3600}
    return value * factors.get(unit, 1)


def _classify_category(status: Optional[int], message: str, *, exc: Any = None) -> Optional[str]:
    text = (message or "").lower()
    if exc and isinstance(exc, (socket.timeout, TimeoutError)):
        return "timeout"
    if "timed out" in text or "timeout" in text:
        return "timeout"
    if any(keyword in text for keyword in LOCK_KEYWORDS):
        return "locked"
    if status in (401, 403) or "notauthorized" in text or "unauthorized" in text:
        return "unauthorized"
    if status in (400, 404) or "novalidoperation" in text:
        return "not_supported"
    if status is not None and 300 <= status < 400:
        return "redirect"
    return "error"


def _build_error_result(
    exc: Any,
    *,
    status: Optional[int] = None,
    redirect: Optional[str] = None,
    latency_ms: Optional[float] = None,
) -> Dict[str, Any]:
    message = str(exc) if exc is not None else ""
    code = _extract_status_code(status if status is not None else exc)
    category = _classify_category(code, message, exc=exc)
    result: Dict[str, Any] = {
        "success": False,
        "status": code,
        "status_group": _status_group(code),
        "category": category,
        "error": message or None,
        "result": None,
        "latency_ms": latency_ms,
        "exception": type(exc).__name__ if exc else None,
    }
    if redirect:
        result["redirect"] = redirect
    if isinstance(exc, Fault):
        result["fault_code"] = getattr(exc, "code", None)
        result["fault_string"] = getattr(exc, "message", None)
    if category == "locked":
        result["lock_seconds"] = parse_lock_time(message) or 31 * 60
    return result


def _build_params(params: Any, service: Any) -> Any:
    if params is None:
        return None
    if callable(params):
        try:
            return params(service)
        except TypeError:
            return params()
    return params


def _update_service_address(service: Any, new_address: str) -> bool:
    try:
        binding = getattr(service.ws_client, "_binding", None)
        if binding is None:
            return False
        binding_name = getattr(binding, "name", None)
        if binding_name is None:
            return False
        service.ws_client = service.zeep_client.create_service(binding_name, new_address)
        service.xaddr = new_address
        return True
    except Exception:
        logging.debug("Failed to update service address to %s", new_address, exc_info=True)
        return False


def _summarize_call(result: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not result:
        return None
    summary = {
        "success": bool(result.get("success")),
        "status": result.get("status"),
        "status_group": result.get("status_group"),
        "category": result.get("category"),
        "error": result.get("error"),
        "latency_ms": result.get("latency_ms"),
        "exception": result.get("exception"),
    }
    if "redirect_chain" in result:
        summary["redirect_chain"] = result["redirect_chain"]
    if "lock_seconds" in result:
        summary["lock_seconds"] = result.get("lock_seconds")
    if "fault_code" in result:
        summary["fault_code"] = result.get("fault_code")
    if "fault_string" in result:
        summary["fault_string"] = result.get("fault_string")
    return summary


def safe_call(
    service: Any,
    method_name: str,
    params: Any = None,
    *,
    allow_redirect: bool = True,
) -> Dict[str, Any]:
    method = getattr(service, method_name)
    prepared = _build_params(params, service)
    start = time.perf_counter()
    try:
        if prepared is None:
            response = method()
        else:
            response = method(prepared)
        latency = round((time.perf_counter() - start) * 1000, 2)
        return {
            "success": True,
            "status": 200,
            "status_group": 2,
            "result": response,
            "category": None,
            "error": None,
            "latency_ms": latency,
        }
    except TransportError as err:
        redirect = _extract_redirect(err)
        latency = round((time.perf_counter() - start) * 1000, 2)
        result = _build_error_result(err, redirect=redirect, latency_ms=latency)
    except Fault as err:
        latency = round((time.perf_counter() - start) * 1000, 2)
        result = _build_error_result(err, latency_ms=latency)
    except ONVIFError as err:
        latency = round((time.perf_counter() - start) * 1000, 2)
        result = _build_error_result(err, latency_ms=latency)
    except Exception as err:
        latency = round((time.perf_counter() - start) * 1000, 2)
        result = _build_error_result(err, latency_ms=latency)

    redirect_url = result.get("redirect")
    if (
        allow_redirect
        and redirect_url
        and result.get("category") == "redirect"
        and _update_service_address(service, redirect_url)
    ):
        previous = getattr(service, "xaddr", None)
        logging.debug(
            "Following redirect for %s.%s: %s -> %s",
            service.__class__.__name__,
            method_name,
            previous,
            redirect_url,
        )
        follow = safe_call(service, method_name, params=params, allow_redirect=False)
        follow.setdefault("redirect_chain", [])
        follow["redirect_chain"].insert(
            0,
            {
                "from": previous,
                "to": redirect_url,
                "status": result.get("status"),
            },
        )
        return follow

    if redirect_url:
        result["redirect_chain"] = [
            {
                "from": getattr(service, "xaddr", None),
                "to": redirect_url,
                "status": result.get("status"),
            }
        ]
    return result


def _execute_method_sequence(camera: ONVIFCamera, methods: Iterable[Dict[str, Any]]):
    service_cache: Dict[str, Any] = {}
    results: List[Dict[str, Any]] = []
    for spec in methods:
        service_name = spec.get("service")
        method_name = spec.get("method")
        params = spec.get("params")
        entry = {"service": service_name, "method": method_name}

        if service_name not in service_cache:
            creator_name = f"create_{service_name}_service"
            creator = getattr(camera, creator_name, None)
            if not callable(creator):
                entry.update(
                    {
                        "success": False,
                        "status": None,
                        "status_group": None,
                        "category": "not_supported",
                        "error": f"Service {service_name} unavailable",
                        "result": None,
                    }
                )
                results.append(entry)
                service_cache[service_name] = None
                continue
            try:
                service_cache[service_name] = creator()
            except (Fault, ONVIFError) as err:
                entry.update(_build_error_result(err))
                results.append(entry)
                service_cache[service_name] = None
                continue
            except Exception as err:
                entry.update(_build_error_result(err))
                results.append(entry)
                service_cache[service_name] = None
                continue

        service = service_cache.get(service_name)
        if service is None:
            entry.update(
                {
                    "success": False,
                    "status": None,
                    "status_group": None,
                    "category": "not_supported",
                    "error": f"Service {service_name} unavailable",
                    "result": None,
                }
            )
            results.append(entry)
            continue

        call_result = safe_call(service, method_name, params=params)
        entry.update(call_result)
        results.append(entry)
    return results


def _results_to_dict(results: Iterable[Dict[str, Any]]):
    return {_method_key(r["service"], r["method"]): r for r in results}


def _summarize_phase(
    methods: Iterable[Dict[str, Any]],
    phase_results: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    methods_list = list(methods)
    summary: Dict[str, List[str]] = {
        "open": [],
        "unauthorized": [],
        "not_supported": [],
        "redirect": [],
        "timeout": [],
        "locked": [],
        "errors": [],
    }
    methods_info: Dict[str, Dict[str, Any]] = {}
    latency_total = 0.0
    latency_count = 0

    for spec in methods_list:
        key = _method_key(spec["service"], spec["method"])
        call_result = phase_results.get(key)
        if call_result:
            summarized = _summarize_call(call_result)
            methods_info[key] = summarized
            latency = summarized.get("latency_ms")
            if isinstance(latency, (int, float)):
                latency_total += float(latency)
                latency_count += 1
            if summarized.get("success"):
                summary["open"].append(key)
            else:
                category = summarized.get("category")
                if category == "unauthorized":
                    summary["unauthorized"].append(key)
                elif category == "not_supported":
                    summary["not_supported"].append(key)
                elif category == "redirect":
                    summary["redirect"].append(key)
                elif category == "timeout":
                    summary["timeout"].append(key)
                elif category == "locked":
                    summary["locked"].append(key)
                else:
                    summary["errors"].append(key)
        else:
            summary["errors"].append(key)

    for key, value in summary.items():
        if isinstance(value, list):
            summary[key] = sorted(set(value))

    if latency_count:
        summary["latency_ms_total"] = round(latency_total, 2)
        summary["latency_ms_avg"] = round(latency_total / latency_count, 2)
    else:
        summary["latency_ms_total"] = None
        summary["latency_ms_avg"] = None
    summary["attempted_methods"] = len(methods_info)
    summary["total_methods"] = len(methods_list)
    summary["counts"] = {
        "open": len(summary["open"]),
        "unauthorized": len(summary["unauthorized"]),
        "not_supported": len(summary["not_supported"]),
        "redirect": len(summary["redirect"]),
        "timeout": len(summary["timeout"]),
        "locked": len(summary["locked"]),
        "errors": len(summary["errors"]),
    }

    return {"methods": methods_info, "summary": summary}


def _derive_anonymous_verdict(summary: Dict[str, Any]) -> str:
    if summary["counts"]["locked"]:
        return "LOCKED"
    if summary["counts"]["open"]:
        return "OPEN_ANON"
    if summary["counts"]["unauthorized"]:
        return "AUTH_REQUIRED"
    if summary["counts"]["not_supported"]:
        return "NOT_SUPPORTED"
    if summary["counts"]["redirect"]:
        return "REDIRECT"
    if summary["counts"]["timeout"]:
        return "TIMEOUT"
    return "ERROR"


def try_onvif_connection(
    ip: str,
    port: int,
    username: str = DEFAULT_USERNAME,
    password: str = DEFAULT_PASSWORD,
) -> Dict[str, Any]:
    phase_results: Dict[str, Dict[str, Any]] = {}
    phase_errors: Dict[str, List[Dict[str, Any]]] = {"anonymous": [], "authenticated": []}
    lock_seconds: Optional[int] = None

    for phase, user, passwd, encrypt in (
        ("anonymous", "", "", False),
        ("authenticated", username, password, True),
    ):
        try:
            camera = ONVIFCamera(ip, port, user, passwd, encrypt=encrypt)
        except (Fault, ONVIFError) as err:
            error_result = _build_error_result(err)
            error_result["phase"] = phase
            phase_errors[phase].append(error_result)
            if error_result.get("lock_seconds"):
                value = error_result.get("lock_seconds")
                if value is not None:
                    lock_seconds = max(lock_seconds or 0, int(value))
            continue
        except Exception as err:
            error_result = _build_error_result(err)
            error_result["phase"] = phase
            phase_errors[phase].append(error_result)
            continue

        results = _execute_method_sequence(camera, ONVIF_PRIORITY_METHODS)
        phase_results[phase] = _results_to_dict(results)

    anonymous_phase = _summarize_phase(ONVIF_PRIORITY_METHODS, phase_results.get("anonymous", {}))
    anonymous_phase["summary"]["verdict"] = _derive_anonymous_verdict(anonymous_phase["summary"])
    anonymous_phase["errors"] = phase_errors.get("anonymous", [])

    auth_phase = _summarize_phase(ONVIF_PRIORITY_METHODS, phase_results.get("authenticated", {}))
    auth_phase["errors"] = phase_errors.get("authenticated", [])

    for phase_block in (anonymous_phase, auth_phase):
        for info in phase_block["methods"].values():
            value = info.get("lock_seconds")
            if value:
                lock_seconds = max(lock_seconds or 0, int(value))

    for err_list in phase_errors.values():
        for err in err_list:
            value = err.get("lock_seconds")
            if value:
                lock_seconds = max(lock_seconds or 0, int(value))

    critical_keys = {
        _method_key(spec["service"], spec["method"])
        for spec in ONVIF_PRIORITY_METHODS
        if spec.get("critical")
    }
    media_keys = {
        _method_key(spec["service"], spec["method"])
        for spec in ONVIF_PRIORITY_METHODS
        if spec.get("target") == "media"
    }
    device_keys = {
        _method_key(spec["service"], spec["method"])
        for spec in ONVIF_PRIORITY_METHODS
        if spec.get("target") == "device"
    }

    auth_results = phase_results.get("authenticated", {})
    first_success = {"device": None, "media": None}
    media_denied = False
    critical_unauthorized: Set[str] = set()
    critical_not_supported: Set[str] = set()
    critical_timeout: Set[str] = set()

    for spec in ONVIF_PRIORITY_METHODS:
        key = _method_key(spec["service"], spec["method"])
        entry = auth_results.get(key)
        if not entry:
            continue
        if entry.get("success"):
            target = spec.get("target")
            if target in first_success and first_success[target] is None:
                first_success[target] = key
        else:
            category = entry.get("category")
            if category == "unauthorized":
                if spec.get("target") == "media":
                    media_denied = True
                if spec.get("critical"):
                    critical_unauthorized.add(key)
            if category == "not_supported" and spec.get("critical"):
                critical_not_supported.add(key)
            if category == "timeout" and spec.get("critical"):
                critical_timeout.add(key)
        if entry.get("lock_seconds"):
            lock_seconds = max(lock_seconds or 0, int(entry.get("lock_seconds")))

    def _has_category(items: Iterable[Dict[str, Any]], category: str) -> bool:
        return any((item or {}).get("category") == category for item in items)

    locked_detected = (
        anonymous_phase["summary"]["counts"]["locked"]
        or auth_phase["summary"]["counts"]["locked"]
        or _has_category(anonymous_phase.get("errors", []), "locked")
        or _has_category(auth_phase.get("errors", []), "locked")
    )

    auth_summary = auth_phase["summary"]
    auth_open = set(auth_summary["open"])
    auth_unauthorized = set(auth_summary["unauthorized"])
    auth_not_supported = set(auth_summary["not_supported"])
    auth_timeout = set(auth_summary["timeout"])
    auth_errors = set(auth_summary["errors"])
    error_categories = {
        err.get("category")
        for err in auth_phase.get("errors", [])
        if err.get("category")
    }

    if locked_detected:
        final_verdict = "LOCKED"
    elif auth_summary["attempted_methods"] == 0:
        if "unauthorized" in error_categories:
            final_verdict = "WRONG_CREDS"
        else:
            final_verdict = "LIMITED_ONVIF"
    else:
        if not auth_open:
            if auth_unauthorized or "unauthorized" in error_categories:
                final_verdict = "WRONG_CREDS"
            elif auth_not_supported and not (auth_timeout or auth_errors):
                final_verdict = "LIMITED_ONVIF"
            elif auth_timeout or "timeout" in error_categories:
                final_verdict = "LIMITED_ONVIF"
            else:
                final_verdict = "LIMITED_ONVIF"
        else:
            if auth_unauthorized or "unauthorized" in error_categories:
                final_verdict = "INSUFFICIENT_ROLE"
            elif media_denied:
                final_verdict = "INSUFFICIENT_ROLE"
            elif critical_not_supported or critical_timeout:
                final_verdict = "LIMITED_ONVIF"
            elif not first_success.get("media") and media_keys:
                final_verdict = "LIMITED_ONVIF"
            else:
                final_verdict = "AUTH_OK"

    auth_phase["summary"]["verdict"] = final_verdict

    services = {
        "device": {
            "first_success": first_success.get("device"),
            "open": sorted(auth_open & device_keys),
            "unauthorized": sorted(auth_unauthorized & device_keys),
            "not_supported": sorted(auth_not_supported & device_keys),
        },
        "media": {
            "first_success": first_success.get("media"),
            "open": sorted(auth_open & media_keys),
            "unauthorized": sorted(auth_unauthorized & media_keys),
            "not_supported": sorted(auth_not_supported & media_keys),
            "denied": media_denied,
        },
    }

    critical_summary = {
        "unauthorized": sorted(critical_unauthorized),
        "not_supported": sorted(critical_not_supported),
        "timeout": sorted(critical_timeout),
    }

    report = {
        "final_verdict": final_verdict,
        "phase": {
            "anonymous": anonymous_phase,
            "authenticated": auth_phase,
        },
        "services": services,
        "critical": critical_summary,
        "lock_seconds": lock_seconds,
        "anonymous_exposure": anonymous_phase["summary"].get("open", []),
        "media_denied": media_denied,
        "first_success": first_success,
        "errors": phase_errors["anonymous"] + phase_errors["authenticated"],
    }

    return report


def find_onvif_port(
    ip: str,
    ports: Iterable[int],
    username: str = DEFAULT_USERNAME,
    password: str = DEFAULT_PASSWORD,
    timeout: int = 2,
) -> Dict[str, Any]:
    last_unauthorized: Optional[Dict[str, Any]] = None
    for port in ports:
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                report = try_onvif_connection(ip, port, username, password)
                verdict = report.get("final_verdict")
                if verdict == "LOCKED":
                    return {
                        "status": "locked",
                        "port": port,
                        "lock_seconds": report.get("lock_seconds", 31 * 60),
                        "report": report,
                    }
                if verdict == "WRONG_CREDS":
                    last_unauthorized = {
                        "status": "unauthorized",
                        "port": port,
                        "report": report,
                    }
                    continue
                if verdict in {"AUTH_OK", "INSUFFICIENT_ROLE", "LIMITED_ONVIF"}:
                    report["port"] = port
                    return {"status": "success", "port": port, "report": report}
                # All other outcomes: continue probing
        except Exception:
            continue
    return last_unauthorized or {"status": "not_found"}


def find_working_credentials(
    ip: str,
    ports: Iterable[int],
    username: str = DEFAULT_USERNAME,
    password: Optional[str] = None,
):
    baseline = load_baseline(ip)
    progress = load_progress(ip)
    tried_passwords = progress.get("tried_passwords", [])
    attempts_this_run = 0

    def record_lock(seconds):
        next_allowed = datetime.datetime.utcnow() + datetime.timedelta(seconds=seconds)
        save_progress(
            ip,
            {
                "tried_passwords": tried_passwords,
                "next_allowed": next_allowed.isoformat(),
            },
        )
        return None, None, None

    def mark_tried(pw):
        nonlocal attempts_this_run
        if pw not in tried_passwords:
            tried_passwords.append(pw)
            attempts_this_run += 1
            save_progress(ip, {"tried_passwords": tried_passwords})

    def evaluate_report(port, pw, report):
        verdict = report.get("final_verdict")
        if verdict in {"AUTH_OK", "INSUFFICIENT_ROLE", "LIMITED_ONVIF"}:
            return port, pw, report
        if verdict == "LOCKED":
            return record_lock(report.get("lock_seconds", 31 * 60))
        if verdict == "WRONG_CREDS":
            return None, None, None
        return None, None, None

    if password is not None:
        if attempts_this_run >= MAX_PASSWORD_ATTEMPTS:
            return None, None, None
        if password not in tried_passwords:
            mark_tried(password)
        port = None
        report = None
        if baseline:
            port = baseline.get("port")
            if port:
                report = try_onvif_connection(ip, port, username, password)
                result = evaluate_report(port, password, report)
                if result[0]:
                    return result
                if report and report.get("final_verdict") == "LOCKED":
                    remove_baseline(ip)
                    return record_lock(report.get("lock_seconds", 31 * 60))
                if report and report.get("final_verdict") == "WRONG_CREDS":
                    remove_baseline(ip)
                    port = None
        if not port:
            port_info = find_onvif_port(ip, ports, username=username, password=password)
            status = port_info.get("status")
            if status == "locked":
                return record_lock(port_info.get("lock_seconds", 31 * 60))
            if status == "unauthorized":
                return None, None, None
            if status == "success":
                return port_info["port"], password, port_info.get("report")
        return None, None, None

    baseline_password = None
    port = None
    if baseline:
        baseline_password = baseline.get("password")
        port = baseline.get("port")
        if baseline_password and baseline_password not in tried_passwords:
            if attempts_this_run >= MAX_PASSWORD_ATTEMPTS:
                return None, None, None
            mark_tried(baseline_password)
            if port:
                report = try_onvif_connection(ip, port, username, baseline_password)
                result = evaluate_report(port, baseline_password, report)
                if result[0]:
                    return result
                if report and report.get("final_verdict") == "LOCKED":
                    remove_baseline(ip)
                    return record_lock(report.get("lock_seconds", 31 * 60))
                if report and report.get("final_verdict") == "WRONG_CREDS":
                    remove_baseline(ip)
                    baseline_password = None
                    port = None
        if baseline_password:
            port_info = find_onvif_port(ip, ports, username=username, password=baseline_password)
            status = port_info.get("status")
            if status == "locked":
                remove_baseline(ip)
                return record_lock(port_info.get("lock_seconds", 31 * 60))
            if status == "unauthorized":
                remove_baseline(ip)
                baseline_password = None
            if status == "success":
                return port_info["port"], baseline_password, port_info.get("report")
        remove_baseline(ip)

    for pw in PASSWORDS:
        if attempts_this_run >= MAX_PASSWORD_ATTEMPTS:
            break
        if pw in tried_passwords:
            continue
        mark_tried(pw)
        port_info = find_onvif_port(ip, ports, username=username, password=pw)
        status = port_info.get("status")
        if status == "locked":
            return record_lock(port_info.get("lock_seconds", 31 * 60))
        if status == "unauthorized":
            continue
        if status == "success":
            return port_info["port"], pw, port_info.get("report")

    remaining = [p for p in PASSWORDS if p not in tried_passwords]
    if not remaining:
        remove_baseline(ip)
    return None, None, None


def normalize_rtsp_path(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    return "/" + path.lstrip("/")


def get_rtsp_info(camera, ip, username, password):
    try:
        media_service = camera.create_media_service()
        profiles = media_service.GetProfiles()
        if profiles:
            profile_token = profiles[0].token
            stream_uri_request = media_service.create_type("GetStreamUri")
            stream_uri_request.StreamSetup = {
                "Stream": "RTP-Unicast",
                "Transport": {"Protocol": "RTSP"},
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
        u = quote(username, safe="")
        p = quote(password, safe="")
        path_enc = quote(path, safe="/?:=&")
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

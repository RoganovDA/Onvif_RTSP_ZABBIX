import datetime
import logging
import re
import socket
import time
from typing import Any, Dict, Iterable, List, Optional, Tuple
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


def _classify_category(status: Optional[int], message: str) -> Optional[str]:
    text = (message or "").lower()
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
) -> Dict[str, Any]:
    message = str(exc) if exc is not None else ""
    code = _extract_status_code(status if status is not None else exc)
    category = _classify_category(code, message)
    result: Dict[str, Any] = {
        "success": False,
        "status": code,
        "status_group": _status_group(code),
        "category": category,
        "error": message or None,
        "result": None,
    }
    if redirect:
        result["redirect"] = redirect
    if isinstance(exc, Fault):
        result["fault_code"] = getattr(exc, "code", None)
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
    }
    if "redirect_chain" in result:
        summary["redirect_chain"] = result["redirect_chain"]
    if "lock_seconds" in result:
        summary["lock_seconds"] = result.get("lock_seconds")
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
    try:
        if prepared is None:
            response = method()
        else:
            response = method(prepared)
        return {
            "success": True,
            "status": 200,
            "status_group": 2,
            "result": response,
            "category": None,
            "error": None,
        }
    except TransportError as err:
        redirect = _extract_redirect(err)
        result = _build_error_result(err, redirect=redirect)
    except Fault as err:
        result = _build_error_result(err)
    except ONVIFError as err:
        result = _build_error_result(err)
    except Exception as err:
        result = _build_error_result(err)

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


def _combine_method_status(
    methods: Iterable[Dict[str, Any]],
    anonymous: Dict[str, Dict[str, Any]],
    authenticated: Dict[str, Dict[str, Any]],
) -> Tuple[List[str], List[str], List[str], Dict[str, Dict[str, Any]], bool, int, int]:
    open_methods: List[str] = []
    protected_methods: List[str] = []
    unsupported_methods: List[str] = []
    method_status: Dict[str, Dict[str, Any]] = {}
    any_success = False
    unauthorized_count = 0
    executed_methods = 0

    for spec in methods:
        key = _method_key(spec["service"], spec["method"])
        anon_entry = anonymous.get(key)
        auth_entry = authenticated.get(key)
        method_status[key] = {
            "anonymous": _summarize_call(anon_entry),
            "authenticated": _summarize_call(auth_entry),
        }

        if auth_entry:
            executed_methods += 1
            if auth_entry.get("success"):
                any_success = True
                if anon_entry and anon_entry.get("success"):
                    open_methods.append(key)
                else:
                    protected_methods.append(key)
            else:
                category = auth_entry.get("category")
                if category == "unauthorized":
                    unauthorized_count += 1
                if category == "not_supported" or auth_entry.get("status") in (400, 404):
                    unsupported_methods.append(key)
        else:
            unsupported_methods.append(key)

    return (
        sorted(set(open_methods)),
        sorted(set(protected_methods)),
        sorted(set(unsupported_methods)),
        method_status,
        any_success,
        unauthorized_count,
        executed_methods,
    )


def try_onvif_connection(
    ip: str,
    port: int,
    username: str = DEFAULT_USERNAME,
    password: str = DEFAULT_PASSWORD,
) -> Dict[str, Any]:
    report: Dict[str, Any] = {
        "status": "error",
        "open_methods": [],
        "protected_methods": [],
        "unsupported_methods": [],
        "anonymous": {},
        "authenticated": {},
        "raw_results": {"anonymous": {}, "authenticated": {}},
        "method_status": {},
        "errors": [],
        "lock_seconds": None,
        "first_success": None,
    }

    phase_results = {}
    for phase, user, passwd, encrypt in (
        ("anonymous", "", "", False),
        ("authenticated", username, password, True),
    ):
        try:
            camera = ONVIFCamera(ip, port, user, passwd, encrypt=encrypt)
        except (Fault, ONVIFError) as err:
            error_result = _build_error_result(err)
            error_result["phase"] = phase
            report["errors"].append(error_result)
            if error_result.get("category") == "locked":
                report["status"] = "locked"
                report["lock_seconds"] = error_result.get("lock_seconds")
            elif phase == "authenticated" and error_result.get("category") == "unauthorized":
                report["status"] = "unauthorized"
            continue
        except Exception as err:
            error_result = _build_error_result(err)
            error_result["phase"] = phase
            report["errors"].append(error_result)
            continue

        results = _execute_method_sequence(camera, ONVIF_PRIORITY_METHODS)
        indexed = _results_to_dict(results)
        phase_results[phase] = indexed
        report["raw_results"][phase] = indexed
        report[phase] = {k: _summarize_call(v) for k, v in indexed.items()}

    authenticated_results = phase_results.get("authenticated", {})
    anonymous_results = phase_results.get("anonymous", {})

    (
        open_methods,
        protected_methods,
        unsupported_methods,
        method_status,
        any_success,
        unauthorized_count,
        executed_methods,
    ) = _combine_method_status(
        ONVIF_PRIORITY_METHODS,
        anonymous_results,
        authenticated_results,
    )

    report["open_methods"] = open_methods
    report["protected_methods"] = protected_methods
    report["unsupported_methods"] = unsupported_methods
    report["method_status"] = method_status

    for key in ONVIF_PRIORITY_METHODS:
        mkey = _method_key(key["service"], key["method"])
        auth_entry = authenticated_results.get(mkey)
        if report.get("first_success") is None and auth_entry and auth_entry.get("success"):
            report["first_success"] = mkey

    if report["status"] == "locked":
        return report

    if report["status"] == "unauthorized" and any_success:
        report["status"] = "success"

    if any_success:
        report["status"] = "success"
    elif report["status"] != "unauthorized":
        total_methods = len(ONVIF_PRIORITY_METHODS)
        if unsupported_methods and len(set(unsupported_methods)) >= total_methods:
            report["status"] = "not_supported"
        elif executed_methods and unauthorized_count == executed_methods:
            report["status"] = "unauthorized"
        elif not executed_methods:
            report["status"] = "error"
        else:
            # Preserve earlier status if set, otherwise generic error
            if report["status"] not in ("locked", "unauthorized"):
                report["status"] = report["status"] if report["status"] != "error" else "error"

    if report["status"] == "unauthorized":
        logging.debug(
            "ONVIF authentication failed for %s:%s (unauthorized)",
            ip,
            port,
        )
    elif report["status"] == "success":
        logging.debug(
            "ONVIF authentication succeeded for %s:%s via %s",
            ip,
            port,
            report.get("first_success"),
        )
    elif report["status"] == "not_supported":
        logging.debug(
            "ONVIF methods unsupported on %s:%s", ip, port
        )
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
                status = report.get("status")
                if status == "success":
                    report["port"] = port
                    return {"status": "success", "port": port, "report": report}
                if status == "locked":
                    return {
                        "status": "locked",
                        "port": port,
                        "lock_seconds": report.get("lock_seconds", 31 * 60),
                        "report": report,
                    }
                if status == "unauthorized":
                    last_unauthorized = {"status": "unauthorized", "port": port, "report": report}
                # Skip unsupported/error ports and continue probing
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
        status = report.get("status")
        if status == "success":
            return port, pw, report
        if status == "locked":
            return record_lock(report.get("lock_seconds", 31 * 60))
        if status == "unauthorized":
            return None, None, None
        if status == "not_supported":
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
                if report and report.get("status") == "locked":
                    remove_baseline(ip)
                    return record_lock(report.get("lock_seconds", 31 * 60))
                if report and report.get("status") == "unauthorized":
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
                if report and report.get("status") == "locked":
                    remove_baseline(ip)
                    return record_lock(report.get("lock_seconds", 31 * 60))
                if report and report.get("status") == "unauthorized":
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

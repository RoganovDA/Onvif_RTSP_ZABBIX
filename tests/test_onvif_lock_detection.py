import datetime
import sys
import types
from pathlib import Path
from types import SimpleNamespace

import pytest


class DummyOnvifError(Exception):
    pass


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


onvif_module = types.ModuleType("onvif")
onvif_module.ONVIFCamera = object
onvif_exceptions = types.ModuleType("onvif.exceptions")
onvif_exceptions.ONVIFError = DummyOnvifError
sys.modules.setdefault("onvif", onvif_module)
sys.modules.setdefault("onvif.exceptions", onvif_exceptions)


class DummyFault(Exception):
    def __init__(self, message=None, code=None):
        super().__init__(message or "")
        self.message = message
        self.code = code


class DummyTransportError(Exception):
    def __init__(self, status_code=None, message=""):
        super().__init__(message)
        self.status_code = status_code


zeep_module = types.ModuleType("zeep")
zeep_exceptions = types.ModuleType("zeep.exceptions")
zeep_exceptions.Fault = DummyFault
zeep_exceptions.TransportError = DummyTransportError
sys.modules.setdefault("zeep", zeep_module)
sys.modules.setdefault("zeep.exceptions", zeep_exceptions)

import onvif_utils


class FakeTransportError(Exception):
    def __init__(self, status_code, headers=None, detail=None):
        super().__init__(f"HTTP {status_code}")
        self.status_code = status_code
        self.http_headers = headers or {}
        self.detail = detail


class FakeSoapError(Exception):
    def __init__(self, code, message="Operation failed", detail=None):
        super().__init__(message)
        self.code = code
        self.detail = detail


@pytest.mark.parametrize("status", [423, 429, 449, 503])
def test_classify_category_http_lock_statuses(status):
    assert onvif_utils._classify_category(status, "Error", exc=None) == "locked"


@pytest.mark.parametrize(
    "fault_code",
    [
        "ter:AccountLocked",
        "ter:PasswordLocked",
        "ter:UserLocked",
        "ter:TooManyFailedAuthenticationAttempts",
    ],
)
def test_classify_category_fault_code_lock(fault_code):
    exc = SimpleNamespace(code=fault_code)
    assert onvif_utils._classify_category(None, "Operation failed", exc=exc) == "locked"


@pytest.mark.parametrize(
    "message",
    [
        "Account temporarily disabled. Please try again later.",
        "Учётная запись заблокирована, повторите попытку позже.",
        "用户已锁定, 请稍后再试。",
    ],
)
def test_classify_category_multilingual_keywords(message):
    assert onvif_utils._classify_category(None, message, exc=None) == "locked"


@pytest.mark.parametrize(
    "message,expected",
    [
        ("Please try again in 5 minutes.", 300),
        ("Account blocked for (30)s", 30),
        ("Через 10 секунд повторите попытку", 10),
        ("Подождите 2 часа перед повторной попыткой", 7200),
        ("账号被锁定, 30秒后重试", 30),
    ],
)
def test_parse_lock_time_variants(message, expected):
    assert onvif_utils.parse_lock_time(message) == expected


def test_retry_after_header_sets_verdict_and_lock_seconds(monkeypatch):
    def fake_camera(*args, **kwargs):
        raise FakeTransportError(429, headers={"Retry-After": "120"})

    monkeypatch.setattr(onvif_utils, "ONVIFCamera", fake_camera)

    report = onvif_utils.try_onvif_connection("1.2.3.4", 80)
    assert report["final_verdict"] == "LOCKED"
    assert report["lock_seconds"] == 120


def test_soap_fault_retry_after_detail(monkeypatch):
    def fake_camera(*args, **kwargs):
        raise FakeSoapError("ter:AccountLocked", detail={"Retry-After": "90"})

    monkeypatch.setattr(onvif_utils, "ONVIFCamera", fake_camera)

    report = onvif_utils.try_onvif_connection("1.2.3.4", 80)
    assert report["final_verdict"] == "LOCKED"
    assert report["lock_seconds"] == 90


def test_find_working_credentials_records_retry_after(monkeypatch):
    base_time = datetime.datetime(2024, 1, 1, 12, 0, 0)

    class FixedDateTime(datetime.datetime):
        @classmethod
        def utcnow(cls):
            return base_time

    monkeypatch.setattr(onvif_utils.datetime, "datetime", FixedDateTime)
    monkeypatch.setattr(onvif_utils, "load_baseline", lambda ip: None)
    monkeypatch.setattr(
        onvif_utils, "load_progress", lambda ip: {"tried_passwords": [], "next_allowed": None}
    )
    saved_calls = []

    def fake_save_progress(ip, data):
        saved_calls.append((ip, dict(data)))

    monkeypatch.setattr(onvif_utils, "save_progress", fake_save_progress)
    monkeypatch.setattr(onvif_utils, "remove_baseline", lambda ip: None)
    monkeypatch.setattr(
        onvif_utils,
        "find_onvif_port",
        lambda *args, **kwargs: {"status": "locked", "lock_seconds": 120},
    )

    result = onvif_utils.find_working_credentials("1.2.3.4", [80], username="admin", password="pass")

    assert result == (None, None, None)
    assert saved_calls, "Expected save_progress to be invoked"
    next_allowed_iso = saved_calls[-1][1].get("next_allowed")
    assert next_allowed_iso is not None
    next_allowed = datetime.datetime.fromisoformat(next_allowed_iso)
    assert next_allowed == base_time + datetime.timedelta(seconds=120)

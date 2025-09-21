import io
import json
import os
import sys
import types
import unittest
from unittest.mock import patch

from zeep.exceptions import Fault

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def _install_cv2_stub():
    if "cv2" in sys.modules:
        return

    cv2_stub = types.SimpleNamespace()
    cv2_stub.CAP_FFMPEG = 0

    class _DummyCap:
        def __init__(self, *args, **kwargs):
            self.opened = False

        def isOpened(self):
            return self.opened

        def release(self):
            pass

        def set(self, *_args, **_kwargs):
            return True

        def read(self):
            return False, None

        def get(self, *_args, **_kwargs):
            return 0

    cv2_stub.VideoCapture = lambda *args, **kwargs: _DummyCap()
    cv2_stub.cvtColor = lambda frame, *_args, **_kwargs: frame
    cv2_stub.COLOR_BGR2GRAY = 0

    sys.modules["cv2"] = cv2_stub


_install_cv2_stub()

import camcheck


class CamcheckReportTests(unittest.TestCase):
    def setUp(self):
        self.sample_onvif_report = {
            "final_verdict": "AUTH_OK",
            "phase": {
                "anonymous": {
                    "summary": {"verdict": "AUTH_REQUIRED", "counts": {key: 0 for key in ("open", "unauthorized", "not_supported", "redirect", "timeout", "locked", "errors")}},
                    "methods": {},
                },
                "authenticated": {
                    "summary": {
                        "counts": {
                            "open": 1,
                            "unauthorized": 0,
                            "not_supported": 1,
                            "redirect": 0,
                            "timeout": 0,
                            "locked": 0,
                            "errors": 0,
                        }
                    },
                    "methods": {
                        "devicemgmt.Bar": {
                            "success": True,
                            "status": 200,
                            "status_group": 2,
                            "category": None,
                            "error": None,
                        },
                        "devicemgmt.Foo": {
                            "success": False,
                            "status": 400,
                            "status_group": 4,
                            "category": "not_supported",
                            "error": "Bad Request",
                        },
                    },
                },
            },
            "services": {
                "device": {
                    "first_success": "devicemgmt.Bar",
                    "open": ["devicemgmt.Bar"],
                    "unauthorized": [],
                    "not_supported": ["devicemgmt.Foo"],
                },
                "media": {
                    "first_success": None,
                    "open": [],
                    "unauthorized": [],
                    "not_supported": [],
                    "denied": False,
                },
            },
            "critical": {
                "unauthorized": [],
                "not_supported": ["devicemgmt.Foo"],
                "timeout": [],
            },
            "lock_seconds": None,
            "anonymous_exposure": ["devicemgmt.Bar"],
            "media_denied": False,
        }

    @patch("camcheck.remove_progress")
    @patch("camcheck.save_progress")
    @patch("camcheck.load_progress", return_value={"tried_passwords": [], "next_allowed": None})
    @patch("camcheck.save_baseline")
    @patch("camcheck.load_baseline", return_value=None)
    @patch("camcheck.check_rtsp_stream_with_fallback")
    @patch("camcheck.get_rtsp_info", return_value=(554, "/stream"))
    @patch("camcheck.safe_call")
    @patch("camcheck.ONVIFCamera")
    @patch("camcheck.try_onvif_connection")
    @patch("camcheck.find_working_credentials")
    @patch("camcheck.is_reachable", return_value=True)
    @patch("camcheck.validate_address", return_value=(True, None))
    @patch("camcheck.parse_args")
    @patch("shutil.which", return_value="/usr/bin/ffmpeg")
    def test_camcheck_generates_new_report(
        self,
        mock_which,
        mock_parse_args,
        mock_validate,
        mock_reachable,
        mock_find_credentials,
        mock_try_connection,
        mock_camera,
        mock_safe_call,
        mock_get_rtsp_info,
        mock_check_rtsp,
        mock_load_baseline,
        mock_save_baseline,
        mock_load_progress,
        mock_save_progress,
        mock_remove_progress,
    ):
        args = types.SimpleNamespace(
            address="192.0.2.1",
            username="admin",
            password="secret",
            ping_timeout=1,
            debug=False,
            logfile=None,
        )
        mock_parse_args.return_value = args
        mock_find_credentials.return_value = (80, "secret", self.sample_onvif_report)
        mock_try_connection.return_value = self.sample_onvif_report

        class DummyService:
            def GetDeviceInformation(self):
                return types.SimpleNamespace(
                    Manufacturer="ACME",
                    Model="Cam",
                    FirmwareVersion="1.0",
                    SerialNumber="123",
                    HardwareId="ABC",
                )

            def GetNetworkInterfaces(self):
                entry = types.SimpleNamespace(
                    Info=types.SimpleNamespace(HwAddress="00:11:22:33:44:55"),
                    IPv4=types.SimpleNamespace(
                        Config=types.SimpleNamespace(
                            FromDHCP=types.SimpleNamespace(Address="192.0.2.1")
                        )
                    ),
                )
                return [entry]

            def GetSystemDateAndTime(self):
                class DateTime:
                    class UTCDateTime:
                        class Date:
                            Year = 2024
                            Month = 1
                            Day = 1

                        class Time:
                            Hour = 0
                            Minute = 0
                            Second = 0

                        Date = Date()
                        Time = Time()

                    UTCDateTime = UTCDateTime()

                return DateTime()

            def GetNTP(self):
                class NTP:
                    NTPManual = []
                    NTPFromDHCP = []

                return NTP()

            def GetUsers(self):
                class User:
                    Username = "admin"

                return [User()]

        dummy_service = DummyService()
        mock_camera.return_value.create_devicemgmt_service.return_value = dummy_service

        def safe_call_stub(service, method_name):
            method = getattr(service, method_name)
            try:
                result = method()
                return {
                    "success": True,
                    "status": 200,
                    "status_group": 2,
                    "result": result,
                    "category": None,
                    "error": None,
                }
            except Fault as fault:
                return {
                    "success": False,
                    "status": 400,
                    "status_group": 4,
                    "category": "not_supported",
                    "error": str(fault),
                    "result": None,
                }

        mock_safe_call.side_effect = safe_call_stub
        mock_check_rtsp.return_value = {
            "status": "ok",
            "note": "",
            "frames_read": 10,
            "avg_frame_size_kb": 12.5,
            "width": 1280,
            "height": 720,
            "avg_brightness": 0.5,
            "frame_change_level": 0.2,
            "real_fps": 15.0,
            "attempts": [
                {"status": "OK", "transport": "tcp", "url": "rtsp://example"}
            ],
            "best_attempt": {"status": "OK", "path": "/stream", "url": "rtsp://example"},
        }

        buffer = io.StringIO()
        with patch("sys.stdout", new=buffer):
            camcheck.main()

        output = json.loads(buffer.getvalue())
        self.assertEqual(output["final_verdict"], "AUTH_OK")
        self.assertIn("phase", output)
        self.assertIn("auth_check", output["phase"])
        auth_methods = output["phase"]["auth_check"]["methods"]
        self.assertTrue(auth_methods["devicemgmt.Bar"]["success"])
        self.assertEqual(auth_methods["devicemgmt.Foo"]["category"], "not_supported")
        mock_save_baseline.assert_called_once()
        saved_baseline = mock_save_baseline.call_args[0][1]
        self.assertEqual(saved_baseline["last_auth_status"], "AUTH_OK")
        self.assertIn("rtsp_attempts", saved_baseline)


if __name__ == "__main__":
    unittest.main()

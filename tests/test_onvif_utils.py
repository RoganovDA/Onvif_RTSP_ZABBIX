import os
import sys
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from zeep.exceptions import Fault


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

        def read(self):
            return False, None

    def _video_capture(*args, **kwargs):
        return _DummyCap()

    cv2_stub.VideoCapture = _video_capture
    cv2_stub.COLOR_BGR2GRAY = 0

    def _cvt_color(frame, *_args, **_kwargs):
        return frame

    cv2_stub.cvtColor = _cvt_color
    cv2_stub.utils = types.SimpleNamespace(
        logging=types.SimpleNamespace(LOG_LEVEL_SILENT=0, setLogLevel=lambda *_: None)
    )

    sys.modules["cv2"] = cv2_stub


_install_cv2_stub()

import onvif_utils


class DummyDeviceMgmt:
    def __init__(self, username):
        self.username = username

    def Foo(self):
        # Method not supported on this camera for any user
        raise Fault("HTTP 400 Bad Request")

    def Bar(self):
        if self.username:
            return {"ok": True}
        raise Fault("HTTP 401 Unauthorized")


class DummyCamera:
    def __init__(self, ip, port, username, password, encrypt=True):
        self.username = username

    def create_devicemgmt_service(self):
        return DummyDeviceMgmt(self.username)


class SafeCallTests(unittest.TestCase):
    def test_safe_call_not_supported(self):
        class Service:
            def Method(self):
                raise Fault("HTTP 400 Bad Request")

        result = onvif_utils.safe_call(Service(), "Method")
        self.assertFalse(result["success"])
        self.assertEqual(result["status"], 400)
        self.assertEqual(result["category"], "not_supported")


class TryOnvifConnectionTests(unittest.TestCase):
    @patch("onvif_utils.ONVIFCamera", DummyCamera)
    @patch(
        "onvif_utils.ONVIF_PRIORITY_METHODS",
        [
            {
                "service": "devicemgmt",
                "method": "Foo",
                "params": None,
                "critical": True,
                "target": "device",
            },
            {
                "service": "devicemgmt",
                "method": "Bar",
                "params": None,
                "critical": True,
                "target": "device",
            },
        ],
    )
    def test_not_supported_method_does_not_mark_unauthorized(self):
        report = onvif_utils.try_onvif_connection("127.0.0.1", 80, "admin", "password")
        self.assertEqual(report["final_verdict"], "LIMITED_ONVIF")
        methods = report["phase"]["authenticated"]["methods"]
        self.assertIn("devicemgmt.Bar", methods)
        self.assertTrue(methods["devicemgmt.Bar"]["success"])
        self.assertEqual(methods["devicemgmt.Foo"]["category"], "not_supported")
        self.assertIn("devicemgmt.Foo", report["critical"]["not_supported"])


if __name__ == "__main__":
    unittest.main()

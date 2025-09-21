import contextlib
import json
import os
import subprocess
import sys
import types
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))


def _install_cv2_stub():
    if "cv2" in sys.modules:
        return

    cv2_stub = types.SimpleNamespace()
    cv2_stub.CAP_FFMPEG = 0
    cv2_stub.CAP_PROP_OPEN_TIMEOUT = 1
    cv2_stub.CAP_PROP_READ_TIMEOUT = 2

    class _DummyCap:
        def __init__(self, *args, **kwargs):
            self.opened = False

        def isOpened(self):
            return self.opened

        def release(self):
            pass

        def set(self, *_args, **_kwargs):
            return True

    def _video_capture(*args, **kwargs):
        return _DummyCap()

    def _cvt_color(frame, *_args, **_kwargs):
        return frame

    cv2_stub.VideoCapture = _video_capture
    cv2_stub.cvtColor = _cvt_color
    cv2_stub.COLOR_BGR2GRAY = 0

    sys.modules["cv2"] = cv2_stub


_install_cv2_stub()

import rtsp_utils


class FallbackFfprobeTests(unittest.TestCase):
    def test_retry_without_stimeout_when_option_missing(self):
        url = "rtsp://example.com/stream"

        responses = [
            subprocess.CompletedProcess(
                args=[],
                returncode=1,
                stdout="",
                stderr="Unrecognized option 'stimeout'",
            ),
            subprocess.CompletedProcess(
                args=[],
                returncode=0,
                stdout=json.dumps({"streams": [{"width": 640, "height": 480}]}),
                stderr="",
            ),
        ]
        calls = []

        def fake_run(cmd, capture_output, text, timeout):
            calls.append(list(cmd))
            return responses.pop(0)

        with patch("rtsp_utils.suppress_stderr", new=contextlib.nullcontext), patch(
            "rtsp_utils.subprocess.run", side_effect=fake_run
        ):
            result = rtsp_utils.fallback_ffprobe(url, timeout=1)

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["width"], 640)
        self.assertEqual(result["height"], 480)
        self.assertIn("-stimeout", calls[0])
        self.assertNotIn("-stimeout", calls[1])


if __name__ == "__main__":
    unittest.main()

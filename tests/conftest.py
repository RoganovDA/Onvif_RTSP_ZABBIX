import sys
import types
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _ensure_module(name: str) -> types.ModuleType:
    module = sys.modules.get(name)
    if module is None:
        module = types.ModuleType(name)
        sys.modules[name] = module
    return module


onvif_module = _ensure_module("onvif")
if not hasattr(onvif_module, "ONVIFCamera"):

    class _DummyCamera:  # pragma: no cover - simple stub
        pass


    onvif_module.ONVIFCamera = _DummyCamera

onvif_exceptions = _ensure_module("onvif.exceptions")
if not hasattr(onvif_exceptions, "ONVIFError"):

    class _DummyONVIFError(Exception):
        pass


    onvif_exceptions.ONVIFError = _DummyONVIFError

zeep_module = _ensure_module("zeep")
zeep_exceptions = _ensure_module("zeep.exceptions")
if not hasattr(zeep_exceptions, "Fault"):

    class _DummyFault(Exception):
        pass


    zeep_exceptions.Fault = _DummyFault

if not hasattr(zeep_exceptions, "TransportError"):

    class _DummyTransportError(Exception):
        pass


    zeep_exceptions.TransportError = _DummyTransportError

zeep_module.exceptions = zeep_exceptions

if "rtsp_utils" not in sys.modules:
    rtsp_utils = types.ModuleType("rtsp_utils")

    def _fallback_ffprobe(*args, **kwargs):  # pragma: no cover - simple stub
        return {}


    def _check_rtsp_stream_with_fallback(*args, **kwargs):  # pragma: no cover - simple stub
        return {}


    rtsp_utils.fallback_ffprobe = _fallback_ffprobe
    rtsp_utils.check_rtsp_stream_with_fallback = _check_rtsp_stream_with_fallback
    sys.modules["rtsp_utils"] = rtsp_utils

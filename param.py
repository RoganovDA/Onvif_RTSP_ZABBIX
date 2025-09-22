# Central configuration for camcheck parameters

# Default username used for login attempts
DEFAULT_USERNAME = "admin"

# Default password used for initial connection attempts
DEFAULT_PASSWORD = "000000"

# Candidate passwords to try for ONVIF authentication
PASSWORDS = ["admin", "12345678", DEFAULT_PASSWORD]

# Maximum number of password attempts per run
MAX_PASSWORD_ATTEMPTS = 5

# Ports to probe when searching for ONVIF services
PORTS_TO_CHECK = [80, 8000, 8080, 8899, 10554, 10080, 554, 37777, 5000, 443]

# Maximum number of overall attempts in camcheck main loop
MAX_MAIN_ATTEMPTS = 3

# Allowed time drift between camera and current time (seconds)
ALLOWED_TIME_DIFF_SECONDS = 120

# Candidate RTSP paths probed when ONVIF does not provide one
RTSP_PATH_CANDIDATES = ["/Streaming/Channels/101", "/h264", "/live", "/stream1"]

# Default RTSP port used when none is provided
DEFAULT_RTSP_PORT = 554

# OpenCV capture timeout settings in milliseconds
CV2_OPEN_TIMEOUT_MS = 5000
CV2_READ_TIMEOUT_MS = 5000

# Order of color channels used when analysing RTSP frames (BGR).
COLOR_CHANNEL_NAMES = ("blue", "green", "red")

# Threshold ratios for detecting dominant colour casts on the captured frames.
# Each entry contains the pair-wise ratios that must exceed the configured
# threshold as well as optional requirements on the relative share of a channel
# in the normalised histogram.  These defaults were derived empirically on test
# footage and can be tweaked to match specific camera fleets.
COLOR_CAST_RULES = {
    "purple": {
        "ratios": {"blue_green": 1.18, "red_green": 1.12},
        "max_balance": {"green": 0.32},
        "description": "Blue/red dominance over a suppressed green channel",
    },
    "yellow": {
        "ratios": {"red_blue": 1.18, "green_blue": 1.12},
        "min_balance": {"red": 0.32, "green": 0.32},
        "description": "Blue channel suppressed compared to red/green",
    },
    "green": {
        "ratios": {"green_red": 1.12, "green_blue": 1.12},
        "min_balance": {"green": 0.38},
        "description": "Green channel dominates over red/blue",
    },
}

# Small tolerance applied to ratio checks to avoid oscillating classifications
# on noisy streams.
COLOR_RATIO_TOLERANCE = 0.02

# Difference in ratio that maps to the maximum confidence value.  When the
# ratios only slightly exceed the thresholds the confidence stays low, and it
# ramps up to 1.0 as the imbalance grows.
COLOR_CONFIDENCE_SCALE = 0.35

# Variance threshold used to determine whether the colour measurements are
# stable between frames.  Higher variance suggests flashing lights or rapidly
# changing scenes.
COLOR_VARIANCE_STABLE_THRESHOLD = 25.0

# Ordered list of ONVIF methods that are probed during authentication and
# capability discovery.  Each entry specifies the service constructor name,
# method name and optional static parameters that should be supplied.  This
# ordered list allows the authentication helper to short-circuit as soon as a
# method returns a valid response, while still providing insight into which
# calls are accessible anonymously.
ONVIF_PRIORITY_METHODS = [
    {
        "service": "devicemgmt",
        "method": "GetDeviceInformation",
        "params": None,
        "critical": True,
        "target": "device",
    },
    {
        "service": "devicemgmt",
        "method": "GetSystemDateAndTime",
        "params": None,
        "critical": True,
        "target": "device",
    },
    {
        "service": "devicemgmt",
        "method": "GetCapabilities",
        "params": {"Category": "All"},
        "critical": True,
        "target": "device",
    },
    {
        "service": "devicemgmt",
        "method": "GetScopes",
        "params": None,
        "critical": False,
        "target": "device",
    },
    {
        "service": "devicemgmt",
        "method": "GetUsers",
        "params": None,
        "critical": True,
        "target": "device",
    },
    {
        "service": "devicemgmt",
        "method": "GetNetworkInterfaces",
        "params": None,
        "critical": False,
        "target": "device",
    },
    {
        "service": "devicemgmt",
        "method": "GetNTP",
        "params": None,
        "critical": False,
        "target": "device",
    },
    {
        "service": "media",
        "method": "GetServiceCapabilities",
        "params": None,
        "critical": True,
        "target": "media",
    },
    {
        "service": "media",
        "method": "GetProfiles",
        "params": None,
        "critical": True,
        "target": "media",
    },
    {
        "service": "media",
        "method": "GetVideoSources",
        "params": None,
        "critical": False,
        "target": "media",
    },
]


def interpret_color_metrics(
    channel_means,
    channel_ratios,
    channel_variance=None,
    normalized_channels=None,
    frame_count=0,
    dominant_channel=None,
):
    """Classify colour balance deviations on RTSP frames."""

    result = {
        "diagnosis": "unknown",
        "confidence": 0.0,
        "frame_count": frame_count,
        "dominant_channel": dominant_channel,
        "triggered_metrics": None,
        "reason": "insufficient_frames" if frame_count == 0 else None,
        "max_ratio": None,
        "stability": "unknown",
        "max_variance": None,
    }

    if not channel_means or not channel_ratios:
        return result

    max_ratio = channel_ratios.get("max_min")
    if max_ratio is not None:
        result["max_ratio"] = round(max_ratio, 3)

    max_variance = None
    if channel_variance:
        max_variance = max(channel_variance.values())
        result["max_variance"] = round(max_variance, 2)
        result["stability"] = (
            "stable" if max_variance <= COLOR_VARIANCE_STABLE_THRESHOLD else "variable"
        )

    result["diagnosis"] = "balanced"
    result["reason"] = "No significant colour cast detected"
    max_min_ratio = channel_ratios.get("max_min") or 1.0
    result["confidence"] = round(1.0 / max(1.0, max_min_ratio), 3)

    best_choice = None
    best_confidence = 0.0

    for name, spec in COLOR_CAST_RULES.items():
        ratios = spec.get("ratios", {})
        meets = True
        ratio_scores = []
        for metric, threshold in ratios.items():
            value = channel_ratios.get(metric)
            if value is None or value + COLOR_RATIO_TOLERANCE < threshold:
                meets = False
                break
            ratio_scores.append(value / threshold)
        if not meets:
            continue

        balance = normalized_channels or {}
        for channel, max_share in spec.get("max_balance", {}).items():
            share = balance.get(channel)
            if share is None or share > max_share:
                meets = False
                break
        if not meets:
            continue

        for channel, min_share in spec.get("min_balance", {}).items():
            share = balance.get(channel)
            if share is None or share < min_share:
                meets = False
                break
        if not meets:
            continue

        min_ratio = min(ratio_scores) if ratio_scores else 1.0
        confidence = max(0.0, min_ratio - 1.0)
        confidence = min(1.0, confidence / COLOR_CONFIDENCE_SCALE)

        if confidence > best_confidence:
            best_choice = {
                "diagnosis": name,
                "confidence": round(confidence, 3),
                "triggered_metrics": {metric: round(channel_ratios.get(metric, 0.0), 3) for metric in ratios},
                "reason": spec.get("description"),
            }
            best_confidence = confidence

    if best_choice:
        result.update(best_choice)

    return result

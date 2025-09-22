import argparse

def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="ONVIF/RTSP Camera Audit Script")
    parser.add_argument("address", nargs="?", help="Camera IP address")
    parser.add_argument("--logfile", help="Path to log file")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("--username", help="Username for camera authentication")
    parser.add_argument("--password", help="Password for camera authentication")
    parser.add_argument(
        "--ping-timeout",
        type=int,
        default=3,
        help="Timeout in seconds for reachability check",
    )
    parser.add_argument(
        "--full-output",
        action="store_true",
        help="Emit the extended audit payload instead of the legacy flat JSON",
    )
    return parser.parse_args(argv)

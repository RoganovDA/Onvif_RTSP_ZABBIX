import argparse

def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="ONVIF/RTSP Camera Audit Script")
    parser.add_argument("address", nargs="?", help="Camera IP address")
    parser.add_argument("--logfile", help="Path to log file")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    return parser.parse_args(argv)

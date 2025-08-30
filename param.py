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

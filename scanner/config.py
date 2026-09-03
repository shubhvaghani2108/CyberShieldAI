# scanner/config.py

# Timeout settings for making connections to external endpoints.
SCAN_CONNECT_TIMEOUT = 5

# Timeout settings for waiting for data after connecting.
SCAN_READ_TIMEOUT = 10

# Maximum number of concurrent threads used for scanning orchestration tasks
# (e.g. parallel VT queries, SSL analysis, Tech detection).
# We keep this strictly to 5 to avoid overloading the Render container
# and avoid exhausting connections.
SCAN_MAX_WORKERS = 5

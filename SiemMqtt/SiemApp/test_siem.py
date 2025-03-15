from datetime import datetime
import logging
from collections import deque
from mqtt_listener import process_unauthorized_login

# Define global variables if used
UNAUTHORIZED_ATTEMPTS = {}
FAILED_ATTEMPT_WINDOW = 60  # Example time window in seconds
MAX_FAILED_ATTEMPTS = 3  # Example max attempts

if __name__ == "__main__":
    process_unauthorized_login("1742046741: INFO Batmans-MBAir.local 127.0.0.1")
    process_unauthorized_login("1742046741: INFO Batmans-MBAir.local 127.0.0.1")
    process_unauthorized_login("1742046741: INFO Batmans-MBAir.local 127.0.0.1")
    process_unauthorized_login("1742046741: INFO Batmans-MBAir.local 127.0.0.1")
    process_unauthorized_login("1742046741: INFO Batmans-MBAir.local 127.0.0.1")
    process_unauthorized_login("1742046741: INFO Batmans-MBAir.local 127.0.0.1")
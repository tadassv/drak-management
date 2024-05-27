from loguru import logger
import requests
import time


def connect(url='http://www.google.com', timeout=5):
    try:
        requests.head(url, timeout=timeout)
        return True
    except requests.ConnectionError:
        return False


def check_internet_connection_multiple_attempts(attempts=5, delay=1):
    for _ in range(attempts):
        if connect():
            return True
        time.sleep(delay)
    return False


def check_internet_connection():
    if check_internet_connection_multiple_attempts():
        logger.warning("Internet connection is active.")
        return True
    else:
        logger.success("No internet connection available.")
        return False

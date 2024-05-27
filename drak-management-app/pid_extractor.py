import time

from config_manager import ConfigManager
from loguru import logger
import requests

cm = ConfigManager()


def get_sample_pid(analysis_uid):
    tries = 5
    delay = 3
    url = f'{cm.API_HOST}/logs/{analysis_uid}/inject'
    while tries > 0:
        time.sleep(delay)
        try:
            r = requests.get(url)
            r.raise_for_status()
            break
        except requests.exceptions.RequestException as e:
            logger.critical(f"Error getting logs: {e}")
            time.sleep(delay)
            tries -= 1
            delay += 3
    if r.status_code == 404:
        return None
    return r.json()["InjectedPid"]



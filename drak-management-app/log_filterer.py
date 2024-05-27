from config_manager import ConfigManager
from loguru import logger
import requests
import json
import time

cm = ConfigManager()


def filter_logs_by_pid_only(analysis_uid, sample_pid):
    tries = 5
    delay = 3
    start_time = time.time()
    # logger.debug(f"Log Filtering Job started at: {time.ctime(start_time)}")

    url = f'{cm.API_HOST}/logs/{analysis_uid}/syscall'
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
    filtered_logs = []
    total_logs_number = 0
    filtered_logs_number = 0
    for line in r.text.splitlines():
        total_logs_number += 1
        try:
            log_entry = json.loads(line)
            if log_entry.get('PID') == sample_pid:
                filtered_logs.append(log_entry)
                filtered_logs_number += 1
        except json.JSONDecodeError as e:
            logger.critical(f"Error decoding JSON: {e}")
    end_time = time.time()
    # logger.debug(f"Log Filtering Job finished at: {time.ctime(end_time)}")
    logger.debug(f"Total execution time: {end_time - start_time} seconds")

    filtered_logs_and_counts = {
        "filtered_logs": filtered_logs,
        "total_logs_number": total_logs_number,
        "filtered_logs_number": filtered_logs_number
    }

    return filtered_logs_and_counts


def filter_logs(analysis_uid, sample_pid):
    tries = 5
    delay = 3
    start_time = time.time()
    # logger.debug(f"Log Filtering Job started at: {time.ctime(start_time)}")

    url = f'{cm.API_HOST}/logs/{analysis_uid}/syscall'
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
    filtered_logs = []
    total_logs_number = 0
    filtered_logs_number = 0
    for line in r.text.splitlines():
        total_logs_number += 1
        try:
            log_entry = json.loads(line)
            if log_entry.get('PID') == sample_pid:
                filtered_logs.append(log_entry)
                filtered_logs_number += 1
                continue
            if log_entry.get('PPID') == sample_pid:
                filtered_logs.append(log_entry)
                filtered_logs_number += 1
        except json.JSONDecodeError as e:
            logger.critical(f"Error decoding JSON: {e}")
    end_time = time.time()
    # logger.debug(f"Log Filtering Job finished at: {time.ctime(end_time)}")
    logger.debug(f"Total execution time: {end_time - start_time} seconds")

    filtered_logs_and_counts = {
        "filtered_logs": filtered_logs,
        "total_logs_number": total_logs_number,
        "filtered_logs_number": filtered_logs_number
    }

    return filtered_logs_and_counts


import random

import sample_filterer
from config_manager import ConfigManager
import requests
import time
import os
import json
from datetime import datetime
from loguru import logger
from requests.exceptions import ConnectionError, HTTPError

cm = ConfigManager()


def check_status(task_uid):
    url = f'{cm.API_HOST}/status/{task_uid}'
    r = requests.get(url)
    r.raise_for_status()
    return r.json()["status"]


def check_logs(task_uid):
    url = f'{cm.API_HOST}/logs/{task_uid}/drakrun'
    r = requests.get(url)
    r.raise_for_status()
    for line in r.text.splitlines():
        try:
            log_entry = json.loads(line)
            if log_entry.get("message") == "Injection failed with error: ERROR_ELEVATION_REQUIRED":
                logger.error(log_entry["message"])
                return "failed"
            if log_entry.get("message") == "Injection failed with error: ERROR_BAD_EXE_FORMAT":
                logger.error(log_entry["message"])
                return "failed"
            if log_entry.get("message") == "Injection succeeded but the sample didn't execute properly":
                logger.error(log_entry["message"])
                return "failed"
            if log_entry.get("message") == "Giving up after 3 failures...":
                logger.error(log_entry["message"])
                return "failed"
            if log_entry.get("message") == "Analysis failed":
                logger.error(log_entry["message"])
                return "failed"
            if log_entry.get("message") == "Analysis done. Collecting artifacts...":
                logger.success(f'{log_entry["message"]} uid: {task_uid}')
                return "done"
        except json.JSONDecodeError as e:
            logger.critical(f"Error decoding JSON: {e}")
    return "waiting"


def check_logs_is_retry_needed(task_uid):
    url = f'{cm.API_HOST}/logs/{task_uid}/drakrun'
    r = requests.get(url)
    r.raise_for_status()
    for line in r.text.splitlines():
        try:
            log_entry = json.loads(line)
            if log_entry.get("message") == "Injection failed with error: ERROR_ELEVATION_REQUIRED":
                logger.error(log_entry["message"])
                return False
            if log_entry.get("message") == "Injection failed with error: ERROR_BAD_EXE_FORMAT":
                logger.error(log_entry["message"])
                return False
        except json.JSONDecodeError as e:
            logger.critical(f"Error decoding JSON: {e}")
    return True


def get_latest_log(task_uid):
    url = f'{cm.API_HOST}/logs/{task_uid}/drakrun'
    r = requests.get(url)
    r.raise_for_status()
    try:
        last_line = r.text.splitlines()[-1]
        message = json.loads(last_line).get("message")
        timestamp = json.loads(last_line).get("created")
        dt_object = datetime.fromtimestamp(timestamp)
        logger.info(f"Status: message [{message}], time [{dt_object}]")
    except json.JSONDecodeError as e:
        logger.critical(f"Error decoding JSON: {e}")


def get_sample_hash(task_uid):
    url = f'{cm.API_HOST}/logs/{task_uid}/drakrun'
    r = requests.get(url)
    r.raise_for_status()
    for line in r.text.splitlines():
        try:
            log_entry = json.loads(line)
            if 'Sample SHA256' in log_entry["message"]:
                sha256_value = log_entry['message'].split('Sample SHA256: ')[1]
                return sha256_value

        except json.JSONDecodeError as e:
            logger.critical(f"Error decoding JSON: {e}")


def push_file(host, fpath):
    url = f'{host}/upload'
    files = {
        'file': (os.path.basename(fpath), open(fpath, "rb")),
    }

    if fpath.endswith('.exe'):
        data = {
            'timeout': f'{cm.N_ANALYSIS_TIME_SECONDS}',
            'plugins': json.dumps(["apimon", "syscalls", "procmon"], separators=(',', ':')) if not cm.ANALYSIS_TOOLS or all(
                not item for item in cm.ANALYSIS_TOOLS) else json.dumps(cm.ANALYSIS_TOOLS, separators=(',', ':'))
        }
    else:
        data = {
            'timeout': f'{cm.N_ANALYSIS_TIME_SECONDS}',
            'plugins': json.dumps(["apimon", "syscalls", "procmon"],
                                  separators=(',', ':')) if not cm.ANALYSIS_TOOLS or all(
                not item for item in cm.ANALYSIS_TOOLS) else json.dumps(cm.ANALYSIS_TOOLS, separators=(',', ':')),
            'file_name': os.path.basename(fpath) + '.exe'

        }

    try:
        r = requests.post(url, files=files, data=data)
        r.raise_for_status()
        return r.json()["task_uid"]
    except ConnectionError:
        logger.critical(f'Connection failed to {host}')
    except HTTPError:
        logger.critical(f'Server returned {r.status_code}')


def start_sample_analysis(malware_sample):
    file_path = os.path.join(cm.MALWARE_SAMPLES_LOCATION, malware_sample)

    if not os.path.isfile(file_path):
        logger.error(f"{file_path} is not a file.")
        return

    if not sample_filterer.check_win_exe(file_path):
        logger.error(f"{file_path} is not Windows executable.")
        return

    logger.info(f"Starting analysis of {file_path}")

    start_time = time.time()
    logger.debug(f"Job start time: {time.ctime(start_time)}")

    task_uid = push_file(cm.API_HOST, file_path)
    if not task_uid:
        return

    logger.warning(f'Created task with uid: {task_uid} for sample: {malware_sample}')
    time.sleep(1)

    while True:
        status_from_status = check_status(task_uid)
        status_from_logs = None
        try:
            status_from_logs = check_logs(task_uid)
            get_latest_log(task_uid)
        except Exception: #HTTPError: #requests.exceptions.RequestException
            # logger.critical("Log file does not exist yet")
            pass
        if (status_from_status == "pending") and (status_from_logs != "waiting" and status_from_logs is not None):
            break
        if status_from_status == "done":
            break
        logger.info(f"Waiting for the task '{task_uid}' to finish...")
        time.sleep(10)

    sample_hash = get_sample_hash(task_uid)
    should_retry = True

    if status_from_logs == "done":
        logger.success(f"Successfully completed the analysis, uid: {task_uid}")
        # logger.info(f"Sample SHA256: {sample_hash}")
    if status_from_logs == "failed":
        logger.error("Analysis failed")
        should_retry = check_logs_is_retry_needed(task_uid)

    end_time = time.time()
    logger.debug(f"Job end time: {time.ctime(end_time)}")
    logger.debug(f"Elapsed time: {end_time - start_time} seconds")
    result = {
        "task_uid": task_uid,
        "status": status_from_logs,
        "sha256": sample_hash,
        "sample_name": malware_sample,
        "start_time": start_time,
        "end_time": end_time,
        "elapsed_time": end_time - start_time,
        "should_retry": should_retry
    }
    return json.dumps(result)


def start_sample_analysis_mock(malware_sample): # use this for testing when you already have at least 1 sample analyzed
    file_path = os.path.join(cm.MALWARE_SAMPLES_LOCATION, malware_sample)

    if not os.path.isfile(file_path):
        logger.error(f"{file_path} is not a file.")
        return

    if not sample_filterer.check_win_exe(file_path):
        logger.error(f"{file_path} is not Windows executable.")
        return

    logger.info(f"Starting analysis of {file_path}")

    start_time = time.time()
    logger.debug(f"Job start time: {time.ctime(start_time)}")

    # delay to simulate analysis
    random_delay = random.uniform(10, 15)
    time.sleep(random_delay)

    # replace the following id with actual id from Drakvuf Sandbox analysis sample
    task_uid = '1a9de888-b45b-4919-b586-615d3bfdce25'

    logger.warning(f'Created task with uid: {task_uid} for sample: {malware_sample}')

    sample_hash = 'ac856a547eb603c9e54bb559dcc9a000345e4a4c4263202734a8a0e725a2b492'
    status_from_logs = 'done'
    should_retry = True

    if status_from_logs == "done":
        logger.success(f"Successfully completed the analysis, uid: {task_uid}")
        logger.info(f"Sample SHA256: {sample_hash}")
    if status_from_logs == "failed":
        logger.error("Analysis failed")
        should_retry = check_logs_is_retry_needed(task_uid)

    end_time = time.time()
    logger.debug(f"Job end time: {time.ctime(end_time)}")
    logger.debug(f"Elapsed time: {end_time - start_time} seconds")
    result = {
        "task_uid": task_uid,
        "status": status_from_logs,
        "sha256": sample_hash,
        "sample_name": malware_sample,
        "start_time": start_time,
        "end_time": end_time,
        "elapsed_time": end_time - start_time,
        "should_retry": should_retry
    }
    return json.dumps(result)

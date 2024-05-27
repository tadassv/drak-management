from config_manager import ConfigManager
from loguru import logger
import sqlite3
import json
import _thread
import queue
import sys
import time
import os
import database_utils

cm = ConfigManager()


################################################################################

class Server:
    def __init__(self, *args):
        self.__lock = _thread.allocate_lock()
        self.__lock.acquire()
        _thread.start_new_thread(self.__serve, args)
        self.__lock.acquire()
        del self.__lock
        if self.__error is not None:
            raise self.__error
        del self.__error

    def __serve(self, *args):
        try:
            database = sqlite3.connect(*args)
        except:
            self.__error = error = sys.exc_info()[1]
        else:
            self.__error = error = None
        self.__lock.release()
        if error is None:
            self.__QU = queue.Queue()
            while True:
                lock, one, sql, parameters, ret = self.__QU.get()
                try:
                    cursor = database.cursor()
                    cursor.execute(sql, parameters)
                    data = cursor.fetchone() if one else cursor.fetchall()
                    ret.extend([True, data])
                except:
                    ret.extend([False, sys.exc_info()[1]])
                lock.release()

    def fetch(self, one, sql, *parameters):
        lock, ret = _thread.allocate_lock(), []
        lock.acquire()
        self.__QU.put((lock, one, sql, parameters, ret))
        lock.acquire()
        if ret[0]:
            return ret[1]
        raise ret[1]


def insert_log_object(db_connection, log_object, analysis_uid, sample_name, sha256):
    remaining_attributes = {key: value for key, value in log_object.items() if
                            key != "NArgs" and key != "Plugin" and key != "TimeStamp" and key != "PID"
                            and key != "PPID" and key != "TID" and key != "UserName" and key != "UserId"
                            and key != "ProcessName" and key != "Method" and key != "EventUID" and key != "Module"
                            and key != "vCPU" and key != "CR3" and key != "Syscall" and key != "NArgs"}

    db_connection.execute(
        'INSERT INTO analysis_sample ('
        'TimeStamp, AnalysisId, Sample, '
        'SampleHash, PPID, PID, ProcessName, Method, EventUID, Module, vCPU, CR3, Syscall, NArgs, Args) '
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        (
            log_object.get("TimeStamp", None),
            analysis_uid,
            sample_name,
            sha256,
            log_object.get("PPID", None),
            log_object.get("PID", None),
            log_object.get("ProcessName", None),
            log_object.get("Method", None),
            log_object.get("EventUID", None),
            log_object.get("Module", None),
            log_object.get("vCPU", None),
            log_object.get("CR3", None),
            log_object.get("Syscall", None),
            log_object.get("NArgs", None),
            json.dumps(remaining_attributes)))


def create_db(db_file_path):
    if not database_utils.check_database_dir(db_file_path):
        return False

    db_connection = sqlite3.connect(db_file_path)
    db_connection.execute('''
        CREATE TABLE IF NOT EXISTS analysis_sample (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            TimeStamp TEXT,
            AnalysisId TEXT,
            Sample TEXT,
            SampleHash TEXT,
            PPID INTEGER,
            PID INTEGER,
            ProcessName TEXT,
            Method TEXT,
            EventUID TEXT,
            Module TEXT,
            vCPU INTEGER,
            CR3 TEXT,
            Syscall INTEGER,
            NArgs INTEGER,
            Args TEXT
        )
    ''')
    db_connection.commit()
    db_connection.close()
    return True


def pass_through(filtered_logs, analysis_uid, sample_name, sha256):
    job_pass = False
    start_time = time.time()
    logger.debug(f"Job start time: {time.ctime(start_time)}")
    db_file_path = cm.SQLITE_OUTPUT_DB_LOCATION_FILE

    if db_file_path == "":
        db_file_path = "/mnt/drak_management/database/database.db"

    # logger.debug(f'Specified location: {db_file_path}')

    if not os.path.exists(db_file_path):
        logger.warning(f"Database file not found. Trying to create a new database in: {db_file_path}")
        if not create_db(db_file_path):
            return False

    db_connection = None

    for i in range(cm.SQLITE_N_ATTEMPTS_IF_FAILED):
        try:
            time.sleep(cm.SQLITE_DELAY_ATTEMPTS_IF_FAILED * i)
            db_connection = sqlite3.connect(db_file_path)
            for log in filtered_logs:
                log = json.dumps(log)
                log_object = json.loads(log)
                insert_log_object(db_connection, log_object, analysis_uid, sample_name, sha256)

            db_connection.commit()
            logger.success(f"Log objects inserted successfully into the database. uid: {analysis_uid}")
            job_pass = True
            break

        except sqlite3.Error as e:
            logger.error(f"Error inserting {analysis_uid} log objects into the database: {e}")
            logger.critical(f"Attempt: {i + 1}/{cm.SQLITE_N_ATTEMPTS_IF_FAILED}")
            continue

        finally:
            db_connection.close()

    end_time = time.time()
    logger.debug(f"Job end time: {time.ctime(end_time)}")
    logger.debug(f"Elapsed time: {end_time - start_time} seconds")

    return job_pass


def get_syscall_pair(analysis_uid):
    job_pass = False
    sys_call_most_common_str = None
    sys_call_most_rare_str = None
    db_file_path = cm.SQLITE_OUTPUT_DB_LOCATION_FILE

    if db_file_path == "":
        db_file_path = "/mnt/drak_management/database/database.db"

    if not os.path.exists(db_file_path):
        return False, sys_call_most_common_str, sys_call_most_rare_str


    db_connection = None

    for i in range(cm.SQLITE_N_ATTEMPTS_IF_FAILED):
        try:
            time.sleep(cm.SQLITE_DELAY_ATTEMPTS_IF_FAILED * i)
            db_connection = sqlite3.connect(db_file_path)
            sys_call_most_rare = db_connection.execute(
                "SELECT Method, Count(Method) as cnt FROM analysis_sample WHERE AnalysisId = ? "
                "GROUP BY Method ORDER BY cnt DESC LIMIT 1",
                (analysis_uid,)).fetchone()

            sys_call_most_common = db_connection.execute(
                "SELECT Method, Count(Method) as cnt FROM analysis_sample WHERE AnalysisId = ? "
                "GROUP BY Method ORDER BY cnt ASC LIMIT 1",
                (analysis_uid,)).fetchone()
            if sys_call_most_rare:
                sys_call_most_rare_str = str(sys_call_most_rare[0])
            if sys_call_most_common:
                sys_call_most_common_str = str(sys_call_most_common[0])
            job_pass = True
            break

        except sqlite3.Error as e:
            logger.error(f"Error retrieving objects from syscall database: {e}")
            logger.critical(f"Attempt: {i + 1}/{cm.SQLITE_N_ATTEMPTS_IF_FAILED}")
            continue

        finally:
            db_connection.close()

    return job_pass, sys_call_most_common_str, sys_call_most_rare_str


def get_all_aggregated_syscall():
    logger.debug("Aggregation starting.")

    db_file_path = cm.SQLITE_OUTPUT_DB_LOCATION_FILE

    if db_file_path == "":
        db_file_path = "/mnt/drak_management/database/database.db"

    if not os.path.exists(db_file_path):
        return False

    sys_call_aggregate = None
    db_connection = None

    for i in range(cm.SQLITE_N_ATTEMPTS_IF_FAILED):
        try:
            time.sleep(cm.SQLITE_DELAY_ATTEMPTS_IF_FAILED * i)
            db_connection = sqlite3.connect(db_file_path)
            sys_call_aggregate = db_connection.execute(
                "SELECT Method, Count(Method) as cnt FROM analysis_sample "
                "GROUP BY Method ORDER BY cnt DESC"
            ).fetchall()
            break

        except sqlite3.Error as e:
            logger.error(f"Error aggregating objects from syscall database: {e}")
            logger.critical(f"Attempt: {i + 1}/{cm.SQLITE_N_ATTEMPTS_IF_FAILED}")
            continue

        finally:
            db_connection.close()

    logger.success("Successfully aggregated.")
    return sys_call_aggregate

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


def insert_log_object(db_connection, analytics):
    db_connection.execute(
        'INSERT INTO session_log ('
        'AnalysisId, SampleName, SampleHash, StartDate, EndDate, Duration, Attempt, Status, '
        'SysCallsUnfiltered, SysCallsFiltered, SysCallMostCommon, SysCallRarest) '
        'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
        (
            analytics.get("analysis_id", None),
            analytics.get("sample_name", None),
            analytics.get("sample_hash", None),
            analytics.get("start_date", None),
            analytics.get("end_date", None),
            analytics.get("duration", None),
            analytics.get("attempt", None),
            analytics.get("status", None),
            analytics.get("sys_calls_unfiltered", None),
            analytics.get("sys_calls_filtered", None),
            analytics.get("sys_call_most_common", None),
            analytics.get("sys_call_rarest", None)))


def create_db(db_file_path):
    if not database_utils.check_database_dir(db_file_path):
        return False

    db_connection = sqlite3.connect(db_file_path)
    db_connection.execute('''
        CREATE TABLE IF NOT EXISTS session_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            AnalysisId TEXT,
            SampleName TEXT,
            SampleHash TEXT,
            StartDate TEXT,
            EndDate TEXT,
            Duration INTEGER,
            Attempt INTEGER,
            Status TEXT,
            SysCallsUnfiltered INTEGER,
            SysCallsFiltered INTEGER,
            SysCallMostCommon TEXT,
            SysCallRarest TEXT
        )
    ''')
    db_connection.commit()
    db_connection.close()
    return True


def pass_through(analytics):
    job_pass = False
    start_time = time.time()
    logger.debug(f"Job start time: {time.ctime(start_time)}")
    db_file_path = cm.SQLITE_SESSION_OUTPUT_DB_LOCATION_FILE

    if db_file_path == "":
        db_file_path = "/mnt/drak_management/database/session.db"

    # logger.debug(f'Specified location: {db_file_path}')

    if not os.path.exists(db_file_path):
        logger.warning(f"Database file not found. Trying to create a new database in: {db_file_path}")
        if not create_db(db_file_path):
            return False

    try:
        analysis_uid = analytics.get("analysis_id", None)
    except Exception as e:
        logger.error(f"Error extracting analysis_id from analytics: {e}")
        return False

    db_connection = None

    for i in range(cm.SQLITE_N_ATTEMPTS_IF_FAILED):
        try:
            time.sleep(cm.SQLITE_DELAY_ATTEMPTS_IF_FAILED * i)
            db_connection = sqlite3.connect(db_file_path)
            insert_log_object(db_connection, analytics)
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

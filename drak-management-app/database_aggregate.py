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


def insert_log_object(db_connection, aggregates):
    for syscall, occurrence in aggregates:
        db_connection.execute(
            'INSERT INTO syscall_aggregate ('
            'SysCall, Occurrence) '
            'VALUES (?, ?)',
            (syscall, occurrence))
    db_connection.commit()


def create_db(db_file_path):
    if not database_utils.check_database_dir(db_file_path):
        return False

    db_connection = sqlite3.connect(db_file_path)
    db_connection.execute('''
        CREATE TABLE IF NOT EXISTS syscall_aggregate (
            SysCall TEXT,
            Occurrence INTEGER
        )
    ''')
    db_connection.commit()
    db_connection.close()
    return True


def recreate_db(db_file_path):
    db_connection = sqlite3.connect(db_file_path)
    try:
        db_connection.execute('DROP TABLE IF EXISTS syscall_aggregate')
        db_connection.execute('''
            CREATE TABLE IF NOT EXISTS syscall_aggregate (
                SysCall TEXT,
                Occurrence INTEGER
            )
        ''')
        db_connection.commit()
    except Exception as e:
        logger.error(f"Error creating database: {e}")
        return False
    finally:
        db_connection.close()
    return True


def pass_through(aggregates):
    if not aggregates:
        return
    logger.debug("Saving aggregates starting.")
    db_file_path = cm.SQLITE_AGGREGATED_SYSCALL_DB_LOCATION_FILE

    if db_file_path == "":
        db_file_path = "/mnt/drak_management/database/aggregated.db"

    logger.debug(f'Specified location: {db_file_path}')

    if not os.path.exists(db_file_path):
        logger.warning(f"Database file not found. Trying to create a new database in: {db_file_path}")
        if not create_db(db_file_path):
            return False

    if not recreate_db(db_file_path):
        return False

    db_connection = sqlite3.connect(db_file_path)

    try:
        insert_log_object(db_connection, aggregates)
        # logger.success("Log objects inserted successfully into the database.")
        job_pass = True

    except sqlite3.Error as e:
        logger.error(f"Error inserting log objects into the database: {e}")
        job_pass = False

    finally:
        db_connection.close()

    logger.success("Successfully saved aggregates.")

    return job_pass

import database_aggregate
from config_manager import ConfigManager
from loguru import logger
import concurrent.futures
import os
import json
import time
import drak_healthchecker
import check_internet_con
import check_xl_list
import database
import database_session
import log_filterer
import minio_keys_extractor
import push_sample
import sample_filterer
import pid_extractor

successfully_processed = 0
total_executed = 0
futures = []


def process_sample_result(result, retries):
    result_dict = json.loads(result)
    analysis_uid = result_dict.get("task_uid")
    status = result_dict.get("status")
    sha256 = result_dict.get("sha256")
    sample_name = result_dict.get("sample_name")
    start_time = result_dict.get("start_time")
    end_time = result_dict.get("end_time")
    elapsed_time = result_dict.get("elapsed_time")

    if status == "done":
        logger.success(f"Analysis of {sample_name} completed successfully")
        # logger.info(f"Sample SHA256: {sha256}")
        # logger.info(f"Analysis UID: {analysis_uid}")
        # logger.info(f"Analysis Start time: {time.ctime(start_time)}")
        # logger.info(f"Analysis End time: {time.ctime(end_time)}")
        # logger.info(f"Analysis Elapsed time: {elapsed_time} seconds")
        logger.info(f"Number of retries: {retries}")
    elif status == "failed":
        logger.error(f"Analysis of {sample_name} failed")

    sample_pid = pid_extractor.get_sample_pid(analysis_uid)
    if not sample_pid:
        logger.error(f"No PID found for {sample_name}")
        return None
    filtered_logs_and_counts = log_filterer.filter_logs(analysis_uid, sample_pid)
    if not filtered_logs_and_counts or not filtered_logs_and_counts.get("filtered_logs"):
        logger.error(f"No logs found for {sample_name}")
        return None
    filtered_logs = filtered_logs_and_counts.get("filtered_logs")
    total_logs_number = filtered_logs_and_counts.get("total_logs_number")
    filtered_logs_number = filtered_logs_and_counts.get("filtered_logs_number")

    db_syscall_job_status = database.pass_through(filtered_logs, analysis_uid, sample_name, sha256)
    if not db_syscall_job_status:
        return None

    # logger.debug(f'First log preview: {filtered_logs[:1]}')
    return_v = {
        "total_logs_number": total_logs_number,
        "filtered_logs_number": filtered_logs_number
    }
    return return_v


def build_analysis_analytics(result, attempt, total_logs_number, filtered_logs_number):
    result_dict = json.loads(result)

    analysis_uid = result_dict.get("task_uid")
    status = result_dict.get("status")
    if status == "done":
        status = "Pass"
    else:
        status = "Fail"
    if (total_logs_number is not None and filtered_logs_number is not None
            and total_logs_number == 0 and filtered_logs_number == 0):
        status = "Conflict"
    sha256 = result_dict.get("sha256")
    sample_name = result_dict.get("sample_name")
    start_time = result_dict.get("start_time")
    if start_time:
        start_time = time.ctime(start_time)
    end_time = result_dict.get("end_time")
    if end_time:
        end_time = time.ctime(end_time)
    elapsed_time = result_dict.get("elapsed_time")

    sys_calls_unfiltered = total_logs_number
    sys_calls_filtered = filtered_logs_number

    get_syscall_pair_status, sys_call_most_common, sys_call_rarest = database.get_syscall_pair(analysis_uid)
    if not get_syscall_pair_status:
        # logger.error(f"Failed to get syscall pair for {sample_name}")
        pass

    analytics = {
        "analysis_id": analysis_uid,
        "sample_name": sample_name,
        "sample_hash": sha256,
        "start_date": start_time,
        "end_date": end_time,
        "duration": elapsed_time,
        "attempt": attempt,
        "status": status,
        "sys_calls_unfiltered": sys_calls_unfiltered,
        "sys_calls_filtered": sys_calls_filtered,
        "sys_call_most_common": sys_call_most_common,
        "sys_call_rarest": sys_call_rarest
    }
    return analytics


def process_sample(malware_sample, sample_number):
    processed = None
    logger.info(f'Pushing - {sample_number: >4}/{cm.N_SAMPLES_TO_SCAN: <4} {malware_sample} for analysis')
    time.sleep(1)

    analysis_attempts = 1
    if cm.N_RETRIES_PER_SAMPLE > 0:
        for i in range(cm.N_RETRIES_PER_SAMPLE + 1):
            result = push_sample.start_sample_analysis(malware_sample)
            if result:
                result_dict = json.loads(result)
                status = result_dict.get("status")
                if status == "done":
                    processed = process_sample_result(result, i)
                    total_logs_number = 0
                    filtered_logs_number = 0
                    try:
                        total_logs_number = processed.get("total_logs_number")
                        filtered_logs_number = processed.get("filtered_logs_number")
                    except Exception:
                        logger.error(f"Could not process the output of the analysis")
                        # return
                    analysis_attempts = i + 1
                    analytics = build_analysis_analytics(result, i + 1, total_logs_number, filtered_logs_number)
                    db_session_job_status = database_session.pass_through(analytics)
                    if not db_session_job_status:
                        logger.critical(
                            "Could not populate session database of the following sample analysis analytics.")
                        return
                    break

                logger.warning(f"Analysis of the sample '{malware_sample}' was unsuccessful.")
                should_retry = result_dict.get("should_retry")
                analytics = build_analysis_analytics(result, i + 1, None, None)
                db_session_job_status = database_session.pass_through(analytics)
                if not db_session_job_status:
                    logger.critical(
                        "Could not populate session database of the following sample analysis analytics.")
                    return
                if not should_retry:
                    logger.warning("Will no longer retry because the sample cannot be started.")
                    time.sleep(cm.N_RETRY_GRACE_TIME_SECONDS)
                    break
                if cm.N_RETRIES_PER_SAMPLE - i != 0:
                    logger.warning(
                        f"Retrying {cm.N_RETRIES_PER_SAMPLE - i} more time(s) "
                        f"after {cm.N_RETRY_GRACE_TIME_SECONDS} second(s).")
                time.sleep(cm.N_RETRY_GRACE_TIME_SECONDS)

            else:
                logger.warning(f"Error processing {malware_sample}: No result returned")
                logger.critical("No analysis analytics will be saved.")
                if cm.N_RETRIES_PER_SAMPLE - i != 0:
                    logger.warning(
                        f"Analysis of the sample '{malware_sample}' was unsuccessful. "
                        f"Retrying {cm.N_RETRIES_PER_SAMPLE - i} more time(s) "
                        f"after {cm.N_RETRY_GRACE_TIME_SECONDS} second(s).")
                    if cm.N_RETRY_GRACE_TIME_SECONDS > 0:
                        time.sleep(cm.N_RETRY_GRACE_TIME_SECONDS)
    else:
        result = push_sample.start_sample_analysis(malware_sample)
        if result:
            result_dict = json.loads(result)
            status = result_dict.get("status")
            if status == "done":
                processed = process_sample_result(result, 0)
                total_logs_number = processed.get("total_logs_number")
                filtered_logs_number = processed.get("filtered_logs_number")
                analytics = build_analysis_analytics(result, 1, total_logs_number, filtered_logs_number)
                db_session_job_status = database_session.pass_through(analytics)
                if not db_session_job_status:
                    logger.critical("Could not populate session database of the following sample analysis analytics.")
                    return
        else:
            logger.error(f"Error processing {malware_sample}: No result returned")
            logger.critical("No analysis analytics will be saved.")

    global total_executed

    if not processed:
        logger.error(
            f"Analysis of the sample '{malware_sample}' was unsuccessful after {analysis_attempts} attempt(s).\n\n")
        total_executed += 1
        return

    logger.success(
        f"Analysis of the sample '{malware_sample}' was successful after {analysis_attempts} attempt(s).\n\n")

    total_executed += 1
    global successfully_processed
    successfully_processed += 1
    logger.debug("###############################")
    logger.success(f"Successfully processed: {successfully_processed}/{cm.N_SAMPLES_TO_SCAN_SUCCESSFULLY}")
    logger.debug("###############################\n")
    if successfully_processed >= cm.N_SAMPLES_TO_SCAN_SUCCESSFULLY:
        logger.success("SUCCESS LIMIT REACHED. Other if any samples will be skipped.")
        for future in futures:
            future.cancel()


def aggregate_system_calls():
    logger.info("Aggregating system calls from the current batch.")
    start_time = time.time()
    logger.debug(f"Job start time: {time.ctime(start_time)}")

    aggregates = database.get_all_aggregated_syscall()
    if not aggregates:
        logger.error("Aggregation failed.")
    if not database_aggregate.pass_through(aggregates):
        logger.error("Could not save aggregates.")

    end_time = time.time()
    logger.debug(f"Job end time: {time.ctime(end_time)}")
    logger.debug(f"Elapsed time: {end_time - start_time} seconds")


def main(startup_pass_flag):
    if not startup_pass_flag:
        logger.error("Startup checks failed. Exiting.")
        return

    main_start_time = time.time()

    try:
        malware_samples_in_dir = [f for f in os.listdir(cm.MALWARE_SAMPLES_LOCATION) if
                                  os.path.isfile(os.path.join(cm.MALWARE_SAMPLES_LOCATION, f))]
    except FileNotFoundError:
        logger.error(f"No such file or directory: {cm.MALWARE_SAMPLES_LOCATION}")
        return
    if not malware_samples_in_dir:
        logger.error(f"No malware samples were found in '{cm.MALWARE_SAMPLES_LOCATION}'")
        return
    logger.debug(f'Total number of samples in directory: {len(malware_samples_in_dir)}')
    malware_samples = malware_samples_in_dir[:cm.N_SAMPLES_TO_SCAN]
    logger.debug(f'Number of samples queued for analysis: {len(malware_samples)}')

    if not cm.IS_BYPASS_XL_CHECK:
        check_xl_list.run_xl_list_command()

    if not cm.IS_BYPASS_DRAK_HEALTHCHECK and not drak_healthchecker.check_services_main():
        logger.error("Drak healthchecker failed.")
        return

    if cm.IS_VERIFY_WINDOWS_EXECUTABLES:
        if not sample_filterer.verify_windows_executables(cm.MALWARE_SAMPLES_LOCATION, malware_samples):
            logger.error("Verification failed. Not all malware samples are Windows executables.")
            return
        else:
            logger.success("Verification passed. All malware samples are Windows executables.")

    global successfully_processed
    global futures
    future_args_mapping = {}

    with concurrent.futures.ThreadPoolExecutor(max_workers=cm.N_CONCURRENT_GUESTS) as executor:
        process(executor, future_args_mapping, malware_samples)

    logger.success("Batch analysis and processing finished.")

    if cm.IS_AGGREGATE_SYSCALLS_AFTER_BATCH_ANALYSIS:
        aggregate_system_calls()
    main_end_time = time.time()
    logger.debug("##############################################################")
    logger.debug("##############################################################")
    logger.info("All jobs finished.\n")
    logger.info(f'Total number of samples in directory: {len(malware_samples_in_dir)}')
    logger.info(f'Number of samples queued for analysis: {len(malware_samples)}\n')
    logger.success(f"Successfully processed: {successfully_processed}/{cm.N_SAMPLES_TO_SCAN_SUCCESSFULLY}")
    logger.error(
        f"Unsuccessfully processed: {total_executed - successfully_processed}/{cm.N_SAMPLES_TO_SCAN_SUCCESSFULLY}\n")
    logger.info(f'Number of samples executed: {total_executed}\n')
    logger.info(f'Success rate: {(successfully_processed / total_executed) * 100}%\n')
    logger.info(f"Batch analysis started:  {time.ctime(main_start_time)}")
    logger.info(f"Batch analysis finished: {time.ctime(main_end_time)}")
    logger.info(
        f"Elapsed time: "
        f"{time.strftime('%H hours %M minutes %S seconds', time.gmtime(round(main_end_time - main_start_time)))}"
        f" or {round((main_end_time - main_start_time), 2)} seconds")
    logger.debug("##############################################################")


def process(executor, future_args_mapping, malware_samples):
    global futures
    futures = []
    sample_i = 0
    for sample in malware_samples:
        sample_i += 1
        future = executor.submit(process_sample, sample, sample_i)
        futures.append(future)
        future_args_mapping[future] = sample
        time.sleep(cm.N_DELAY_CONCURRENT_THREADS)
    for future in concurrent.futures.as_completed(futures):
        s = future_args_mapping[future]
        try:
            future.result()
        except Exception as e:
            if isinstance(e, concurrent.futures.CancelledError):
                logger.warning(f"SUCCESS LIMIT REACHED. Skipped sample: {s}")
            else:
                logger.error(f"Error processing sample: {e}")


if __name__ == '__main__':
    cm = None
    config_pass = True
    try:
        cm = ConfigManager()
    except Exception as e:
        logger.error("An error occurred during configuration parsing. Terminating the program.")
        logger.critical(f"Error details: {e}")
        config_pass = False
    if cm.IS_SAVE_LOGS:
        log_format = ("<green>{time:YYYY-MM-DD HH:mm:ss.SSS zz}</green> | <level>{level: <8}</level> | "
                      "<yellow>Line {line: >4} ({file: <21}):</yellow> <b>{message}</b>")
        logger.add(cm.OUTPUT_LOGS_LOCATION_FILE, level="TRACE", format=log_format, colorize=False, backtrace=False,
                   diagnose=True)
    if cm.IS_CHECK_INTERNET_CON_DISABLED:
        if check_internet_con.check_internet_connection():
            logger.error("Internet connection is enabled. Disconnect from the internet and retry.")
            config_pass = False
    main(config_pass)


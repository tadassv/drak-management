from loguru import logger
import configparser


class ConfigManager:
    def __init__(self, config_file='config.ini'):
        self.config = configparser.ConfigParser()
        self.config.read(config_file)

        # ADMIN
        self.IS_SAVE_LOGS = self.get_config_boolean('admin', 'save_logs')
        self.IS_BYPASS_XL_CHECK = self.get_config_boolean('admin', 'bypass_xl_check')
        self.IS_BYPASS_DRAK_HEALTHCHECK = self.get_config_boolean('admin', 'bypass_drak_healthcheck')
        self.IS_CHECK_INTERNET_CON_DISABLED = self.get_config_boolean('admin', 'check_internet_connection_is_disabled')
        self.SUDO_PASS = self.get_config_value('admin', 'sudo_password')

        # API
        self.API_HOST = self.get_config_value('api', 'api_host')

        # SQLITE
        self.SQLITE_HOSTNAME = self.get_config_value('sqlite_database', 'hostname')
        self.SQLITE_PORT = self.get_config_int('sqlite_database', 'port')
        self.SQLITE_N_ATTEMPTS_IF_FAILED = self.get_config_int('sqlite_database', 'number_of_attempts_if_failed')
        self.SQLITE_DELAY_ATTEMPTS_IF_FAILED = (
            self.get_config_int('sqlite_database', 'initial_delay_between_attempts_if_failed'))

        # GUEST VM
        self.GUEST_RAM = self.get_config_int('guest_vm_config', 'memory_mb')

        # MANAGEMENT
        self.IS_VERIFY_WINDOWS_EXECUTABLES = self.get_config_boolean('management', 'verify_windows_executables')
        self.N_CONCURRENT_GUESTS = self.get_config_int('management', 'number_of_concurrent_guests')
        self.N_DELAY_CONCURRENT_THREADS = self.get_config_int('management', 'delay_between_concurrent_threads_seconds')
        self.N_ANALYSIS_TIME_SECONDS = self.get_config_int('management', 'analysis_time_seconds')
        self.ANALYSIS_TOOLS = self.get_config_list('management', 'analysis_tools')
        self.N_RETRY_GRACE_TIME_SECONDS = self.get_config_int('management', 'retry_grace_time_seconds')
        self.N_RETRIES_PER_SAMPLE = self.get_config_int('management', 'number_of_retries_per_sample')
        self.IS_AGGREGATE_SYSCALLS_AFTER_BATCH_ANALYSIS = (
            self.get_config_boolean('management', 'aggregate_syscalls_after_batch_analysis'))

        # AUTOMATION
        self.N_SAMPLES_TO_SCAN = self.get_config_int('automation', 'number_of_samples_to_scan')
        self.N_SAMPLES_TO_SCAN_SUCCESSFULLY = self.get_config_int('automation',
                                                                  'number_of_samples_to_scan_successfully')

        # DIRECTORIES        
        self.OUTPUT_LOGS_LOCATION_FILE = self.get_config_value('directories', 'output_logs_location_file')
        self.MALWARE_SAMPLES_LOCATION = self.get_config_value('directories', 'malware_samples_location')
        self.SQLITE_OUTPUT_DB_LOCATION_FILE = self.get_config_value('directories', 'sqlite_output_db_location_file')
        self.SQLITE_SESSION_OUTPUT_DB_LOCATION_FILE = self.get_config_value('directories',
                                                                            'sqlite_session_output_db_location_file')
        self.SQLITE_AGGREGATED_SYSCALL_DB_LOCATION_FILE = (
            self.get_config_value('directories', 'sqlite_aggregated_syscall_db_location_file'))
        self.MINIO_KEYS_LOCATION_FILE = self.get_config_value('directories', 'minio_keys_location_file')

        self.perform_check_on_number_of_samples()

    def get_config_value(self, section, key):
        try:
            return self.config[section][key]
        except KeyError as e:
            logger.error(f'Config value not found for {section}/{key}')
            logger.critical(f'Error: {e}')
            raise

    def get_config_boolean(self, section, key):
        try:
            return self.config.getboolean(section, key)
        except (KeyError, ValueError) as e:
            logger.error(f'Error parsing boolean config value for {section}/{key}')
            logger.critical(f'Error: {e}')
            raise

    def get_config_int(self, section, key):
        try:
            return self.config.getint(section, key)
        except (KeyError, ValueError) as e:
            logger.error(f'Error parsing integer config value for {section}/{key}')
            logger.critical(f'Error: {e}')
            raise

    def get_config_list(self, section, key):
        try:
            plugins_str = self.config.get(section, key)
            plugins_list = [plugin.strip() for plugin in plugins_str.split(',')]
            return plugins_list
        except (KeyError, ValueError) as e:
            logger.error(f'Error parsing list config value for {section}/{key}')
            logger.critical(f'Error: {e}')
            raise

    def perform_check_on_number_of_samples(self):
        if self.N_SAMPLES_TO_SCAN_SUCCESSFULLY > self.N_SAMPLES_TO_SCAN:
            self.N_SAMPLES_TO_SCAN_SUCCESSFULLY = self.N_SAMPLES_TO_SCAN

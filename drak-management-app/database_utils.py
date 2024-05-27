from config_manager import ConfigManager
from loguru import logger
import os
import getpass
import subprocess

cm = ConfigManager()


def create_missing_dir(db_dir):
    if cm.SUDO_PASS == "":
        logger.error('Sudo password is not configured!')
        logger.warning('Setup your password in config.ini - "sudo_password ="')
        return False
    try:
        current_user = getpass.getuser()
        cmd1 = subprocess.Popen(['echo', cm.SUDO_PASS], stdout=subprocess.PIPE)
        cmd2 = subprocess.Popen(['sudo', '-S', 'mkdir', '-p', db_dir], stdin=cmd1.stdout,
                                stdout=subprocess.PIPE)
        cmd2.communicate()
        cmd3 = subprocess.Popen(['sudo', 'chown', '-R', f'{current_user}:{current_user}', db_dir],
                                stdout=subprocess.PIPE)
        cmd3.communicate()
        logger.warning(f"Database directory not found. Created new directory in: {db_dir}")
        return True
    except subprocess.CalledProcessError as e:
        logger.critical(f"Error creating directory: {e}")
        return False


def check_database_dir(db_file_path):
    db_dir = os.path.dirname(db_file_path)
    if not os.path.exists(db_dir) and not create_missing_dir(db_dir):
        logger.error("Could not create directory.")
        return False
    return True

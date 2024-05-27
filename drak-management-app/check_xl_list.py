from loguru import logger
import configparser
import subprocess


def run_xl_list_command():
    config = configparser.ConfigParser()
    config.read('config.ini')

    try:
        sudo_password = config['admin']['sudo_password']
    except KeyError:
        logger.error('Failed to fetch sudo_password.')
        return
    if sudo_password == "":
        logger.error('Sudo password is not configured!')
        logger.warning('Setup your password in config.ini - "sudo_password ="')
        return
    try:
        command = 'xl list'
        command = command.split()

        cmd1 = subprocess.Popen(['echo', sudo_password], stdout=subprocess.PIPE)
        cmd2 = subprocess.Popen(['sudo', '-S'] + command, stdin=cmd1.stdout, stdout=subprocess.PIPE)

        result = cmd2.stdout.read().decode()

        if result == "":
            logger.error("Could not execute 'xl list'. Either provided wrong password or other issues.")
            return

        logger.debug('\n' + result)

    except subprocess.CalledProcessError as e:
        logger.error(f"Error executing 'xl list': {e}")


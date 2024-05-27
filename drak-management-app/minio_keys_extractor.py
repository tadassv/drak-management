from loguru import logger
import os
import configparser


# support util

def extract_minio_keys():
    file_path = None

    config = configparser.ConfigParser()
    config.read('config.ini')

    try:
        file_path = config['directories']['minio_keys_location_file']
    except KeyError:
        logger.error('Failed to fetch minio_keys_location_file, using default.')

    if file_path == "":
        file_path = "/etc/drakcore/minio.env"

    logger.debug(f'Specified location: {file_path}')

    access_key = None
    secret_key = None

    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            for line in file:
                key, value = line.strip().split('=')
                if key == 'MINIO_ACCESS_KEY':
                    access_key = value
                elif key == 'MINIO_SECRET_KEY':
                    secret_key = value
        if access_key and secret_key:
            logger.success(f"MINIO_ACCESS_KEY: {access_key}")
            logger.success(f"MINIO_SECRET_KEY: {secret_key}")
        else:
            logger.warning("MINIO_ACCESS_KEY or MINIO_SECRET_KEY not found in the file.")
    else:
        logger.error(f"MINIO configuration file not found in {file_path}")


if __name__ == '__main__':
    extract_minio_keys()

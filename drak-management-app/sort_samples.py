import os
import shutil
import configparser
import time

from loguru import logger


def main():
    config = configparser.ConfigParser()
    config.read('config_sorting.ini')

    source_folder = config.get('Settings', 'source_folder')
    destination_folder = config.get('Settings', 'destination_folder')
    num_files_to_copy = config.getint('Settings', 'num_files_to_copy')
    change_file_extension = config.getboolean('Settings', 'change_file_extension')

    file_types = {
        ".exe": b"\x4D\x5A",
        ".dll": b"\x4D\x5A",
        ".ocx": b"\x4D\x5A"
    }

    num_files_copied = 0

    malware_samples_in_dir = [f for f in os.listdir(source_folder) if
                              os.path.isfile(os.path.join(source_folder, f))]
    logger.info(f'[{len(malware_samples_in_dir)}] Total number of files in directory.')
    logger.info(f'[{num_files_to_copy}] Executables to sort.')
    time.sleep(2)
    logger.debug('#################################################################')
    for i in range(5):
        logger.warning(f'Starting sorting in {5 - i} seconds')
        time.sleep(1)

    for filename in os.listdir(source_folder):
        if num_files_to_copy != 0 and num_files_copied >= num_files_to_copy:
            break
        file_extension = os.path.splitext(filename)[1].lower()
        if file_extension not in file_types:
            with open(os.path.join(source_folder, filename), "rb") as f:
                file_header = f.read(2)
                for extension, magic_number in file_types.items():
                    if file_header == magic_number:
                        file_extension = extension
                        break

        if file_extension in file_types:
            if change_file_extension:
                destination_file_path = os.path.join(destination_folder, os.path.splitext(filename)[0] + file_extension)
            else:
                destination_file_path = os.path.join(destination_folder, filename)
            shutil.copy(os.path.join(source_folder, filename), destination_file_path)
            num_files_copied += 1
            logger.success(f'  OK - {num_files_copied: >4}/{num_files_to_copy: <4} {filename}')

        else:
            logger.error(f'FAIL ----------- {filename}')
    logger.debug('#################################################################')
    logger.info(f'[{num_files_copied}] Total EXEcutables processed.')


if __name__ == '__main__':
    main()

from loguru import logger
import os


def check_win_exe(file_path):
    file_types = {
        ".exe": b"\x4D\x5A",
        ".dll": b"\x4D\x5A",
        ".ocx": b"\x4D\x5A"
    }

    with open(file_path, "rb") as f:
        file_header = f.read(2)
        for extension, magic_number in file_types.items():
            if file_header == magic_number:
                return True
        return False


def verify_windows_executables(malware_samples_location, malware_samples):
    check_flag = True
    for sample in malware_samples:
        file_path = os.path.join(malware_samples_location, sample)
        if os.path.isfile(file_path) and check_win_exe(file_path):
            logger.info(f"{sample} is a Windows executable.")
        else:
            logger.warning(f"{sample} is not a Windows executable.")
            check_flag = False
    return check_flag

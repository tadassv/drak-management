from loguru import logger
import subprocess
import re


def remove_escape_sequences(text):
    return re.sub(r'\x1b\[[0-9;]*m', '', text)


def check_services_status():
    command = 'drak-healthcheck'
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        logger.debug("Command 'drak-healthcheck' output:")
        logger.info('\n' + result.stdout)
        output_lines = result.stdout.split('\n')
        # logger.debug(output_lines)
        output_lines_normalized = [remove_escape_sequences(line) for line in output_lines]
        # logger.debug(output_lines_normalized)
        service_statuses = {}
        current_service = None
        for line in output_lines_normalized:
            if line.strip():
                if 'Checking' in line:
                    current_service = None
                elif current_service:
                    parts = line.split()
                    if len(parts) >= 2:
                        service = parts[0]
                        status = ' '.join(parts[1:])
                        service_statuses[service] = status
                    else:
                        logger.warning(f"Issue with line: {line}. "
                                       f"Expected at least 2 parts but found {len(parts)} parts.")
                else:
                    current_service = line.strip()
                    if 'Checking' not in current_service:
                        parts = current_service.split()
                        if len(parts) >= 2:
                            service = parts[0]
                            status = ' '.join(parts[1:])
                            service_statuses[service] = status
                        else:
                            logger.warning(f"Issue with line: {current_service}. "
                                           f"Expected at least 2 parts but found {len(parts)} parts.")

        drakrun_service_number = 0
        drakpostprocess_service_number = 0

        for service_name, status in service_statuses.items():
            if 'drakrun@' in service_name:
                # logger.debug(f"Status of {service_name}: {status}")
                if status == 'OK':
                    drakrun_service_number += 1
            if 'drak-postprocess@' in service_name:
                # logger.debug(f"Status of {service_name}: {status}")
                if status == 'OK':
                    drakpostprocess_service_number += 1

        logger.debug(f"Drakrun (Guest VM) services: {drakrun_service_number}")
        logger.debug(f"Drak Post Process services: {drakpostprocess_service_number}")

        for status in service_statuses.values():
            if status != 'OK':
                return False

        return True

    except subprocess.CalledProcessError as e:
        logger.critical(f"Error executing 'drak-healthcheck': {e}")
        return False


def check_services_main():
    all_services_ok = check_services_status()

    if all_services_ok:
        logger.success("All services are OK\n\n\n")
    else:
        logger.error("At least one service has failed\n\n\n")

    return all_services_ok

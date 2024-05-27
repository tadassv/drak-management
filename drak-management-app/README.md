# Welcome to Drak Management - a Malware Analysis Automation Tool build for Drakvuf Sandbox
  
## 1st step - Install required dependencies  
```  
pip3 install -r requirements.txt  
```  
  
## 2nd step - review configurations  
  
`config.ini` stores "Drak Management" configuration. You might want to edit various locations, input your sudo password, etc.  
  
## Optional step - Sort Malware samples (Windows executables)  
  
`config_sorting.ini` stores sample sorting configuration. Pick your `source_folder` and `destination_folder`, modify `num_files_to_copy` and specify whether to `change_file_extension`  
  
Run `python3 sort_samples.py`  
  
## 3rd step - run "Drak Management"  
  
Run `python3 app.py`  
  
### "Drak Management" configuration explained  

#### Administrative configuration:  
 
`save_logs` - whether to safe console output (`true` / `false`) (default: `true`)  

`bypass_xl_check` = whether not to perform "xl list" -- Xen check (`true` / `false`) (default: `false`)  

`bypass_drak_healthcheck` = whether not to perform "drak healthcheck" -- Drakvuf services health check (`true` / `false`) (default: `false`)   

`check_internet_connection_is_disabled` = whether to perform the connection to the internet checking (`true` / `false`) (default: `true`)  

`sudo_password` = specify your ***sudo*** password here to allow elevated privileges (mainly for Xen check, directory creation & permission management)
 
---  
#### Api configuration:

`api_host` - Drakvuf Sandbox API (default: `http://localhost:6300`)
 
---
#### SQLite database configuration:
`hostname` - database hostname (default: `localhost`)  

`port` - database port(default: `3306`)  

`number_of_attempts_if_failed` - number of try attempts for a single DB operation (min: `1`, default: `10`) 

`initial_delay_between_attempts_if_failed` - initial delay (in seconds) after the first failed attempt to perform a DB operation (min: `0`, default: `3`)  
  
  ---
#### Guest VM configuration:
`memory_mb` - amount of allocated RAM memory (in megabytes) for a single VM instance (depends on the **Guest** OS, should be matched with Drakvuf Sandbox configuration default: `3076`)  

  ---
#### Generic management configuration:
`verify_windows_executables` - whether to verify if all samples are Windows executables before starting batch analysis (`true` / `false`) (Recommended to set it 

`false` if sample sorting was performed prior to the analysis, default: `false`)  

`number_of_concurrent_guests` - number of concurrent **Guest** VM (Make sure that your Host machine has enough resources to run certain amount of Guest VMs, min: `1`, default: `1`)

`delay_between_concurrent_threads_seconds` - initial delay (in seconds) between concurrent Guest VMs (min: `0` (will start all Guest VMs simultaneously), default: `20`)

`analysis_time_seconds` - sample analysis time (in seconds) (default: `60`)

`analysis_tools` - specify which tools Drakvuf Sandbox should be using to analyse the sample (below is a list of all available tools) (default: `syscalls`)  

`retry_grace_time_seconds` - if the analysis was unsuccessful, how much time (in seconds) to wait before retrying (min: `0`, default: `5`)  

`number_of_retries_per_sample` - specify the number of analysis retries (min: `0` (will attempt to analyze the sample only once without retrying), default: `3`) 

`aggregate_syscalls_after_batch_analysis` - whether to perform system calls aggregation at the end batch analysis (`true` / `false`) (default: `true`)  
  
  ---
#### Automation configuration:

`number_of_samples_to_scan` - number of queued samples to analyze (default: `100`)  

`number_of_samples_to_scan_successfully` - number of samples to analyze successfully (The batch analysis stops when the limit is reached **OR** ran out of samples to analyze) (default: `100`)  
  
  ---
#### Directories configuration:

`output_logs_location_file` - specify a full path and file name with .log extension where to output console logs (example: `/home/osusername/Documents/console_output.log`)

`minio_keys_location_file` - specify a full path and filename with extension where minio environment file is located (default: `/etc/drakcore/minio.env`)

`sqlite_output_db_location_file` -  specify a full path and filename with extension where to save database file for system calls (example: `/home/osusername/Documents/database.db`)

`sqlite_session_output_db_location_file` - specify a full path and filename with extension where to save database file for every analysis sample result (example: `/home/osusername/Documents/session.db`)

`sqlite_aggregated_syscall_db_location_file` - specify a full path and filename with extension where to save database file for aggregated system calls (example: `/home/osusername/Documents/aggregated.db`)

`malware_samples_location` - specify a full path where all samples are located (example: `/home/osusername/Documents/analysis_samples/sorted`)
  
  ---
### Available plugins:  
```  
apimon  
bsodmon  
clipboardmon  
codemon  
cpuidmon  
crashmon  
debugmon  
delaymon  
exmon  
filedelete  
filetracer  
ipt  
librarymon  
memdump  
procdump  
procmon  
regmon  
rpcmon  
ssdtmon  
syscalls  
tlsmon  
windowmon  
wmimon  
```

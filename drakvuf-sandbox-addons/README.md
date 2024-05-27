## Drakvuf Sandbox Patches
Disclaimer: The code presented in the `Drakvuf Sandbox Patches` section is derived from the 
original source code developed by [Drakvuf Sandbox](https://github.com/CERT-Polska/drakvuf-sandbox). 

I do not claim ownership of any code provided herein; these patches represent modifications made for specific use cases.

Additionally, all modifications are made in compliance with the GNU General Public License (GPL).

The LICENSE file for the Drakvuf Sandbox is also included in the parent directory of this repository.


### Use Case

If you are experiencing issues with the `draksetup postinstall` command, 
applying the Drakvuf Sandbox patches can help resolve problems when setting up Guest VM.
These patches are intended to provide code fixes that address issues encountered during the post-installation process.

However, due to the fact that Dravuf Sandbox is development, in the future these patches can become invalid.

Proceed with caution and make backups.

### How to Install

To apply the Drakvuf Sandbox patches, follow these steps:

1. **Locate the Patches:**

   Withing the repository you should find `opt-couple_of_dirs-site-packages` & `opt-venvs-drakrun` directories.


2. **Locate the Target Directories:**

   Identify the directories in your Drakvuf Sandbox installation where the files need to be replaced and make backups.

   These directories typically found in `/opt/venvs/drakrun/bin` and `/opt/venvs/drakrun/lib/python3.8/site-packages/drakrun`.


3. **Replace Files:**

   Manually replace the existing files in the specified directories with the patched versions. Or use the provided script.

   !!! Make sure to back up the original files before proceeding with the replacement.

   - **To replace (with sudo):**
     ```sh
     cp -rT /opt-venvs-drakrun/bin /opt/venvs/drakrun/bin
     cp -rT /opt-couple_of_dirs-site-packages/drakrun /opt/venvs/drakrun/lib/python3.8/site-packages/drakrun
     ```

4. **Verify Installation:**
   After replacing the files, run the `draksetup postinstall` command again to verify that the issues have been resolved.

### Patches change log

Here are some of key changes:

- `draksetup.py` on `create_rekall_profile` function introduced retry mechanism. Addressed the issue where sometimes
Rekall profile could not be fetched due to unstable VM state.
- `injector.py` on `_run_with_timeout` function replaced exception raises with log error messages.
- `injector.py` on `write_file` function increased timeout from 60 to 180.

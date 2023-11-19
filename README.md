# quick-threat-hunting
Quick scripts and one liners to look for malicious processes, persistence, and obfuscation techniques

# Windows OS Quickstart
1. Spawn an **Administrator** PowerShell terminal.
2. Run this PowerShell one-liner to download and execute the script.
   
   `[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12, [Net.SecurityProtocolType]::Ssl3; Invoke-WebRequest "https://raw.githubusercontent.com/brandondudley1775/quick-threat-hunting/main/os_windows.ps1" -OutFile .\os_windows.ps1 -UseBasicParsing; Set-ExecutionPolicy RemoteSigned -Force; Unblock-File .\os_windows.ps1; .\os_windows.ps1`

# Linux OS Quickstart
1. Spawn a root shell, user will work if root us unavailable.  Try these commands:

`sudo su`

or

`sudo su - root`

or

`sudo find /home -exec /bin/bash \;`

2. Run the command to retrieve and run the script, there are two possible commands to choose from to account for missing binaries/permissions:

`wget https://raw.githubusercontent.com/brandondudley1775/quick-threat-hunting/main/os_linux.py; python3 os_linux.py`

or

`curl https://raw.githubusercontent.com/brandondudley1775/quick-threat-hunting/main/os_linux.py > os_linux.py; python3 os_linux.py`

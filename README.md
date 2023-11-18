# quick-threat-hunting
Quick scripts and one liners to look for malicious processes, persistence, and obfuscation techniques

# Windows OS Quickstart
1. Spawn an **Administrator** PowerShell terminal.
2. Run this PowerShell one-liner to download and execute the script.
   
   `Invoke-WebRequest "https://raw.githubusercontent.com/brandondudley1775/quick-threat-hunting/main/os_windows.ps1" -OutFile .\os_windows.ps1; Set-ExecutionPolicy RemoteSigned -Force; Unblock-File .\os_windows.ps1; .\os_windows.ps1`

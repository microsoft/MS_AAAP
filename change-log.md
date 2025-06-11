# Script Version: v1.7

***Last Updated: June 11th, 2025 @ 1:07 PM (EST)***

## Change Log

#### Changes
- [@blakedrumm] Changed directory from `C:\MicrosoftSupportLogs` to `C:\MS_AAAP`.
- [@blakedrumm] Add shortname **AutomaticUpdates** to **AutomaticUpdatesWuApp** in `Update_Info.txt`.
- [@blakedrumm] Added `// Note without NoAutoUpdate=1 with newer OS can result in updates installing automatically` and `// this is the option we recommend to prevent system from auto installing updates` to REG-WindowsUpdate.txt.
- [@blakedrumm] Added **Microsoft.Update.ServiceManager** - COM Object checking output to Windows Update folder.
- [@blakedrumm] Gathering Hybrid Worker Service (HybridWorkerService) and AutoAssessPatchService.
- [@blakedrumm] Added `HKLM:\SOFTWARE\Microsoft\Azure\HybridWorker` and `HKLM:\SOFTWARE\Microsoft\HybridRunbookWorkerV2` registry path to output.
- [@blakedrumm] Fixed `WindowsUpdate.log` gathering / output.
- [@blakedrumm] Azure VM folder: Windows Azure Log, WAP Agent Log. `C:\WindowsAzure\Logs\WaAppAgent.log`.
- [@blakedrumm] Gathering Windows Update Active Hours information.
- [@blakedrumm] Added Pretty *.status `..\Packages\Plugins\Microsoft.CPlat.Core.WindowsPatchExtension\1.5.71\Status\69.status`
- [@blakedrumm] Added new parameter to script: `-SkipNetworkConnectivityCheck`

---
&nbsp; \
&nbsp;

# Script Version: v1.6

***Last Updated: March 24th, 2025 @ 11:53 AM (EST)***

## Change Log

#### Changes
- [@blakedrumm] Fixed issue with `azcmagent check` command when the location is missing in the HIMDS metadata.
- [@blakedrumm] A big thank you to Francisco Carranza for reporting this! Fixed issue with wrong URL being presented in the output when copying the script directly from GitHub: `https://aka.ms/MicrosoftSupportScripts` -> `https://aka.ms/MicrosoftSupportLogs`

---
&nbsp; \
&nbsp;

# Script Version: v1.5

***Last Updated: March 18th, 2025 @ 9:48 AM (EST)***

## Change Log

#### Changes
- [@blakedrumm] Removed Network Trace parameter and functionality.

---
&nbsp; \
&nbsp;

# Script Version: v1.4

***Last Updated: March 13th, 2025 @ 11:29 AM (EST)***

## Change Log

#### Changes
- [@blakedrumm] Added **ScheduledInstallEveryWeek** to `Update_Info.txt` file.
- [@blakedrumm] Added DISM Logs to `<OutputPath>Windows_Update\DISM`.
- [@blakedrumm] Added a check at the beginning of the script to verify that all required functions are available. This ensures the user did not copy the Generate-Microsoft-Support-Logs.ps1 script directly from GitHub. The script now requires downloading the release and cannot be run by simply copying and pasting.
- [@blakedrumm] Added gathering currently configured Roles and Features.
- [@blakedrumm] Added gathering HIMDS metadata from the local API.
- [@blakedrumm] Added `-AzureLocation` and `-NetworkTrace` parameters.
- [@blakedrumm] Fixed formatting of files output.

---
&nbsp; \
&nbsp;

# Script Version: v1.3

***Last Updated: December 1st, 2024 @ 2:06 AM (EST)***

## Change Log

#### Changes
- [@blakedrumm] Keep in mind I did not capture all the changes I made with this release as this was around a 90% rewrite.
- [@blakedrumm] Added changelog to release.
- [@blakedrumm] Moved the functions into separate folders when in development. This allows easier maintenance on the separate parts of the tool.
- [@blakedrumm] You now have to assemble the script to merge all the functions into the main script, which makes it one `.ps1` file to run. This is the release file.
- [@blakedrumm] Added gathering User Rights from local machine.
- [@blakedrumm] Added additional details to `<OutputPath>\OS-Miscellaneous\Misc.txt` file. You can now see all of the versions of PowerShell installed on the machine.
- [@blakedrumm] Fixed spelling errors in the main script.
- [@blakedrumm] Completely rewrote the directory listings to now include the file (and folder) sizes.
  ```
  ==============================================================================================
  ==============================================================================================
  
      Directory: C:\Packages (241.89 MB utilized)
  
  Mode    LastWriteTime          Size            Type                   Name
  ----    -------------          ------          ----                   ----
  d-----  11/14/2024 12:23 AM    241.89 MB       Directory              Plugins
  
  ==============================================================================================
  ==============================================================================================
  
      Directory: C:\Packages\Plugins (241.89 MB utilized)
  
  Mode    LastWriteTime          Size            Type                   Name
  ----    -------------          ------          ----                   ----
  d-----  11/14/2024 12:23 AM    63.75 MB        Directory              Microsoft.Azure.Automation.HybridWorker.HybridWorkerForWindows
  d-----  10/13/2024 10:01 AM    173.33 MB       Directory              Microsoft.Azure.AzureDefenderForServers.MDE.Windows
  d-----  10/5/2024 12:04 AM     1.32 MB         Directory              Microsoft.CPlat.Core.WindowsPatchExtension
  d-----  7/15/2024 1:56 PM      1.00 MB         Directory              Microsoft.SoftwareUpdateManagement.WindowsOsUpdateExtension
  d-----  4/4/2024 10:57 AM      2.48 MB         Directory              microsoft.cplat.core.runcommandhandlerwindows
  
  ==============================================================================================
  ==============================================================================================
  
      Directory: C:\Packages\Plugins\Microsoft.Azure.Automation.HybridWorker.HybridWorkerForWindows (63.75 MB utilized)
  
  Mode    LastWriteTime          Size            Type                   Name
  ----    -------------          ------          ----                   ----
  d-----  11/14/2024 12:23 AM    63.75 MB        Directory              1.1.13
  
  ==============================================================================================
  ==============================================================================================
  
      Directory: C:\Packages\Plugins\Microsoft.Azure.Automation.HybridWorker.HybridWorkerForWindows\1.1.13 (63.75 MB utilized)
  
  Mode    LastWriteTime          Size            Type                   Name
  ----    -------------          ------          ----                   ----
  -a----  11/26/2024 9:58 AM     733 bytes       File                   state.json
  d-----  11/14/2024 12:23 AM    50.56 MB        Directory              HybridWorkerPackage
  d-----  11/14/2024 12:23 AM    0 bytes         Directory              HybridWorkerWork
  d-----  11/14/2024 12:23 AM    219 bytes       Directory              RuntimeSettings
  -a----  11/14/2024 12:23 AM    687 bytes       File                   HandlerEnvironment.json
  d-----  11/14/2024 12:23 AM    0 bytes         Directory              status
  d-----  11/14/2024 12:23 AM    12.69 MB        Directory              HybridWorkerAgent
  d-----  11/14/2024 12:23 AM    517.17 KB       Directory              bin
  -a----  11/14/2024 12:23 AM    459 bytes       File                   HybridWorkerVersion.xml
  -a----  11/14/2024 12:23 AM    1.07 KB         File                   manifest.xml
  -a----  11/14/2024 12:23 AM    442 bytes       File                   HandlerManifest.json
    ```
  - [@blakedrumm] Modified the Event Log gathering to also gather the Localemetadata.
  - [@blakedrumm] Now using one function for all time stamps used in the script.
  - [@blakedrumm] Added file `script-log.log` to output folder, which will allow you to see the output when the script ran.
  - [@blakedrumm] Modified formatting in many files in the output.
  - [@blakedrumm] Added script auto updater. This will pull the latest release (if needed) from GitHub.
  - [@blakedrumm] Added VM Metadata to output. (`<OutputPath>\AzureVM\vm_metadata.json`)
  - [@blakedrumm] Added Azure Arc Connected Machine Agent folder to output. (`<OutputPath>\Azure_Arc\AzureConnectedMachineAgent`)
  - [@blakedrumm] Added Client Application ID's available to the Operating System. (`<OutputPath>\Windows_Update\Update_Info.txt`)
  - [@blakedrumm] Renamed folder in output from `arc` to `Azure Arc`.
  - [@blakedrumm] Added additional data to the `<OutputPath>\WindowsTime.txt` file. Also modified the output to make it easier to understand.
  - [@blakedrumm] Added comments and regions to the whole script for organization.
  - [@blakedrumm] Added check for Administrator at beginning of script. If script is not running as administrator, it will attempt to relaunch as Administrator.
  - [@blakedrumm] The script will now output to a zip file (`MicrosoftSupportLogs_BLAKES-HOMEPC_10_19_2024_03-58-AM.zip`), and to a folder.
  - [@blakedrumm] Added the following file in the `<OutputPath>\Azure_Arc` folder: `REG-AzureConnectedMachineAgent.txt`, `REG-WindowsHotpatch.txt`
  - [@blakedrumm] Converted all commands from `Get-WmiObject` to `Get-CimInstance`.
  - [@blakedrumm] Completely rewrote the check SSL functionality to now include if the certificate is correct and display other checks like TLS compatibility.
  - [@blakedrumm] Added more detailed information to the ClientApplicationID table in the `Update_Info.txt` file:
    ```
    NOTE: The Windows Update Service is used to install updates, however it is the ClientApplicationID that initiates the request to the Windows Update Service. 
          The following Table can be used to help establish the application that initiated the request to the Windows Update Service.
    
    ClientApplicationID                             Process Initiating the Request to the Windows Update Service
    ===================                             =================================================================================
    UpdateManagement_Patch-MicrosoftOMSComputer     Azure Automation Update Management (v1) initiating Windows Update Service to install updates
    Windows Defender                                Updates initiated by Windows Defender Antivirus (now Microsoft Defender Antivirus) for malware definitions
    MoUpdateOrchestrator                            Modern Update Orchestrator - Part of the Windows Update infrastructure, managing updates (Windows 10 and later).
    Update                                          Windows Update Agent - Local Windows Update process responsible for detecting, downloading, and installing updates.
    CcmExec                                         Configuration Manager (SCCM) Client Agent Host service (Microsoft Endpoint Configuration Manager client), responsible for initiating software update scans and installation.
    UpdateOrchestrator                              Update Orchestrator Service (UsoSvc) - Core Windows service managing scanning, downloading, installing, and scheduling of Windows Updates
    UpdateAgentLCU                                  Used internally by Windows Update for installing Servicing Stack Updates (SSUs) and Cumulative Updates
    Azure VM Guest Patching                         Azure VM Guest Patching feature initiating updates on Azure virtual machines.
    WindowsOsUpdateExtension                        Azure Arc-enabled servers Update Management Extension initiating updates
    OperationalInsights                             Azure Log Analytics Agent (formerly OMS) initiating updates via Update Management
    SqlIaaSExtension.Service.exe                    Azure SQL Virtual Machine Extension - Manages SQL Server updates
    wusa                                            Windows Update Standalone Installer - Used for manual installation of update packages (.msu files)
    UpdateManagementActionExec.exe                  Azure VM Guest Patching - Part of 'Microsoft.SoftwareUpdateManagement.WindowsOsUpdateExtension' extension
    UsoClient                                       Update Session Orchestrator Client - Windows Update client utility
    ITSecMgmt                                       Windows Security (Defender) - Initiates security updates and scans
    SUS Client                                      Software Update Services Client - Refers to Windows Server Update Services (WSUS) client interactions
    
    If you do not want Azure VMGuest Patching to randomly install updates after 10 PM local Regional time change the system to "Customer managed Schedules" in Update Manager
    ```


---
&nbsp; \
&nbsp;

# Script Version: v1.2

***Last Updated: October 4th, 2024 @ 10:10 PM (EST)***

## Change Log

#### Changes
- [@blakedrumm] Fixed spelling errors in the main script.



---
&nbsp; \
&nbsp;

# Script Version: v1.1

***Last Updated: April 10th, 2024 @ 10:25 PM (EST)***

## Change Log

#### Changes
- Moved the license information to bottom of the script.
- Added script version inside the script.




---
&nbsp; \
&nbsp;

# Script Version: v1.0

***Last Updated: April 10th, 2024 @ 9:46 PM (EST)***

## Change Log

#### First Release!
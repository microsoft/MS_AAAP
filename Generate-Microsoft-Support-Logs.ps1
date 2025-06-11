<#
	.SYNOPSIS
		Generate and collect logs needed to assist Microsoft Support with customer support cases.
	
	.DESCRIPTION
		This script collects the log files and diagnostic information required by Microsoft Support to investigate customer issues. The data is saved to a folder named `C:\MS_AAAP_<LocalComputerName>`. Please note that the collected data is not automatically uploaded; users must manually zip the folder and its subfolders and then upload it to Microsoft Support.
	
	.PARAMETER OutputFolder
		Specifies the folder where the collected logs and diagnostic data will be saved. If not provided, the script defaults to `C:\MS_AAAP_<LocalComputerName>`.
	
	.PARAMETER DontDisplayProgressBar
		Suppresses the display of the progress bar during the script execution. Use this parameter in environments where progress indicators are unnecessary or could interfere with automation.
	
	.PARAMETER AzureLocation
		A description of the AzureLocation parameter.
	
	.PARAMETER SkipNetworkConnectivityCheck
		Allows you to skip the network connectivity check.
	
	.EXAMPLE
		Run the script to collect logs:
		.\Generate-Microsoft-Support-Logs.ps1
	
	.EXAMPLE
		Run the script to collect logs and output to a specific folder:
		.\Generate-Microsoft-Support-Logs.ps1 -OutputFolder `C:\Temp`
	
	.EXAMPLE
		Run the script to collect logs and hide the progress bar:
		.\Generate-Microsoft-Support-Logs.ps1 -DontDisplayProgressBar
	
	.OUTPUTS
		A folder containing log files and diagnostic information. By default, the folder is created in the script's current directory or at `C:\MS_AAAP_<LocalComputerName>`. If the `-OutputFolder` parameter is specified, the data is saved to the provided path instead. The folder may include subfolders to organize the collected data.
	
	.NOTES
		Authors:
		Austin Mack (austinm@microsoft.com)
		Blake Drumm (blake.drumm@microsoft.com)
		
		Contributors:
		Robert Janes (robertjanes@microsoft.com)
		Piotr Walesiak (piotr.walesiak@microsoft.com)
		
		Version: DevelopmentVersion
		Last Modified: 2nd June 2025
		
		MIT License
		
		Copyright (c) Microsoft
		
		Permission is hereby granted, free of charge, to any person obtaining a copy
		of this software and associated documentation files (the "Software"), to deal
		in the Software without restriction, including without limitation the rights
		to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
		copies of the Software, and to permit persons to whom the Software is
		furnished to do so, subject to the following conditions:
		
		The above copyright notice and this permission notice shall be included in all
		copies or substantial portions of the Software.
		
		THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
		IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
		FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
		AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
		LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
		OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
		SOFTWARE.
	
	.INPUTS
		None. You do not need to pipe any input to this script.
	
	.LINK
		For additional information: https://github.com/microsoft/MS_AAAP
#>
[CmdletBinding()]
param
(
	[Alias('OutputPath', 'op', 'OutputDirectory', 'od')]
	[string]$OutputFolder = "C:\MS_AAAP",
	[Alias('NoProgressBar', 'npb', 'ddpb')]
	[switch]$DontDisplayProgressBar,
	[ValidateSet('asiapacific', 'australiacentral', 'australiacentral2', 'australiaeast', 'australiasoutheast', 'brazilsouth', 'brazilsoutheast', 'canadaeast', 'canadacentral', 'centralindia', 'centralus', 'centralusstage', 'centraluseuap', 'chinaeast2', 'chinanorth', 'chinanorth2', 'chinanorth3', 'eastasia', 'eastasiastage', 'eastus', 'eastus2', 'eastus2euap', 'eastus2stage', 'eastusstg', 'europe', 'france', 'francecentral', 'francesouth', 'germany', 'germanynorth', 'germanywestcentral', 'global', 'india', 'israel', 'israelcentral', 'italy', 'italynorth', 'japan', 'japaneast', 'japanwest', 'jioindiacentral', 'jioindiawest', 'korea', 'koreacentral', 'koreasouth', 'mexicocentral', 'newzealand', 'newzealandnorth', 'norway', 'norwayeast', 'norwaywest', 'northeurope', 'northcentralus', 'northcentralusstage', 'poland', 'polandcentral', 'qatar', 'qatarcentral', 'singapore', 'southafrica', 'southafricanorth', 'southafricawest', 'southcentralus', 'southcentralusstg', 'southindia', 'spaincentral', 'sweden', 'swedencentral', 'switzerland', 'switzerlandnorth', 'switzerlandwest', 'uaecentral', 'uaenorth', 'uksouth', 'ukwest', 'unitedstates', 'usgov', 'usgovarizona', 'usgovtexas', 'usgovvirginia', 'westcentralus', 'westeurope', 'westindia', 'westus', 'westus2', 'westus3', 'westusstage', 'none')]
	[Alias('Location')]
	[string]$AzureLocation = 'none',
	[Parameter(HelpMessage = 'Allows you to skip the network connectivity check.')]
	[Alias('sncc', 'SkipNetworkCheck')]
	[switch]$SkipNetworkConnectivityCheck
)
BEGIN
{
	trap
	{
		Write-Console $_ -ForegroundColor Red
	}
		
	#Start-Transcript -Path "C:\Temp\script-transcript.txt" -Force
	#region Script version
	$version = "DevelopmentVersion"
	#endregion Script version
	$script:VerbosePreference = $VerbosePreference
	try
	{
		$ScriptPath = Split-Path -ErrorAction Stop -Verbose:$VerbosePreference -Path $MyInvocation.MyCommand.Definition -Parent
	}
	catch
	{
		$ScriptPath = "C:\"
	}
	$scriptname = $((Get-PSCallStack -ErrorAction SilentlyContinue -Verbose:$VerbosePreference | Select-Object -First 1).Command)
	
	if (($version -eq ("Development" + "Version")) -and (-NOT (Test-Path "$ScriptPath\Functions")))
	{
		Write-Warning "Unable to continue because the script was copied from GitHub instead of downloaded from the release. Please download the latest release here: https://aka.ms/MS_AAAP"
		break
	}
	
	#region Global Functions
	. "$ScriptPath\Functions\GlobalFunctions.ps1"
	#endregion Global Functions
	
	if (-NOT (Test-Path Function:\Write-Console))
	{
		Write-Warning "Unable to continue because the script was copied from GitHub instead of downloaded from the release. Please download the latest release here: https://aka.ms/MS_AAAP"
		break
	}
	
	Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 1
	
	#region Output Path
	
<#
if (-NOT $ScriptPath) {
    $OutputFolder = "C:\MS_AAAP"
} else {
    $OutputFolder = "$ScriptPath\MS_AAAP"
}
#>
	
	# Ensure the output folder path is correctly formatted
	if ($OutputFolder.EndsWith('\') -or $OutputFolder.EndsWith('/'))
	{
		$OutputFolder = $OutputFolder.TrimEnd('\', '/') + "_$($env:computerName)\"
	}
	else
	{
		$OutputFolder += "_$($env:computerName)\"
	}
	# Check if the output folder exists
	if (Test-Path $OutputFolder -ErrorAction SilentlyContinue)
	{
		try
		{
			# Attempt to remove the folder recursively
			Remove-Item $OutputFolder -Recurse -Force -ErrorAction Stop
			Write-Verbose "Removed existing folder: $OutputFolder"
			<#
			Write-Console -MessageSegments @(
				@{ Text = "Removed existing folder: "; ForegroundColor = "DarkYellow" },
				@{ Text = $OutputFolder; ForegroundColor = "Gray" }
			)
			#>
		}
		catch
		{
			Write-Console -MessageSegments @(
				@{ Text = "Failed to remove folder: $($_.Exception.Message)"; ForegroundColor = "Red" }
			)
			try
			{
				# Remove folder contents if the full folder removal failed
				Get-ChildItem -Path "$OutputFolder*" -Recurse -Force -ErrorAction Stop |
				ForEach-Object {
					try
					{
						Remove-Item -Path $_.FullName -Recurse -Force -ErrorAction Stop
					}
					catch
					{
						Write-Console -MessageSegments @(
							@{ Text = "Failed to remove: $_"; ForegroundColor = "Red" }
						)
					}
				}
				Write-Console -MessageSegments @(
					@{ Text = "Removed existing folder contents: "; ForegroundColor = "DarkYellow" },
					@{ Text = $OutputFolder; ForegroundColor = "Gray" }
				)
			}
			catch
			{
				Write-Console -MessageSegments @(
					@{ Text = "Unable to remove folder contents: $($_.Exception.Message)"; ForegroundColor = "Red" }
				)
			}
		}
	}
	Write-Console -MessageSegments @(
		@{ Text = "Output folder: "; ForegroundColor = "Gray" },
		@{ Text = $OutputFolder; ForegroundColor = "White" }
	)
	#endregion Output Path
	
	#region Check is Administrator
	# Collect passed parameters and construct argument list
	$ScriptPassedArgs = @()
	foreach ($param in $PSBoundParameters.GetEnumerator())
	{
		$key = "-$($param.Key)"
		$value = if ($param.Value -is [bool])
		{
			# For switch parameters, include only the key if true
			if ($param.Value) { $key }
			else { "" }
		}
		else
		{
			$param.Value
		}
		if ($value)
		{
			$ScriptPassedArgs += @($key, $value)
		}
		else
		{
			$ScriptPassedArgs += $key
		}
	}
	Write-Verbose "Arguments passed to script: $ScriptPassedArgs"
	
	# Check if running as administrator
	if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
	{
		$nopermission = "Insufficient permissions to run this script. Attempting to open the PowerShell script ($ScriptPath) as administrator."
		Write-Warning $nopermission
		
		# Relaunch the script as administrator
		$command = @"
cd '$ScriptPath';
& '$ScriptPath\$scriptname' $argsString;
"@
		
		Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-NoExit", "-Command", $command -Verb RunAs
		exit
	}
	else
	{
		$permissiongranted = "Currently running as administrator - proceeding with script execution..."
		Write-Console $permissiongranted -ForegroundColor Green
		Create-Folder $OutputFolder
	}
	
	#endregion Check is Administrator
	
	$previousProgressPreferenceSetting = $Global:ProgressPreference
	
	# Set the location for the console to the output folder
	#Push-Location $OutputFolder
	
	Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 2
	
	# Development Mode Unblock (Optional) [DO NOT EDIT THE BELOW LINE]
	Write-Console -MessageSegments (@(@{ Text = "[" }, @{ Text = "DEV"; ForegroundColor = "Cyan" }, @{ Text = "] " }, @{ Text = "Attempting to run the following command to unblock the PowerShell Scripts under the current folder:`nGet-ChildItem `"$ScriptPath`" -Recurse | Unblock-File"; ForegroundColor = "Gray" })); Get-ChildItem "$ScriptPath" -Recurse | Unblock-File | Out-Null
	
	#region Variables
	$wsid = "########-####-####-####-############" # Workspace ID from Log Analytics
	$aaid = "########-####-####-####-############" # Automation ID from Automation Account
	# Map AzureLocation to short names using a switch statement
	$azureLocationShortName = switch ($AzureLocation)
	{
		'asiapacific' { 'ap' }
		'australiacentral' { 'ac' }
		'australiacentral2' { 'cbr2' }
		'australiaeast' { 'ae' }
		'australiasoutheast' { 'ase' }
		'brazilsouth' { 'brs' }
		'brazilsoutheast' { 'brse' }
		'canadaeast' { 'ce' }
		'canadacentral' { 'cc' }
		'centralindia' { 'cid' }
		'centralus' { 'cus' }
		'centralusstage' { 'cusstage' }
		'centraluseuap' { 'cus2' }
		'chinaeast2' { 'sha2' }
		'chinanorth' { 'bjb' }
		'chinanorth2' { 'bjs2' }
		'chinanorth3' { 'cnn3' }
		'eastasia' { 'ea' }
		'eastasiastage' { 'eas' }
		'eastus' { 'eus' }
		'eastus2' { 'eus2' }
		'eastus2euap' { 'eus2euap' }
		'eastus2stage' { 'eus2stage' }
		'eastusstg' { 'eusstg' }
		'europe' { 'eu' }
		'france' { 'fr' }
		'francecentral' { 'fc' }
		'francesouth' { 'mrs' }
		'germany' { 'de' }
		'germanynorth' { 'den' }
		'germanywestcentral' { 'dewc' }
		'global' { 'gl' }
		'india' { 'in' }
		'israel' { 'il' }
		'israelcentral' { 'ilc' }
		'italy' { 'it' }
		'italynorth' { 'itn' }
		'japan' { 'jp' }
		'japaneast' { 'jpe' }
		'japanwest' { 'jpw' }
		'jioindiacentral' { 'jic' }
		'jioindiawest' { 'jiw' }
		'korea' { 'kr' }
		'koreacentral' { 'kc' }
		'koreasouth' { 'ps' }
		'mexicocentral' { 'mc' }
		'newzealand' { 'nz' }
		'newzealandnorth' { 'nzn' }
		'norway' { 'no' }
		'norwayeast' { 'noe' }
		'norwaywest' { 'now' }
		'northeurope' { 'ne' }
		'northcentralus' { 'ncus' }
		'northcentralusstage' { 'ncusstg' }
		'poland' { 'pl' }
		'polandcentral' { 'plc' }
		'qatar' { 'qa' }
		'qatarcentral' { 'qac' }
		'singapore' { 'sg' }
		'southafrica' { 'za' }
		'southafricanorth' { 'san' }
		'southafricawest' { 'saw' }
		'southcentralus' { 'scus' }
		'southcentralusstg' { 'scusstg' }
		'southindia' { 'si' }
		'spaincentral' { 'es' }
		'sweden' { 'se' }
		'swedencentral' { 'sec' }
		'switzerland' { 'ch' }
		'switzerlandnorth' { 'chn' }
		'switzerlandwest' { 'chw' }
		'uaecentral' { 'auh' }
		'uaenorth' { 'uaen' }
		'uksouth' { 'uks' }
		'ukwest' { 'ukw' }
		'unitedstates' { 'us' }
		'usgov' { 'usg' }
		'usgovarizona' { 'phx' }
		'usgovtexas' { 'ussc' }
		'usgovvirginia' { 'usge' }
		'westcentralus' { 'wcus' }
		'westeurope' { 'we' }
		'westindia' { 'wi' }
		'westus' { 'wus' }
		'westus2' { 'wus2' }
		'westus3' { 'usw3' }
		'westusstage' { 'wusstg' }
		'none' { 'none' }
		default { Write-Error "Unknown Azure Location"; break }
	}
	#$azureLocationShortName = "####" # Azure region abbreviation
	#endregion Variables
	
	Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 4
	
	# Update Information
	$GetUpdateInfo = $true
	
	# Check if TLS 1.3 is supported
	if ([Enum]::GetValues([System.Security.Authentication.SslProtocols]) -contains 'Tls13')
	{
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls13
	}
	else
	{
		[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
	}
	Write-Verbose "Using highest SSL Security Protocol available [Net.ServicePointManager]::SecurityProtocol: $([Net.ServicePointManager]::SecurityProtocol)"
	
	# Validate Location
	if ($azureLocationShortName.Length -gt 4)
	{
		Write-Verbose -Verbose "$azureLocationShortName is WRONG. Please update to an abbreviated region name and re-run the script."
		Write-Verbose -Verbose "Refer to: https://learn.microsoft.com/en-us/azure/automation/how-to/automation-region-dns-records#support-for-private-link"
		Break
	}
	
	Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 5
	
}
PROCESS
{
	Write-Console -Text "==========================================================" -NoTimestamp
	Write-Console -Text "Starting data collection (v$version) on: $env:COMPUTERNAME" -ForegroundColor 'DarkCyan'
	
	
	#region Who is running the script?
	$runningas = $null
	$runningas = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
	# Write-Console will output the user running the script to the (script-log.log) file in the output folder
	Write-Console "Script currently running as: " -ForegroundColor DarkGray -NoNewLine
	Write-Console $runningas -ForegroundColor Gray -NoTimestamp
	#endregion Who is running the script?
	
	Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 13
	
	#region OS Misc Data
	Write-Console "Gathering OS Miscellaneous data" -ForegroundColor Cyan
	. "$ScriptPath\Functions\Get-OSMiscData.ps1"
	#endregion OS Misc Data
	
	Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 14
	
	#region Gathering User Rights
	Write-Console "Gathering local user rights" -ForegroundColor Cyan
	. "$ScriptPath\Functions\Get-UserRights.ps1"
	Get-UserRights
	#endregion Gathering User Rights
	
	Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 15
	
	#region Azure Machine Details
	$azureVM = "$OutputFolder`AzureVM\"
	
	#region Get VM Metadata
	Write-Console -Text "Attempting to gather Azure VM compute metadata" -ForegroundColor Cyan
	
	# Metadata Request Headers
	$headers = @{ "Metadata" = "true" }
	$versionsEndpoint = "http://169.254.169.254/metadata/versions"
	
	# Initialize Metadata Variables
	$computeMetadata = $null
	$latestApiAvailable = $null
	
	try
	{
		$response = Invoke-RestMethod -Verbose:$VerbosePreference -Uri $versionsEndpoint -Headers $headers -TimeoutSec 5 -ErrorAction SilentlyContinue
		if ($null -ne $response)
		{
			$latestApiAvailable = $response.apiVersions | Select-Object -Last 1
		}
	}
	catch
	{
		# Suppress errors
	}
	
	Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 16
	
	if ($null -ne $latestApiAvailable)
	{
		$metadataUrl = "http://169.254.169.254/metadata/instance/compute?api-version=$latestApiAvailable"
		$invokeParams = @{
			Uri		    = $metadataUrl
			Headers	    = $headers
			TimeoutSec  = 1
			ErrorAction = 'SilentlyContinue'
			Verbose	    = $VerbosePreference
		}
		if ($PSVersionTable.PSVersion -ge [Version]"6.0")
		{
			$invokeParams.NoProxy = $true
		}
		try
		{
			$computeMetadata = Invoke-RestMethod @invokeParams
		}
		catch
		{
			# Suppress errors
		}
	}
	
	if ($null -ne $computeMetadata -and $null -ne $computeMetadata.resourceId)
	{
		Write-Console -MessageSegments @(
			New-MessageSegment -Text "Successfully retrieved compute metadata: " -ForegroundColor Green
			New-MessageSegment -Text "VM Name: " -ForegroundColor Gray
			New-MessageSegment -Text $computeMetadata.name -ForegroundColor Cyan
			New-MessageSegment -Text " / Resource ID: " -ForegroundColor Gray
			New-MessageSegment -Text $computeMetadata.resourceId -ForegroundColor Cyan
		)
		Create-Folder $azureVM
		# Save Metadata to JSON
		$computeMetadata | ConvertTo-Json -Depth 64 | Out-FileWithErrorHandling -FilePath "$azureVM\vm_metadata.json" -Width 4096 -Force
	}
	else
	{
		Write-Console -Text "Either this is not an Azure VM, or the script is unable to gather data from the Azure VM compute metadata service." -ForegroundColor Gray
	}
	#endregion Get VM Metadata
	
	Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 17
	
	#region Collecting Windows Azure Logs
	if (Test-Path "C:\WindowsAzure\Logs")
	{
		Write-Verbose "Found path for C:\WindowsAzure\Logs"
		Create-Folder "$azureVM`WindowsAzure\Logs\"
		
		Get-CustomChildItem "C:\WindowsAzure\Logs" -Recurse | Out-FileWithErrorHandling -Force -FilePath "$azureVM\WindowsAzure\Logs\Logs-Directory-listing.txt"
		
		@(
			"C:\WindowsAzure\Logs\Plugins\Microsoft.Azure.Automation.HybridWorker.HybridWorkerForWindows",
			"C:\WindowsAzure\Logs\Plugins\Microsoft.CPlat.Core.WindowsPatchExtension",
			"C:\WindowsAzure\Logs\Plugins\Microsoft.GuestConfiguration.ConfigurationforWindows",
			"C:\WindowsAzure\Logs\Plugins\Microsoft.Powershell.DSC",
			"C:\WindowsAzure\Logs\WaAppAgent.log",
			"C:\WindowsAzure\Logs\TransparentInstaller.log"
		) | ForEach-Object {
			$sourcePath = $_
			if (Test-Path $sourcePath)
			{
				$destinationPath = "$azureVM$($sourcePath.Replace('C:', ''))"
				Copy-File -SourcePath $sourcePath -DestinationFolder $destinationPath -Quiet
			}
			else
			{
				Write-Verbose "Path not found: $sourcePath"
			}
		}
	}
	else
	{
		Write-Verbose "Did not find path for: C:\WindowsAzure\Logs"
	}
	#endregion Collecting Windows Azure Logs
	#endregion Azure Machine Details
	
	Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 19
	if (-NOT $SkipNetworkConnectivityCheck)
	{
		#region Other Endpoint Connectivity Tests
		. "$ScriptPath\Functions\Start-EndpointConnectivityTests.ps1"
		#endregion Other Endpoint Connectivity Tests
	}
	Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 20
	
	#region Gather Hybrid Worker data
	. "$ScriptPath\Functions\Get-HybridWorkerData.ps1"
	#endregion Gather Hybrid Worker data
	
	Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 22
	
	#region Gathering Event Logs
	. "$ScriptPath\Functions\Get-EventLogs.ps1"
	$eventLogFolder = "$OutputFolder`EventLogs\"
	Get-EventLogs -OutputPath $eventLogFolder
	#endregion Gathering Event Logs
	
	Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 24
	
	#region Proxy Information
	$ProxyFolder = "$OutputFolder`Network\ProxySettings\"
	Create-Folder $ProxyFolder
	$OutputFile = "$ProxyFolder\Win-HTTP-Proxy.txt"
	netsh Winhttp show proxy *> $OutputFile
	"Note Proxy can be set through DHCP Option 252 see $($NetworkFolder + "DHCP-Options.txt") for more details" > "$ProxyFolder\DHCP-Proxy.txt"
	#endregion Proxy Information
	
	Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 30
	
	#region Proxy Registry Information
	Write-Console -MessageSegments @(
		@{ Text = "Gathering Proxy information"; ForegroundColor = "Cyan" }
	)
	New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS | Out-Null
	REG LOAD HKU\UserHive "C:\Users\Default\NTUSER.DAT" *> $null
	
	$RegoutputFile = "$ProxyFolder\REG-System-ProxyInfo.txt"
	if (Test-Path "HKU:\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings")
	{
		REG EXPORT "HKU\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings" $RegoutputFile /y *> $null
	}
	else
	{
		"'HKU:\S-1-5-18\Software\Microsoft\Windows\CurrentVersion\Internet Settings' Not present" > $RegoutputFile
	}
	REG UNLOAD HKU\UserHive *> $null
	Remove-PSDrive -Name HKU
	
	Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 29
	
	$RegoutputFile = "$ProxyFolder\REG-HKLM-ProxyInfo.txt"
	if (Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings")
	{
		REG EXPORT "HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" $RegoutputFile /y *> $null
	}
	else
	{
		"'HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' Not present" > $RegoutputFile
	}
	
	Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 28
	
	$RegoutputFile = "$ProxyFolder\REG-HKCU-ProxyInfo.txt"
	if (Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings")
	{
		REG EXPORT "HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" $RegoutputFile /y *> $null
	}
	else
	{
		"'HKCU\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings' Not present" > $RegoutputFile
	}
	#endregion Proxy Registry Information
	
	Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 31
	
	#region SCHANNEL Registry
	$RegoutputFile = "$NetworkFolder\REG-SCHANNEL.txt"
	if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL")
	{
		REG EXPORT "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" $RegoutputFile /y *> $null
	}
	else
	{
		"'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' Not present" > $RegoutputFile
	}
	#endregion SCHANNEL Registry
	
	Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 37
	
	#region TLS Miscellaneous Registry
	$RegoutputFile = "$NetworkFolder\REG-TLS-Misc.txt"
	$Msg = $null
	
	# Check SchUseStrongCrypto in .NET Framework v4.0.30319
	$regpath = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NetFramework\v4.0.30319'
	$return = (Get-ItemProperty -Path $regpath).SchUseStrongCrypto
	if (!($return))
	{
		$Msg += $CRLF + "$regpath\SchUseStrongCrypto is NotPresent (setting a value of 1 may help)"
	}
	else
	{
		$Msg += $CRLF + "$regpath\SchUseStrongCrypto = $return"
	}
	
	Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 34
	
	# Check SchUseStrongCrypto in .NET Framework v4.0.30319 (Non-Wow6432)
	$regpath = 'HKLM:\SOFTWARE\Microsoft\.NetFramework\v4.0.30319'
	$return = (Get-ItemProperty -Path $regpath).SchUseStrongCrypto
	if (!($return))
	{
		$Msg += $CRLF + "$regpath\SchUseStrongCrypto is NotPresent (setting a value of 1 may help)"
	}
	else
	{
		$Msg += $CRLF + "$regpath\SchUseStrongCrypto = $return"
	}
	
	Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 35
	
	# Check DisableRenegoOnClient in SCHANNEL
	$regpath = 'HKLM:\system\CurrentControlSet\Control\SecurityProviders\SCHANNEL'
	$return = (Get-ItemProperty -Path $regpath).DisableRenegoOnClient
	if ($return -eq 1)
	{
		$Msg += $CRLF + "!!! WARNING !!! $regpath\DisableRenegoOnClient=1 is present, this key is known to cause problems"
	}
	
	$Msg > $RegoutputFile
	#endregion TLS Miscellaneous Registry
	
	Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 38
	
	#region Guest Configuration Data
	Write-Console "Gathering Guest Configuration data" -ForegroundColor Cyan
	. "$ScriptPath\Functions\Get-GuestConfigurationData.ps1"
	#endregion Guest Configuration Data
	
	Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 40
	
	#region Arc Data and azcmagent Logs
	Write-Console "Gathering Azure Arc data" -ForegroundColor Cyan
	. "$ScriptPath\Functions\Get-AzureArcData.ps1"
	#endregion Arc Data and azcmagent Logs
	
	Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 42
	
	#region Installed Updates Information
	. "$ScriptPath\Functions\Get-WindowsUpdateData.ps1"
	#endregion Installed Updates Information
	
	Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 55
	
	#region Collecting Hosts File
	Copy-File "C:\Windows\System32\drivers\etc\hosts" "$NetworkFolder\hosts.txt"
	#endregion Collecting Hosts File
	
	Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 58
	
	#region IP Configuration
	ipconfig.exe /all | Out-FileWithErrorHandling -Force -FilePath "$NetworkFolder\ipconfig.txt"
	#endregion IP Configuration
	
	Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 62
	
	#region DHCP Options
	$OutputDHCPOptions = "$NetworkFolder\DHCP-Options.txt"
	# "DHCP Message Type 53 values" from IANA
	$DhcpMessageType53Values = @(
		"", "DHCPDISCOVER", "DHCPOFFER", "DHCPREQUEST", "DHCPDECLINE", "DHCPACK",
		"DHCPNAK", "DHCPRELEASE", "DHCPINFORM", "DHCPFORCERENEW", "DHCPLEASEQUERY",
		"DHCPLEASEUNASSIGNED", "DHCPLEASEUNKNOWN", "DHCPLEASEACTIVE",
		"DHCPBULKLEASEQUERY", "DHCPLEASEQUERYDONE"
	)
	
	$objWin32NAC = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Namespace "root\CIMV2" -Filter "IPEnabled = 'True' AND DHCPEnabled ='True'"
	"If present display network Adapters using Get-CimInstance -Class Win32_NetworkAdapterConfiguration that have IPEnabled=True and DHCPEnabled=true"  >> $OutputDHCPOptions
	""  >> $OutputDHCPOptions
	
	Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 60
	
	foreach ($objNACItem in $objWin32NAC)
	{
		Write-Console -MessageSegments @(
			@{ Text = "Reading DHCP options of NIC: "; ForegroundColor = 'Cyan' },
			@{ Text = $objNACItem.Caption }
		)
		"Reading DHCP options of NIC: " + $objNACItem.Caption  >> $OutputDHCPOptions
		"  IP address : " + ((Get-ItemProperty -ErrorAction Stop -Path ("HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{0}" -f $objNACItem.SettingID) -Name DhcpIPAddress).DhcpIPAddress)  >> $OutputDHCPOptions
		"  DHCP server: " + ((Get-ItemProperty -ErrorAction Stop -Path ("HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{0}" -f $objNACItem.SettingID) -Name DhcpServer).DhcpServer)  >> $OutputDHCPOptions
		"  Options    : "   >> $OutputDHCPOptions
		
		# Read DHCP Options
		try
		{
			$DhcpInterfaceOptions = (Get-ItemProperty -ErrorAction Stop -Path ("HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters\Interfaces\{0}" -f $objNACItem.SettingID) -Name DhcpInterfaceOptions).DhcpInterfaceOptions
			$DhcpOptions = @(); for ($i = 0; $i -lt 256; $i++) { $DhcpOptions += @("") }
			$DhcpVendorSpecificOptions = @(); for ($i = 0; $i -lt 256; $i++) { $DhcpVendorSpecificOptions += @("") }
			
			# Iterate through DHCP options
			$intPosition = 0
			while ($intPosition -lt $DhcpInterfaceOptions.Length)
			{
				$DhcpOptionCode = $DhcpInterfaceOptions[$intPosition]
				$intPosition += 8 # Shift 8 bytes
				$DhcpOptionLength = $DhcpInterfaceOptions[$intPosition]
				$intPosition += 4 # Shift 4 bytes
				$DhcpIsVendorSpecific = $DhcpInterfaceOptions[$intPosition]
				$intPosition += 4 # Shift 4 bytes
				$DhcpUnknownData = ""
				for ($i = 0; $i -lt 4; $i++)
				{
					$DhcpUnknownData += $DhcpInterfaceOptions[$intPosition + $i]
				}
				$intPosition += 4 # Shift 4 bytes
				
				# Determine bytes to read
				if (($DhcpOptionLength % 4) -eq 0)
				{
					$DhcpOptionBytesToRead = ($DhcpOptionLength - ($DhcpOptionLength % 4))
				}
				else
				{
					$DhcpOptionBytesToRead = ($DhcpOptionLength - ($DhcpOptionLength % 4) + 4)
				}
				$DhcpOptionValue = New-Object Byte[] $DhcpOptionBytesToRead
				for ($i = 0; $i -lt $DhcpOptionLength; $i++)
				{
					$DhcpOptionValue[$i] = $DhcpInterfaceOptions[$intPosition + $i]
				}
				$intPosition += $DhcpOptionBytesToRead # Shift bytes read
				
				# Assign option values
				if ($DhcpIsVendorSpecific -eq 0)
				{
					$DhcpOptions[$DhcpOptionCode] = $DhcpOptionValue
				}
				else
				{
					$DhcpVendorSpecificOptions[$DhcpOptionCode] = $DhcpOptionValue
				}
			}
			
			# Display DHCP Options
			for ($i = 0; $i -lt 256; $i++)
			{
				if ($i -ne 43)
				{
					$DhcpOptionIndex = $i
					$DhcpOptionValue = $DhcpOptions[$DhcpOptionIndex]
					
					if ($DhcpOptionValue)
					{
						$dhcpOptionName = ($dhcpOptionDetails | Where-Object { $_.Code -eq $DhcpOptionIndex }).Name
						if (-not [string]::IsNullOrEmpty($dhcpOptionName))
						{
							$dhcpOptionName = (" ({ 0 })" -f $dhcpOptionName)
						}
						$dhcpOptionType = ($dhcpOptionDetails | Where-Object { $_.Code -eq $DhcpOptionIndex }).Type
						if ([string]::IsNullOrEmpty($dhcpOptionType))
						{
							$dhcpOptionType = "unknown"
						}
						
						switch ($dhcpOptionType.ToLower())
						{
							"ip"          {
								"  - $DhcpOptionIndex $dhcpOptionName : $($DhcpOptionValue[0]).$($DhcpOptionValue[1]).$($DhcpOptionValue[2]).$($DhcpOptionValue[3]).$($DhcpOptionValue[4])." >> $OutputDHCPOptions
							}
							"string"      {
								"  - $DhcpOptionIndex $dhcpOptionName : $(Convert-ByteArrayToString $DhcpOptionValue)" >> $OutputDHCPOptions
							}
							"time"        {
								"  - $DhcpOptionIndex $dhcpOptionName : $([Convert]::ToInt32(($DhcpOptionValue[0].ToString("X2") + $DhcpOptionValue[1].ToString("X2") + $DhcpOptionValue[2].ToString("X2") + $DhcpOptionValue[3].ToString("X2")), 16)) seconds" >> $OutputDHCPOptions
							}
							"dhcpmsgtype" {
								"  - $DhcpOptionIndex $dhcpOptionName : $($DhcpOptionValue[0]) $($DhcpMessageType53Values[$DhcpOptionValue[0]])" >> $OutputDHCPOptions
							}
							default       {
								"  - $DhcpOptionIndex $dhcpOptionName : " + ($DhcpOptionValue | ForEach-Object { $_.ToString("X2") })  >> $OutputDHCPOptions
							}
						}
					}
				}
				else
				{
					"  - $i (vendor specific)"   >> $OutputDHCPOptions
					for ($j = 0; $j -lt 256; $j++)
					{
						$DhcpOptionIndex = $j
						$DhcpOptionValue = $DhcpVendorSpecificOptions[$DhcpOptionIndex]
						
						if ($DhcpOptionValue)
						{
							$dhcpOptionName = ($dhcpOptionVSDetails | Where-Object { $_.Code -eq $DhcpOptionIndex }).Name
							if (-not [string]::IsNullOrEmpty($dhcpOptionName))
							{
								$dhcpOptionName = (" ({ 0 })" -f $dhcpOptionName)
							}
							$dhcpOptionType = ($dhcpOptionVSDetails | Where-Object { $_.Code -eq $DhcpOptionIndex }).Type
							if ([string]::IsNullOrEmpty($dhcpOptionType))
							{
								$dhcpOptionType = "unknown"
							}
							"$DhcpOptionIndex $dhcpOptionName" >> $OutputDHCPOptions
							switch ($dhcpOptionType.ToLower())
							{
								"ip"          {
									"  - $DhcpOptionIndex (vendor specific) : $($DhcpOptionValue[0]).$($DhcpOptionValue[1]).$($DhcpOptionValue[2]).$($DhcpOptionValue[3]).$($DhcpOptionValue[4])." >> $OutputDHCPOptions
								}
								"string"      {
									"  - $DhcpOptionIndex (vendor specific) : $(Convert-ByteArrayToString $DhcpOptionValue)" >> $OutputDHCPOptions
								}
								"time"        {
									"  - $DhcpOptionIndex (vendor specific) : $([Convert]::ToInt32(($DhcpOptionValue[0].ToString("X2") + $DhcpOptionValue[1].ToString("X2") + $DhcpOptionValue[2].ToString("X2") + $DhcpOptionValue[3].ToString("X2")), 16)) seconds" >> $OutputDHCPOptions
								}
								"dhcpmsgtype" {
									"  - $DhcpOptionIndex (vendor specific) : $($DhcpOptionValue[0]) $($DhcpMessageType53Values[$DhcpOptionValue[0]])" >> $OutputDHCPOptions
								}
								default       {
									"  - $DhcpOptionIndex (vendor specific) : " + ($DhcpOptionValue | ForEach-Object { $_.ToString("X2") })  >> $OutputDHCPOptions
								}
							}
						}
					}
				}
			}
		}
		catch
		{
			Write-Console -Text "Error retrieving DHCP data: $_" -ForegroundColor Red
		}
	}
	#endregion DHCP Options
	
	Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 80
	
	#region Packages
	#region Packages Directory Listing
	if (Test-Path "C:\Packages")
	{
		if ($OutputFolder -ne "" -and (Test-Path "$OutputFolder`Packages"))
		{
			try
			{
				Remove-Item "$OutputFolder`Packages" -Recurse -Force -ErrorAction Stop
			}
			catch [System.IO.IOException]
			{
				if ($_.Exception.Message -like "*because it is being used by another process*")
				{
					Write-Warning "Cannot remove item $OutputFolder`Packages: The process cannot access the file because it is being used by another process."
					
					# Find processes locking the files
					$lockingProcesses = Get-LockingProcess -Path "$OutputFolder`Packages"
					
					if ($lockingProcesses)
					{
						Write-Console -MessageSegments @(
							@{ Text = "The following processes are locking files in the folder: " },
							@{ Text = $($lockingProcesses | Format-Table -AutoSize); ForegroundColor = 'Yellow' }
						)
						
						
						# Ask user if they want to terminate the processes
						$response = Read-Host "Do you want to close these processes to continue? (Y/N)"
						do { $response = Read-Host "Do you want to close these processes to continue? (Y/N)" }
						until ($response -match '^[Yy]')
						if ($response -match '^[Yy]')
						{
							foreach ($proc in $lockingProcesses)
							{
								try
								{
									Stop-Process -Id $proc.ProcessId -Force
									Write-Host "Terminated process $($proc.ProcessName) (PID: $($proc.ProcessId))"
								}
								catch
								{
									Write-Warning "Failed to terminate process $($proc.ProcessName) (PID: $($proc.ProcessId)): $_"
								}
							}
							
							# Retry removing the item
							Remove-Item "$OutputFolder`Packages" -Recurse -Force
						}
						else
						{
							Write-Warning "Cannot proceed without removing $OutputFolder`Packages. Exiting."
							break
						}
					}
					else
					{
						Write-Warning "No locking processes found. Exiting."
						exit
					}
				}
				else
				{
					throw
				}
			}
		}
		Create-Folder "$OutputFolder`Packages\"
		Get-CustomChildItem "C:\Packages" -Recurse | Out-FileWithErrorHandling -Force -FilePath "$OutputFolder`Packages\Packages-Directory-listing.txt"
	}
	#endregion Packages Directory Listing
	
	Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 74
	
	#region Gather Packages
	# ================================================================================================
	. "$ScriptPath\Functions\Get-Packages.ps1"
	#endregion Gather Packages
	#endregion Packages
}
END
{
	#region Zip output folder / Wrap up
	#Zip output
	$Error.Clear()
	Write-Console "Creating zip file of all output data." -ForegroundColor DarkCyan
	[Reflection.Assembly]::LoadWithPartialName("System.IO.Compression.FileSystem") | Out-Null
	[System.AppDomain]::CurrentDomain.GetAssemblies() | Out-Null
	$SourcePath = Resolve-Path $OutputFolder
	$FolderName = Split-Path $OutputFolder -Leaf
	
	Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 90
	
	[string]$filedate = (Get-Date).ToString("MMMdd").ToLower()
	[string]$destfilename = "$FolderName`_$filedate`.zip"
	
	#[string]$destfile = "$ScriptPath\$destfilename"
	[string]$destfile = "C:\$destfilename"
	IF (Test-Path $destfile)
	{
		#File exists from a previous run on the same day - delete it
		Write-Console "Found existing zip file: $destfile.`n Deleting existing file." -ForegroundColor DarkGreen
		Remove-Item $destfile -Force
	}
	Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 95
	$compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
	$includebasedir = $false
	try
	{
		[System.IO.Compression.ZipFile]::CreateFromDirectory($SourcePath, $destfile, $compressionLevel, $includebasedir) | Out-Null
	}
	catch
	{
		Write-Console -Text $_ -ForegroundColor Red
	}
	IF ($Error)
	{
		Write-Error "Error creating zip file."
	}
	ELSE
	{
		Write-Console -MessageSegments @(
			@{ Text = "Saved zip file to: '"; ForegroundColor = "DarkCyan" }
			@{ Text = $destfile; ForegroundColor = "Cyan" }
			@{ Text = "'"; ForegroundColor = "DarkCyan" }
		)
		#Write-Console "--Cleaning up output directory." -ForegroundColor DarkCyan
		#Remove-Item $OutputFolder -Recurse
	}
	
	Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 98
	
	# Open Output Folder in Explorer
	Start-Process "explorer.exe" -ArgumentList "$OutputFolder" -Verb RunAs
	
	Write-ScriptProgress -Activity 'Gathering data' -PercentComplete 100 -Completed
	#endregion Zip everything up / Wrap up
	#Stop-Transcript
}
# Destination base folder
$GuestConfigPath = "$outputFolder`GuestConfig"
if (Test-Path "C:\ProgramData\GuestConfig")
{
	Create-Folder $GuestConfigPath
	Get-CustomChildItem "C:\ProgramData\GuestConfig" -Recurse | Out-FileWithErrorHandling -Force -FilePath "$GuestConfigPath\GuestConfig-Directory-listing.txt"
	
	Copy-File -SourcePath "C:\ProgramData\GuestConfig\gc_agent_logs" -DestinationFolder "$GuestConfigPath"
}

# Paths to process
$SourcePaths = @(
	"C:\ProgramData\GuestConfig\extension_logs\Microsoft.Azure.Automation.HybridWorker.HybridWorkerForWindows",
	"C:\ProgramData\GuestConfig\extension_logs\Microsoft.Azure.OpenSSH.WindowsOpenSSH",
	"C:\ProgramData\GuestConfig\extension_logs\Microsoft.CPlat.Core.WindowsPatchExtension",
	"C:\ProgramData\GuestConfig\extension_logs\Microsoft.SoftwareUpdateManagement.WindowsOsUpdateExtension"
)

# Calculate the date 3 months ago from today
$DateLimit = (Get-Date).AddMonths(-3)

# Process each source path
foreach ($SourcePath in $SourcePaths)
{
	if (Test-Path $SourcePath)
	{
		# Get base extension folder name
		$ExtensionName = Split-Path $SourcePath -Leaf
		$ExtensionFolder = "$GuestConfigPath\extension_logs\$ExtensionName"
		Create-Folder -path $ExtensionFolder
		
		# Get all items (files and folders) recursively
		Get-ChildItem $SourcePath -Recurse | Where-Object { $_.LastWriteTime -gt $DateLimit } | ForEach-Object {
			if ($_.PSIsContainer)
			{
				# For directories, create the corresponding folder in destination
				$RelativePath = $_.FullName.Substring($SourcePath.Length).TrimStart('\')
				$DestPath = Join-Path $ExtensionFolder $RelativePath
				Create-Folder -path $DestPath
			}
			else
			{
				# For files, get the destination directory and copy the file there
				$RelativePath = $_.Directory.FullName.Substring($SourcePath.Length).TrimStart('\')
				$DestDir = Join-Path $ExtensionFolder $RelativePath
				Create-Folder -path $DestDir
				Copy-File -SourcePath $_.FullName -DestinationFolder $DestDir -Quiet
			}
		}
	}
	else
	{
		Write-Console -Text "Source path not found: $SourcePath" -ForegroundColor Gray
	}
}

# Get Extension Manager Logs
$arcpolicyLogsPath = 'C:\ProgramData\GuestConfig\arc_policy_logs'
if (Test-Path "$arcpolicyLogsPath")
{
	$arcPolicyLogsFolder = "$GuestConfigPath\arc_policy_logs"
	Create-Folder -path $arcPolicyLogsFolder
	
	Write-Console -MessageSegments @(
		@{ Text = "Copying "; ForegroundColor = "Green" },
		@{ Text = "(most recent)"; ForegroundColor = "Gray" },
		@{ Text = " files from: "; ForegroundColor = 'Green' }
		@{ Text = "$extMgrLogsPath"; ForegroundColor = 'DarkCyan' }
		@{ Text = " -> "; }
		@{ Text = $arcPolicyLogsFolder; ForegroundColor = 'DarkCyan' }
	)
	
	Copy-File -SourcePath $arcpolicyLogsPath -DestinationFolder $arcPolicyLogsFolder -Quiet
}

# Get Extension Manager Logs
$extMgrLogsPath = 'C:\ProgramData\GuestConfig\ext_mgr_logs'
if (Test-Path "$extMgrLogsPath")
{
	$ExtMgrLogsFolder = "$GuestConfigPath\ext_mgr_logs"
	Create-Folder -path $ExtMgrLogsFolder
	
	Write-Console -MessageSegments @(
		@{ Text = "Copying "; ForegroundColor = "Green" },
		@{ Text = "(most recent)"; ForegroundColor = "Gray" },
		@{ Text = " files from: "; ForegroundColor = 'Green' }
		@{ Text = "$extMgrLogsPath"; ForegroundColor = 'DarkCyan' }
		@{ Text = " -> "; }
		@{ Text = $ExtMgrLogsFolder; ForegroundColor = 'DarkCyan' }
	)
	
	
	@(
		"gc_ext.log", "gc_ext.1.log", "gc_ext.2.log", "gc_ext.3.log",
		"gc_agent.json", "gc_ext_telemetry.txt", "gc_ext_telemetry.1.txt",
		"gc_ext_telemetry.2.txt", "gc_ext_telemetry.3.txt", "restart_ExtensionService.log"
	) | ForEach-Object {
		$sourcePath = "$extMgrLogsPath\$_"
		if (Test-Path $sourcePath)
		{
			Copy-File -SourcePath $sourcePath -DestinationFolder $ExtMgrLogsFolder -Quiet
		}
	}
}

# Get Extension Reports
if (Test-Path "C:\ProgramData\GuestConfig\extension_reports")
{
	$ExtensionReports = "$GuestConfigPath\extension_reports"
	Create-Folder -path $ExtensionReports
	
	# Create destination directory and copy files
	Get-ChildItem "C:\ProgramData\GuestConfig\extension_reports" -Recurse | ForEach-Object {
		if ($_.PSIsContainer)
		{
			$RelativePath = $_.FullName.Substring("C:\ProgramData\GuestConfig\extension_reports".Length).TrimStart('\')
			$DestPath = Join-Path $ExtensionReports $RelativePath
			Create-Folder -path $DestPath
		}
		else
		{
			$RelativePath = $_.Directory.FullName.Substring("C:\ProgramData\GuestConfig\extension_reports".Length).TrimStart('\')
			$DestDir = Join-Path $ExtensionReports $RelativePath
			Create-Folder -path $DestDir
			Copy-File -SourcePath $_.FullName -DestinationFolder $DestDir -Quiet
		}
	}
	
	$WindowsOsUpdateExtension_report_File = "$ExtensionReports\WindowsOsUpdateExtension_report.txt"
	$WindowsOsUpdateExtension_report_Friendly = "$ExtensionReports\WindowsOsUpdateExtension_report_Friendly.txt"
	
	if (Test-Path $WindowsOsUpdateExtension_report_File)
	{
		$WindowsOsUpdateExtension_report = Get-Content $WindowsOsUpdateExtension_report_File | ConvertFrom-Json
		# [Rest of report processing remains the same]
	}
}

# Get Configuration Data
if (Test-Path "C:\ProgramData\GuestConfig\Configuration")
{
	$GCconfiguration = "$GuestConfigPath\Configuration"
	Create-Folder -path $GCconfiguration
	
	# Create destination directory and copy files
	Get-ChildItem "C:\ProgramData\GuestConfig\Configuration" -Recurse | ForEach-Object {
		if ($_.PSIsContainer)
		{
			$RelativePath = $_.FullName.Substring("C:\ProgramData\GuestConfig\Configuration".Length).TrimStart('\')
			$DestPath = Join-Path $GCconfiguration $RelativePath
			Create-Folder -path $DestPath
		}
		else
		{
			$RelativePath = $_.Directory.FullName.Substring("C:\ProgramData\GuestConfig\Configuration".Length).TrimStart('\')
			$DestDir = Join-Path $GCconfiguration $RelativePath
			Create-Folder -path $DestDir
			Copy-File -SourcePath $_.FullName -DestinationFolder $DestDir -Quiet
		}
	}
}
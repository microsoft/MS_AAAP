#region Hybrid Worker Connectivity Tests
Write-Verbose "Starting Hybrid Worker Connectivity Tests"

$jrdsArr = @()
$regpath = "HKLM:\SOFTWARE\Microsoft\HybridRunbookWorker"
$CheckSSLPath = "$NetworkFolder\CheckSSL.txt"
$CheckSSLSummaryPath = "$NetworkFolder\CheckSSL_Summary.txt"

Write-Verbose "Checking registry path: $regpath"
If (Test-Path $regpath)
{
	Write-Verbose "Registry path exists: $regpath"
	Get-ChildItem -Path $regpath -Recurse | ForEach-Object {
		$props = Get-ItemProperty -Path $_.PSPath
		Write-Verbose "Processing registry key: $($_.PSPath)"
		if ($props.JobRuntimeDataServiceUri)
		{
			Write-Verbose "Found JobRuntimeDataServiceUri: $($props.JobRuntimeDataServiceUri)"
			$jrdsArr += $props.JobRuntimeDataServiceUri
		}
		else
		{
			Write-Verbose "JobRuntimeDataServiceUri not found in $($_.PSPath)"
		}
	}
}
else
{
	Write-Verbose "Registry path does not exist: $regpath"
}

$regpath = "HKLM:\SOFTWARE\Microsoft\HybridRunbookWorkerV2"
Write-Verbose "Checking registry path: $regpath"
If (Test-Path $regpath)
{
	Write-Verbose "Registry path exists: $regpath"
	Get-ChildItem -Path $regpath -Recurse | ForEach-Object {
		$props = Get-ItemProperty -Path $_.PSPath
		Write-Verbose "Processing registry key: $($_.PSPath)"
		if ($props.JobRuntimeDataServiceUri)
		{
			Write-Verbose "Found JobRuntimeDataServiceUri: $($props.JobRuntimeDataServiceUri)"
			$jrdsArr += $props.JobRuntimeDataServiceUri
		}
		else
		{
			Write-Verbose "JobRuntimeDataServiceUri not found in $($_.PSPath)"
		}
	}
}
else
{
	Write-Verbose "Registry path does not exist: $regpath"
}

Write-Verbose "Original jrdsArr contents:"
$jrdsArr | ForEach-Object { Write-Verbose " - $_" }

# Remove 'https://' from the URIs
$jrdsArr = $jrdsArr -replace 'https://', ''
Write-Verbose "jrdsArr after removing 'https://':"
$jrdsArr | ForEach-Object { Write-Verbose " - $_" }

# Sort and remove duplicates and empty entries
$jrdsArr = $jrdsArr | Sort-Object -Unique | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
Write-Verbose "jrdsArr after sorting and filtering:"
$jrdsArr | ForEach-Object { Write-Verbose " - $_" }

$aaidArr = @()

foreach ($endpoint in $jrdsArr)
{
	Write-Verbose "Processing endpoint: $endpoint"
	if ([string]::IsNullOrWhiteSpace($endpoint))
	{
		Write-Verbose "Endpoint is null or whitespace, skipping."
		continue
	}
	
	Write-Verbose "Endpoint length: $($endpoint.Length)"
	if ($endpoint.Length -gt 63)
	{
		Write-Verbose "Endpoint length greater than 63 characters."
		$endpointParts = $endpoint.Split(".")
		Write-Verbose "Endpoint parts: $($endpointParts -join ', ')"
		if ($endpointParts.Length -ge 3)
		{
			$EndpointAaid = $endpointParts[0]
			$EndpointLocation = $endpointParts[2]
			Write-Verbose "EndpointAaid: $EndpointAaid"
			Write-Verbose "EndpointLocation: $EndpointLocation"
			if ($EndpointAaid -and $EndpointLocation)
			{
				$FQDNs = @(
					"$EndpointAaid.jrds.$EndpointLocation.azure-automation.net",
					"$EndpointAaid.agentsvc.$EndpointLocation.azure-automation.net",
					"$EndpointAaid.webhook.$EndpointLocation.azure-automation.net",
					"$EndpointLocation-jobruntimedata-prod-su1.azure-automation.net"
				) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
				
				Write-Verbose "Constructed FQDNs:"
				$FQDNs | ForEach-Object { Write-Verbose " - $_" }
				
				if ($FQDNs.Count -gt 0)
				{
					Write-Verbose "Calling Test-SSLConfiguration with FQDNs: $($FQDNs -join ', ')"
					Test-SSLConfiguration -FQDNs $FQDNs -SummaryOutputFile $CheckSSLSummaryPath | Out-File -FilePath $CheckSSLPath -Append -Force
				}
			}
			else
			{
				Write-Verbose "EndpointAaid or EndpointLocation is null or empty."
			}
		}
		else
		{
			Write-Output "Warning: Endpoint '$endpoint' does not have enough segments."
		}
	}
	else
	{
		Write-Verbose "Endpoint length less than or equal to 63 characters."
		Write-Verbose "Calling Test-SSLConfiguration with endpoint: $endpoint"
		Test-SSLConfiguration -FQDNs $endpoint -SummaryOutputFile $CheckSSLSummaryPath | Out-File -FilePath $CheckSSLPath -Append
	}
}

# Ensure $aaid and $AzureLocation are defined
if ($aaid -and $AzureLocation -and ($aaid -notlike "none") -and ($aaid -notin $jrdsArr))
{
	Write-Verbose "Processing aaid and location: $aaid, $AzureLocation"
	$FQDNs = @(
		"$aaid.jrds.$AzureLocation.azure-automation.net",
		"$aaid.agentsvc.$AzureLocation.azure-automation.net",
		"$aaid.webhook.$AzureLocation.azure-automation.net",
		"$AzureLocation-jobruntimedata-prod-su1.azure-automation.net"
	) | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
	
	Write-Verbose "Constructed FQDNs:"
	$FQDNs | ForEach-Object { Write-Verbose " - $_" }
	
	if ($FQDNs.Count -gt 0)
	{
		Write-Verbose "Calling Test-SSLConfiguration with FQDNs: $($FQDNs -join ', ')"
		Test-SSLConfiguration -FQDNs $FQDNs -SummaryOutputFile $CheckSSLSummaryPath | Out-File -FilePath $CheckSSLPath -Append -Force
	}
}
else
{
	Write-Verbose "aaid or location is not defined or invalid."
}

"$script:CRLF================================================================================$script:CRLF" | Out-File -FilePath $CheckSSLPath -Append -Force

# Ensure $MiscTargetarr is defined and not empty
if ($MiscTargetarr -and $MiscTargetarr.Count -gt 0)
{
	Write-Verbose "Processing MiscTargetarr"
	$MiscTargetarr = $MiscTargetarr | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
	Write-Verbose "Filtered MiscTargetarr:"
	$MiscTargetarr | ForEach-Object { Write-Verbose " - $_" }
	if ($MiscTargetarr.Count -gt 0)
	{
		Write-Verbose "Calling Test-SSLConfiguration with MiscTargetarr: $($MiscTargetarr -join ', ')"
		Test-SSLConfiguration -FQDNs $MiscTargetarr -SummaryOutputFile $CheckSSLSummaryPath | Out-File -FilePath $CheckSSLPath -Append -Force
	}
}
else
{
	Write-Verbose "MiscTargetarr is not defined or empty."
}
#endregion Hybrid Worker Connectivity Tests


#region Hybrid Worker Registry
Write-Console -MessageSegments @(
	@{ Text = "Gathering Hybrid Worker registry"; ForegroundColor = "Cyan" }
)

$registryChecks = @(
	@{
		RegPathPS  = 'HKLM:\SOFTWARE\Microsoft\HybridRunbookWorker'
		RegPathRaw = 'HKLM\SOFTWARE\Microsoft\HybridRunbookWorker'
		OutputFile = "$miscFolder\Reg-HybridRunbookWorker.txt"
	},
	@{
		RegPathPS  = 'HKLM:\SOFTWARE\Microsoft\HybridRunbookWorkerV2'
		RegPathRaw = 'HKLM\SOFTWARE\Microsoft\HybridRunbookWorkerV2'
		OutputFile = "$miscFolder\Reg-HybridRunbookWorkerV2.txt"
	},
	@{
		RegPathPS  = 'HKLM:\SOFTWARE\Microsoft\Azure\HybridWorker'
		RegPathRaw = 'HKLM\SOFTWARE\Microsoft\Azure\HybridWorker'
		OutputFile = "$miscFolder\Reg-AzureHybridWorker.txt"
	}
)

foreach ($reg in $registryChecks)
{
	if (Test-Path $reg.RegPathPS)
	{
		REG EXPORT $reg.RegPathRaw $reg.OutputFile /y | Out-Null
	}
	else
	{
		"'$($reg.RegPathPS)' Not present" | Out-FileWithErrorHandling -Force -FilePath $reg.OutputFile
	}
}

#endregion Hybrid Worker Registry

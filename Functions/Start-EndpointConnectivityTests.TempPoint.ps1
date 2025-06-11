# Define Endpoints
$MiscTargetarr = @(
	# Authentication and Identity Services
	"login.windows.net", # Azure AD and OAuth-based authentication
	"login.microsoftonline.com", # Microsoft online services authentication (Office 365, Azure)
	"pas.windows.net", # Azure Primary Authentication Service (PAS) for identity management
	
	# Azure Management and Operations
	"management.core.windows.net", # Classic Azure Management API endpoint
	"management.azure.com", # Azure Resource Manager (ARM) endpoint
	"agentserviceapi.guestconfiguration.azure.com", # Azure Guest Configuration service
	"gbl.his.arc.azure.com", # Azure Arc management for hybrid resources
	
	# Monitoring and Diagnostics Services
	"api.monitor.azure.com", # Azure Monitor API for metrics and logs
	"profiler.monitor.azure.com", # Azure Profiler for application performance monitoring
	"live.monitor.azure.com", # Azure Live Metrics Stream for real-time data
	"snapshot.monitor.azure.com", # Azure Snapshot Debugger for application diagnostics
	
	# Windows Update
	"catalog.update.microsoft.com" # Microsoft Update Catalog for Windows updates
	
	<# Use these for testing the endpoints to verify the errors are getting handled in the script:
	,"revoked.badssl.com",
	"expired.badssl.com",
	"self-signed.badssl.com",
	"untrusted-root.badssl.com",
	"pinning-test.badssl.com" # Known Issue: Pinning test does not correctly evaluate in this script.
	#>
	
)

# Initialize Results Array
[array]$connectionResults = @()
$testCount = 5 # Number of tests per endpoint

$NetworkFolder = "$outputFolder`Network\"
Create-Folder $NetworkFolder
$TCPTest = "$NetworkFolder\TCPTestResults.txt"

# Function to convert TLS version to a friendly format
function Get-FriendlyTlsVersion($tlsVersion)
{
	switch ($tlsVersion)
	{
		"Ssl3"  { return "SSL 3.0" }
		"Tls"   { return "TLS 1.0" }
		"Tls11" { return "TLS 1.1" }
		"Tls12" { return "TLS 1.2" }
		"Tls13" { return "TLS 1.3" }
		"None"  { return "None" }
		default { return $tlsVersion }
	}
}

$baseProgressBarValue = 10
$targetCount = $MiscTargetarr.Count
$targetCountProgressValue = 90 / $targetCount

foreach ($MiscTargetEndPoint in $MiscTargetarr)
{
	Write-ScriptProgress -Activity '-- Network connectivity tests' -Id 1 -PercentComplete $baseProgressBarValue
	$baseProgressBarValue = $baseProgressBarValue + $targetCountProgressValue
	Write-Console -MessageSegments @(
		@{ Text = "Testing connectivity to: "; ForegroundColor = "Gray" },
		@{ Text = $MiscTargetEndPoint; ForegroundColor = "Cyan" },
		@{ Text = " - "; ForegroundColor = "Gray" }
	) -NoNewLine
	
	$Error.Clear()
	
	try
	{
		# Resolve IP Address
		$ipAddresses = [System.Net.Dns]::GetHostAddresses($MiscTargetEndPoint)
		$ipAddress = $ipAddresses[0]
	}
	catch
	{
		Write-Console "Unable to resolve hostname $MiscTargetEndPoint" -ForegroundColor Red -NoTimestamp
		$connectionResults += [PSCustomObject]@{
			Endpoint	   = $MiscTargetEndPoint
			IPAddress	   = "N/A"
			ConnectionTime = "N/A"
			TLSVersion	   = "N/A"
			Status		   = "Hostname resolution failed"
		}
		continue
	}
	
	# Initialize Connection Times Array and TLS Versions
	$connectionTimes = @()
	$tlsVersions = @()
	$connectivityProgress = 10
	
	# Perform Connectivity Tests
	for ($i = 1; $i -le $testCount; $i++)
	{
		#$connectivityProgress = $connectivityProgress + (Get-Random -Maximum 19 -Minimum 1)
		$connectivityProgress = $connectivityProgress + (Get-Random -Maximum 4 -Minimum 1)
		Write-ScriptProgress -Activity "---- Checking connectivity to '$ipAddress'" -Id 2 -PercentComplete $connectivityProgress
		try
		{
			$tcpClient = New-Object System.Net.Sockets.TcpClient
			$timeout = 5000
			$stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
			
			$asyncResult = $tcpClient.BeginConnect($ipAddress, 443, $null, $null)
			$success = $asyncResult.AsyncWaitHandle.WaitOne($timeout, $false)
			$stopwatch.Stop()
			
			$connectivityProgress = $connectivityProgress + (Get-Random -Maximum 4 -Minimum 1)
			
			if ($success -and $tcpClient.Connected)
			{
				$tcpClient.EndConnect($asyncResult)
				$ConnectionTime = $stopwatch.ElapsedMilliseconds
				$connectionTimes += $ConnectionTime
				
				# Perform SSL/TLS handshake
				$stream = $tcpClient.GetStream()
				$sslStream = New-Object System.Net.Security.SslStream($stream, $false, ({ $true }))
				
				try
				{
					$allowedProtocols = [System.Security.Authentication.SslProtocols]::Tls13 -bor `
					[System.Security.Authentication.SslProtocols]::Tls12 -bor `
					[System.Security.Authentication.SslProtocols]::Tls11 -bor `
					[System.Security.Authentication.SslProtocols]::Tls
					$sslStream.AuthenticateAsClient($MiscTargetEndPoint, $null, $allowedProtocols, $false)
					$connectivityProgress = $connectivityProgress + (Get-Random -Maximum 4 -Minimum 1)
					$tlsVersionRaw = $sslStream.SslProtocol.ToString()
					$tlsVersion = Get-FriendlyTlsVersion $tlsVersionRaw
					$tlsVersions += $tlsVersion
				}
				catch
				{
					$tlsVersions += "Handshake Failed"
				}
				finally
				{
					if ($sslStream)
					{
						$sslStream.Dispose()
					}
				}
			}
			else
			{
				$connectionTimes += $timeout
				$tlsVersions += "Timeout"
			}
		}
		catch
		{
			$stopwatch.Stop()
			$connectionTimes += $timeout
			$tlsVersions += "Connection Failed"
		}
		finally
		{
			if ($tcpClient)
			{
				$tcpClient.Close()
			}
		}
		$connectivityProgress = $connectivityProgress + (Get-Random -Maximum 4 -Minimum 1)
		Start-Sleep -Milliseconds 500
	}
	Write-ScriptProgress -Activity "---- Checking connectivity to '$ipAddress'" -Id 2 -PercentComplete 100 -Completed
	Write-ScriptProgress -Activity '--- Network connectivity tests' -Id 1 -PercentComplete 70
	# Calculate Average Connection Time and Determine Most Common TLS Version
	if ($connectionTimes.Count -gt 0)
	{
		$AverageTime = [math]::Round(($connectionTimes | Measure-Object -Average).Average, 2)
		$mostCommonTLSVersion = ($tlsVersions | Where-Object { $_ -notin @("Handshake Failed", "Timeout", "Connection Failed") } | Group-Object | Sort-Object Count -Descending | Select-Object -First 1).Name
		
		if (-not $mostCommonTLSVersion)
		{
			$mostCommonTLSVersion = "Unknown"
		}
		
		Write-Console -MessageSegments @(
			@{ Text = "Connected "; ForegroundColor = "Green" },
			@{ Text = "(IP Address: "; ForegroundColor = "Gray" },
			@{ Text = "$($ipAddress)"; ForegroundColor = "DarkGreen" },
			@{ Text = "; Average Connection Time: "; ForegroundColor = "Gray" },
			@{ Text = "$AverageTime ms"; ForegroundColor = "Yellow" },
			@{ Text = "; TLS Version: "; ForegroundColor = "Gray" },
			@{ Text = "$mostCommonTLSVersion"; ForegroundColor = "Yellow" },
			@{ Text = ")"; ForegroundColor = "Gray" }
		) -NoTimestamp
		
		# Collect Results
		$connectionResults += [PSCustomObject]@{
			Endpoint	   = $MiscTargetEndPoint
			IPAddress	   = $ipAddress.ToString()
			ConnectionTime = "$AverageTime ms"
			TLSVersion	   = $mostCommonTLSVersion
			Status		   = "Connected"
		}
	}
	Write-ScriptProgress -Activity 'Network connectivity tests' -Id 1 -PercentComplete 100 -Completed
}

$connectionResults | Format-Table | Out-FileWithErrorHandling -FilePath $TCPTest -Force
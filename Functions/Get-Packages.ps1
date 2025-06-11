@(
	"C:\Packages\Plugins\Microsoft.Azure.Automation.HybridWorker.HybridWorkerForWindows",
	"C:\Packages\Plugins\Microsoft.CPlat.Core.WindowsPatchExtension",
	"C:\Packages\Plugins\Microsoft.SoftwareUpdateManagement.WindowsOsUpdateExtension"
) | ForEach-Object -Process {
	$pluginPath = $_
	$pluginPathFolder = ($_ | Split-Path -Leaf)
	
	try
	{
		# Add initial plugin check output
		Write-Console -MessageSegments @(
			@{ Text = "Checking plugin path: "; ForegroundColor = "Cyan" },
			@{ Text = $pluginPath; ForegroundColor = "White" }
		)
		
		if (Test-Path "$pluginPath")
		{
			Write-Console -Text "Plugin path found - Processing..." -ForegroundColor Green
			
			try
			{
				$packagesPluginFolder = "$outputFolder`Packages\Plugins\$pluginPathFolder"
				Copy-File "$pluginPath" $packagesPluginFolder
				Write-Verbose -Message "Copied plugin files to: $packagesPluginFolder"
			}
			catch
			{
				Write-Console -MessageSegments @(
					@{
						Text		    = "ERROR: Failed to copy plugin files - "
						ForegroundColor = "Red"
					},
					@{
						Text		    = $_.Exception.Message
						ForegroundColor = "DarkRed"
					}
				)
				continue
			}
			
			# Status Files Summary
			try
			{
				$Statusfiles = Get-ChildItem "$packagesPluginFolder\*.status" -Recurse -ErrorAction Stop | Sort-Object -Property Name
				$objStatusList = @()
				$StatusSummary = "$packagesPluginFolder\Status_Summary.txt"
				$StatusSummaryDetailed = "$packagesPluginFolder\Status_Summary_Detailed.txt"
				
				Write-Verbose -Message "Found $($Statusfiles.Count) status files to process"
				
				foreach ($fileStatus in $Statusfiles)
				{
					try
					{
							<#
							Write-Console -MessageSegments @(
								@{
									Text		    = "Processing status file: "
									ForegroundColor = "White"
								},
								@{
									Text		    = $fileStatus.Name
									ForegroundColor = "Cyan"
								}
							)
							#>
						Write-Verbose -Message "Working on: $($fileStatus.FullName)"
						# Create status file headers
						@"
====================================================================================================================
====================================================================================================================
==  $($fileStatus.FullName)
"@ | Out-FileWithErrorHandling -Append -FilePath $StatusSummaryDetailed
						
						# Process JSON content
						$JsonStatus = Get-Content $fileStatus.FullName -ErrorAction Stop | ConvertFrom-Json
						$JsonStatus | Format-Table -AutoSize | Out-FileWithErrorHandling -Append -FilePath $StatusSummaryDetailed -Width 4096
						
						if ($JsonStatus.status.substatus)
						{
							
							foreach ($substatus in $JsonStatus.status.substatus)
							{
								try
								{
									"$CRLF`----------------------------------------------------------------------------------------------------------------$CRLF" | Out-FileWithErrorHandling -Append -FilePath $StatusSummaryDetailed
									
									# Output the .pretty.status files
									Format-JsonString -JsonString $substatus.formattedMessage.message | Out-FileWithErrorHandling -Force -FilePath "$($fileStatus.FullName | Split-Path)`\$(($fileStatus.FullName | Split-Path -Leaf) -Replace ".status", ".status.pretty.txt")" -Append
									
									#region Microsoft.Azure.Automation.HybridWorker.HybridWorkerForWindows
									if ($fileStatus.FullName -match "Microsoft.Azure.Automation.HybridWorker.HybridWorkerForWindows")
									{
										$substatus | Format-Table configurationAppliedTime, Name, status, Code | Out-FileWithErrorHandling -Append -FilePath $StatusSummaryDetailed
										Write-Verbose -Message "Encountered: Microsoft.Azure.Automation.HybridWorker.HybridWorkerForWindows"
										# Iterate over each main JSON object
										foreach ($entry in $substatus)
										{
											# Process the main status formatted message
											$formattedMessage = $entry.formattedMessage.message
											$logEntries = @()
											# Split the message text by line breaks and parse each line
											foreach ($line in $formattedMessage -split "\r\n")
											{
												if ($line -match '^\[(?<timestamp>[^\]]+)\]\s+(?<message>.+)$')
												{
													# Extract timestamp and message using named capture groups
													$logEntry = [PSCustomObject]@{
														Timestamp = $matches['timestamp']
														Message   = $matches['message']
													}
													$logEntries += $logEntry
												}
											}
											# Replace the original message with the structured JSON
											$entry.formattedMessage.message = $logEntries
										}
										# Output the entire modified JSON structure
										$substatus.formattedMessage.Message | Out-FileWithErrorHandling -Append -Force -FilePath $StatusSummaryDetailed
									}
									#endregion Microsoft.Azure.Automation.HybridWorker.HybridWorkerForWindows
									#region Microsoft.SoftwareUpdateManagement.WindowsOsUpdateExtension
									elseif ($fileStatus.FullName -match "Microsoft.SoftwareUpdateManagement.WindowsOsUpdateExtension")
									{
										$substatus | Out-FileWithErrorHandling -Append -FilePath $StatusSummaryDetailed
										Write-Verbose -Message "Encountered: Microsoft.SoftwareUpdateManagement.WindowsOsUpdateExtension"
										# Iterate over each main JSON object
										foreach ($entry in $substatus)
										{
											# Process the main status formatted message
											$formattedMessage = $entry.formattedMessage.message | ConvertFrom-Json
											Format-JsonString -JsonString $entry.formattedMessage.message | Out-FileWithErrorHandling -Append -Force -FilePath $StatusSummaryDetailed
											$subStatusMessage | Format-List | Out-FileWithErrorHandling -Append -FilePath $StatusSummaryDetailed
										}
									}
									#endregion Microsoft.SoftwareUpdateManagement.WindowsOsUpdateExtension
									elseif ($substatus.formattedMessage.message)
									{
										$substatusObject = [PSCustomObject]@{
											timestampUTC = $JsonStatus.timestampUTC
											Name		 = $substatus.Name
											status	     = $substatus.status
											Code		 = $substatus.Code
										} | Out-FileWithErrorHandling -Append -Force -FilePath $StatusSummaryDetailed
																				
										$subStatusMessage = $substatus.formattedMessage.message | ConvertFrom-Json
										Format-JsonString -JsonString $substatus.formattedMessage.message | Out-FileWithErrorHandling -Append -FilePath $StatusSummaryDetailed
										$subStatusMessage | Format-List | Out-FileWithErrorHandling -Append -FilePath $StatusSummaryDetailed
									}
								}
								catch
								{
									Write-Console -MessageSegments @(
										@{
											Text		    = "ERROR: Failed to process substatus in status file: $($fileStatus.FullName) - "
											ForegroundColor = "Red"
										},
										@{
											Text		    = $_.Exception.Message
											ForegroundColor = "DarkRed"
										}
									)
								}
							}
						}
						else
						{
							Write-Console -Text "No substatus found in status file: $($fileStatus.FullName)" -ForegroundColor Yellow
						}
						if ($subStatusMessage.patchServiceUsed)
						{
							$Statusobjxx = [PSCustomObject]@{
								Name			 = $JsonStatus.status.name
								Status		     = $JsonStatus.status.status
								Operation	     = $JsonStatus.status.operation
								patchServiceUsed = $subStatusMessage.patchServiceUsed
								Code			 = $JsonStatus.status.code
								Message		     = $JsonStatus.status.formattedMessage.message
								timestampUTC	 = $JsonStatus.timestampUTC
							}
						}
						else
						{
							$Statusobjxx = [PSCustomObject]@{
								Name	  = $JsonStatus.status.name
								Status    = $JsonStatus.status.status
								Operation = $JsonStatus.status.operation
								Code	  = $JsonStatus.status.code
								Message   = ($JsonStatus.status.formattedMessage.message).Replace("`"[", "").Replace(".`"]", "").Replace("].`"", "")
								timestampUTC = $JsonStatus.timestampUTC
							}
						}
						
						$objStatusList += $Statusobjxx
					}
					catch
					{
						Write-Console -MessageSegments @(
							@{
								Text		    = "ERROR: Failed to process status file '$($fileStatus.Name)' - "
								ForegroundColor = "Red"
							},
							@{
								Text		    = $_.Exception.Message
								ForegroundColor = "DarkRed"
							}
						)
					}
				}
				
				if ($objStatusList)
				{
					try
					{
						Write-Console -Text "Writing status summary to: $StatusSummary" -ForegroundColor Green
						if ($pluginPathFolder -eq 'Microsoft.SoftwareUpdateManagement.WindowsOsUpdateExtension')
						{
							Write-Verbose "Patch Service Used: $($objStatusList.patchServiceUsed)"
							$objStatusList | Sort-Object timestampUTC | Format-Table timestampUTC, patchServiceUsed, Operation, Status, Message -Wrap |
							Out-FileWithErrorHandling -FilePath $StatusSummary
						}
						else
						{
							Write-Verbose "Patch Service not used."
							$objStatusList | Sort-Object timestampUTC | Format-Table timestampUTC, Operation, Status, Message -Wrap |
							Out-FileWithErrorHandling -FilePath $StatusSummary
						}
						
					}
					catch
					{
						Write-Console -MessageSegments @(
							@{
								Text		    = "ERROR: Failed to write status summary - "
								ForegroundColor = "Red"
							},
							@{
								Text		    = $_.Exception.Message
								ForegroundColor = "DarkRed"
							}
						)
					}
				}
				else
				{
					Write-Console -Text "No status information collected to summarize" -ForegroundColor Yellow
				}
			}
			catch
			{
				Write-Console -MessageSegments @(
					@{
						Text		    = "ERROR: Failed to process status files - "
						ForegroundColor = "Red"
					},
					@{
						Text		    = $_.Exception.Message
						ForegroundColor = "DarkRed"
					}
				)
			}
			
			Write-Verbose -Message "Completed processing plugin: $pluginPathFolder"
		}
		else
		{
			Write-Verbose -Message "Plugin path not found: $pluginPath"
		}
	}
	catch
	{
		Write-Console -MessageSegments @(
			@{
				Text = "CRITICAL ERROR: Failed to process plugin '$pluginPathFolder' - "
				ForegroundColor = "Red"
			},
			@{
				Text		    = $_.Exception.Message
				ForegroundColor = "DarkRed"
			}
		) -NoNewLine:$false
	}
}
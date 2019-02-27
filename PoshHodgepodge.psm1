Function Start-RDP {
    [CmdletBinding(SupportsShouldProcess=$false)]
    param(
        [Alias("Server")]
        [Parameter (Position=0, ValueFromPipeline=$true, HelpMessage="The ComputerName to connect to as a string, may include the port number if not default by adding a colon and then the port number.")]
        [string]$ComputerName,
        [Parameter (Position=1, HelpMessage="Username to pass to MSTSC via cmdkey.")]
        [string]$Username,
        [Parameter (Position=2, HelpMessage="Password to pass to MSTSC via cmdkey.")]
        [string]$Password = "",
        [Parameter (HelpMessage="Width of display.")]
        [int]$Width,
        [Parameter (HelpMessage="Height of display.")]
        [int]$Height,
        [Parameter (HelpMessage="Path and filename of an RDP connection settings file.")]
        [string]$RDPFile,
        [Alias("Console")]
        [Parameter (HelpMessage="Connect to the admin or console session.")]
        [switch]$Admin,
        [Parameter (HelpMessage="Display in fullscreen.")]
        [switch]$Fullscreen,
        [Parameter (HelpMessage="Runs in public mode which prevents client from saving caching things like computername, credentials, etc.")]
        [switch]$Public,
        [Parameter (HelpMessage="Matches the remote desktop width and height with the local virtual deskop, spanning across multiple monitors, if necessary.")]
        [switch]$Span,
        [Parameter (HelpMessage="Configures the remote deskotp session monitor layout to be identical to the current client-side configuration.")]
        [switch]$MultiMonitor,
        [Parameter (HelpMessage="Clears any credentials saved for server using cmdkey.")]
        [switch]$ClearCredentials
    )

    begin {
        $arguments = ""
        if ($RDPFile) {
            $arguments = "'" + $RDPFile + "' "
        }
        if ($Admin) {
            $arguments += "/admin "
        }
        if ($Fullscreen) {
            $arguments += "/f "
        }
        if ($Public) {
            $arguments += "/public "
        }
        if ($Span) {
            $arguments += "/span "
        }
        if ($MultiMonitor) {
            $arguments += "/multimon "
        }
        if ($Width) {
            $arguments += "/w:$Width "
        }
        if ($Height) {
            $arguments += "/h:$Height "
        }
    }

    process {
        if (!$Public) {
            if ($Username) {
                $servername = $ComputerName.Split(":")[0]
                $cmdkeyargs = "/generic:TERMSRV/" + $servername + " /user:" + $Username
                if ($Password -gt "") {
                    $cmdkeyargs += " /pass:" + $Password
                }
                Invoke-Expression "cmdkey $cmdkeyargs" | Out-Null
            }
            if ($ClearCredentials) {
                $servername = $ComputerName.Split(":")[0]
                $cmdkeyargs = "/delete:TERMSRV/" + $servername
                Invoke-Expression "cmdkey $cmdkeyargs" | Out-Null
            }
        }
        $cmdline = "$env:windir\system32\mstsc.exe $arguments"
        if ($ComputerName) {
            $cmdline += "/v:" + $ComputerName + " "
        }
        Write-Verbose $cmdline
        Invoke-Expression $cmdline
    }
}
<#
Boolean CheckSessionIsElevated()
http://blog.msresource.net/2011/05/04/check-whether-or-not-the-current-powershell-session-is-elevated/

Check whether or not the current identity (the principal
running the current PS session) is a member of
Builtin\Administrators.

Returns true if the current principal is a member of
administrators; false otherwise

Function based on the code at:
http://www.interact-sw.co.uk/iangblog/2007/02/09/pshdetectelevation
#>

function Test-SessionIsElevated
{
   [System.Security.Principal.WindowsPrincipal]$currentPrincipal = `
      New-Object System.Security.Principal.WindowsPrincipal(
         [System.Security.Principal.WindowsIdentity]::GetCurrent());

   [System.Security.Principal.WindowsBuiltInRole]$administratorsRole = `
      [System.Security.Principal.WindowsBuiltInRole]::Administrator;

   if($currentPrincipal.IsInRole($administratorsRole))
   {
      return $true;
   }
   else
   {
      return $false;
   }
}

function Start-Beep {
    [CmdletBinding(SupportsShouldProcess=$false)]
	Param(
        [Parameter(Mandatory=$false,Position=0,ValueFromPipeline=$false,ValueFromPipelineByPropertyName=$false)]
        [Int32] $Count = 1
    )
    [Int32] $cntr = 0
    Do {
        [console]::beep(500,300)
        $cntr += 1
    } While (($Count -eq 0) -or ($cntr -lt $Count))
}

<#
.SYNOPSIS
Returns a list os users logged on to a computer(s).  Only display domain (non computer) accounts and returns them as ADUser objects.

#>
function Get-LoggedOnUsers {
	[CmdletBinding(SupportsShouldProcess=$false)]
	Param(
		[Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,HelpMessage="Computer(s) to get current logged on users from.")]
		[String[]]$ComputerName
	)
	Process {
        $ComputerName | %{Get-WmiObject Win32_LoggedOnUser -ComputerName $ComputerName | select Antecedent -Unique | Where-Object -Property "Antecedent" -NotLike -Value "*$ComputerName*" | %{(((($_.Antecedent.ToString().Split(","))[1]).Split("="))[1]).Replace('"', "") | Get-ADUser}}
	}
}
function Get-StartOfMonth {
	[CmdletBinding(SupportsShouldProcess=$false)]
	Param(
		[Parameter(Mandatory=$false,Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[DateTime]$Date
	)
	Process {
        if (!$Date) {$Date = Get-Date}
        return (Get-Date $date -day 1 -hour 0 -minute 0 -second 0).Date
	}
}

function Get-EndOfMonth {
	[CmdletBinding(SupportsShouldProcess=$false)]
	Param(
		[Parameter(Mandatory=$false,Position=0,ValueFromPipeline=$true,ValueFromPipelineByPropertyName=$true)]
		[DateTime]$Date
	)
	Process {
        if (!$Date) {$Date = Get-Date}
        $startofmonth = Get-Date $date -day 1 -hour 0 -minute 0 -second 0
        return (($startofmonth).AddMonths(1).AddMilliseconds(-1)).Date
	}
}

<#
.SYNOPSIS
Listens to a UDP port outputing resulting strings.  Built to listen for GPS sentences broadcast via UDP.

#>
function Listen-UDPSocket {
	[CmdletBinding(SupportsShouldProcess=$false)]
	Param(
		[Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$false,HelpMessage="Port to Listen On")]
		[Int]$Port,
		[Parameter(Mandatory=$false,Position=1,ValueFromPipeline=$false,HelpMessage="Number of recieves before it stops, defaults to 100")]
		[Int]$MaxRecieves = 100,
        [Parameter(Mandatory=$false,Position=2,ValueFromPipeline=$false,HelpMessage="Return the raw bytes instead of converting to ASCII")]
		[Switch]$AsBytes
	)
	Begin {
        #Create UDPClient
        [System.Net.Sockets.UdpClient] $receivingUdpClient = New-Object -TypeName "System.Net.Sockets.UdpClient" -ArgumentList @($Port);
        [System.Net.IPEndPoint] $RemoteIpEndPoint = New-Object -TypeName "System.Net.IPEndPoint" -argumentlist @([System.Net.IPAddress]::Any, 0)
	}
	Process {
        
        [Int]$cntr = 0
        While ($cntr -lt $MaxRecieves) {
            [Byte[]] $recieveBytes = $receivingUdpClient.Receive([ref] $RemoteIpEndPoint)
            [String] $returnString = [System.Text.Encoding]::ASCII.GetString($recieveBytes)
            Write-Output $returnString
            if ($MaxRecieves -eq 1) {
                if ($AsBytes) {
                    return $recieveBytes
                } else {
                    return $returnString
                }
            }
            $cntr = $cntr + 1
        }
	}
	End {
        $receivingUdpClient.Close()
        $receivingUdpClient.Dispose()
        $receivingUdpClient = $null
	}
}

<#
.SYNOPSIS
TODO

#>

Function Watch-ValueForChange {
	[CmdletBinding(SupportsShouldProcess=$false,DefaultParameterSetName="Object")]
	Param(
		[Parameter(HelpMessage="Exits the function on value change, returning the value or ReturnValue.  Defaults to TRUE.")]
	    	[Switch]$StopOnChange=$true,
        [Parameter(HelpMessage="Invokes the ScriptBlock on value change.")]
            [ScriptBlock]$InvokeOnChange,
        [Parameter(HelpMessage="Number of seconds to delay between value tests, defaults to 60.")]
            [int]$Seconds=60,
        [Parameter(HelpMessage="Number of time to test value, defaults to 60.")]
            [int]$Count=60,
        [Parameter(HelpMessage="Value to return instead of the test value.")]
            [Object]$ReturnValue,
        [Parameter(Mandatory=$false,Position=0,ParameterSetName="ScriptBlock",HelpMessage="A script block which returns value to monitor.")]
		    [ScriptBlock]$InvokeForValue,
        [Parameter(Mandatory=$false,Position=0,ParameterSetName="Object",HelpMessage="Object to monitor.  Compares object or if Parameter specified, uses the parameter value.")]
		    [Object]$Object,
        [Parameter(Mandatory=$false,Position=1,ParameterSetName="Object",HelpMessage="Parameter to retrieve value from object")]
            [Object]$Parameter
    )
    
    [boolean]$continue = $true
    [int]$CurrentCount = 0

    [Object]$OldValue
    [Object]$NewValue
    [Object]$ValueToReturn = $null

    #Get current value based on
    #which ParameterSet are we using
    if ($psCmdlet.ParameterSetName -eq "Object") {  #Object
        if ($Parameter) {
            $NewValue = $Object.$Parameter
        } else {
            $NewValue = $Object
        }
    } else {   #ScriptBlock
        $NewValue = ($InvokeForValue.InvokeReturnAsIs())
    }

    $OldValue = $NewValue

    #Loop
    while ($continue) {
        Start-Sleep -Seconds $Seconds
        
        #Get current value based on
        #which ParameterSet are we using
        if ($psCmdlet.ParameterSetName -eq "Object") {  #Object
            if ($Parameter) {
                $NewValue = $Object.$Parameter
            } else {
                $NewValue = $Object
            }
        } else {   #ScriptBlock
            $NewValue = ($InvokeForValue.InvokeReturnAsIs())
        }

        #Test for change
        if (!($NewValue -eq $OldValue)) {
            #Found a change
            if ($InvokeOnChange) {
                $InvokeOnChange.Invoke()
            }

            #Return value
            if ($ReturnValue) {
                $ValueToReturn = $ReturnValue
            } else {
                $ValueToReturn = $NewValue
            }

            if ($StopOnChange) {
                $continue = $false
            } else {
                $OldValue = $NewValue
            }
        }

        if ($CurrentCount -eq $Count) {
            $continue = $false
        } else {
            $CurrentCount = $CurrentCount +  1
        }
    }

    return $ValueToReturn

}

<#
.SYNOPSIS
Outputs input to a ps1 file with a random name and opens in text editor, defaulting to Notepad.  Returns the full path and file name so you can run it.  Also saves path to $PSMy

#>
function Out-Scratch {
	[CmdletBinding(SupportsShouldProcess=$false,DefaultParameterSetName="input")]
	Param(
		[Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,ParameterSetName="input",HelpMessage="Text to output to Notepad.")]
		[PSObject[]]$InputObj,
		[Parameter(Mandatory=$false,Position=1,ValueFromPipeline=$false,ParameterSetName="input",HelpMessage="Editor to open ps1 file in. Defaults to notepad.  Can be overiden by setting PSMyScratchEditor.")]
		[String]$ScratchEditor,
		[Parameter(Mandatory=$false,Position=2,ValueFromPipeline=$false,ParameterSetName="input",HelpMessage="Path to save scratch files to.  Defaults to your profile directory.  Can be overiden by setting PSMyScratchPath.")]
		[String]$ScratchPath,
		[Parameter(Mandatory=$false,Position=3,ValueFromPipeline=$false,ParameterSetName="input",HelpMessage="Name of file to save to.  Defaults to Scratch-<random number>.ps1.")]
		[String]$ScratchFileName,
		[Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,ParameterSetName="clear",HelpMessage="Clear the scratch folder")]
		[switch]$Clear
	)
	Begin {
		if (!$ScratchPath) {
			if ($PSMyScratchPath) {
				$ScratchPath = $PSMyScratchPath
			} else {
				$ScratchPath = (Get-Item $Profile).DirectoryName
			}
		}

		if (!$ScratchEditor) {
			if ($PSMyScratchEditor) {
				$ScratchEditor = $PSMyScratchEditor
			} else {
				$ScratchEditor = "notepad.exe"
			}
		}
		
		if (!$ScratchFileName) {
			$ScratchFileName = "Scratch-" + (Get-Random) + ".ps1"
		}

		[String] $ScratchFile = $ScratchPath + "\" + $ScratchFileName
		[String] $ScratchOutput = ""
	}
	Process {
		if ($Clear) {
			Remove-Item -Path ($PSMyScripts + "\Scratch\Scratch-*.ps1") -ErrorAction SilentlyContinue
		} else {
			Out-File -FilePath $ScratchFile -Append -InputObject $InputObj -NoClobber -Width 1000
			$ScratchOutput += $InputObj
		}
	}
	End {
		if ($Clear) {
			Clear-Variable -Name "PSMyLastScratch" -Scope Global
		} else {
			& $ScratchEditor $ScratchFile
			Set-Variable -Name "PSMyLastScratchFile" -Value $ScratchFile -Scope Global
			Set-Variable -Name "PSMyLastScratch" -Value $ScratchOutput -Scope Global
			return "$ScratchFile"
		}
	}
}


function Search-Web {
    [CmdletBinding(SupportsShouldProcess=$false)]
	Param(
		[Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,HelpMessage="String to search for.")]
		[String]$Search,
		[Parameter(Mandatory=$false,Position=1,ValueFromPipeline=$false,HelpMessage="Search enginge to use, defaults to Google")]
		[String]$SearchEngine = "Google"
	)
    $Search = [System.Web.HttpUtility]::UrlEncode($Search)
    [String]$url = ""
    switch ($SearchEngine.toLower()) {
        "google" {$url="https://www.google.com/search?q=$Search&output=search"}
        "bing" {$url="http://www.bing.com/search?q=$Search"}
    }
    browse $url
}


<#
.SYNOPSIS
Changes a users primary group, adding them to the group if they are not already a member.

#>

#Parse GPS strings
#$GPRMC, $GPGGA, >RPV

<#
.SYNOPSIS
A template for cmdlets

#>
function Parse-GPSSentence {
	[CmdletBinding(SupportsShouldProcess=$false)]
	Param(
		[Parameter(Mandatory=$true,Position=0,ValueFromPipeline=$true,HelpMessage="String to find GPS data in")]
		[String]$Sentence,
                [Parameter(Mandatory=$true,Position=1,ValueFromPipeline=$false,HelpMessage="GPS sentence type to parse for")]
                [String]$SentenceType
	)
	Begin {
        #Put begining stuff here
	}
	Process {
        #Create object to hold resulting data
        $GPSData = New-Object PSObject -Property @{
            Sentence = ""
            LattitudeDecimal = 0
            LongitudeDecimal = 0
            Date = $null
            Time = $null
            HeadingDegrees = 0
            SpeedMPH = 0
        }

        #Branch to sentence type
        Switch ($SentenceType) {
            "RPV" {
                    #Parse the sentence string for RPV
                    #>RPV00010+4878644-1224490200108812;ID=TEST;*6C<
                    $GPSData.Sentence = $Sentence.Substring($Sentence.IndexOf(">RPV"), ($Sentence.IndexOf("<") - $Sentence.IndexOf(">RPV")))
                    [TimeSpan] $ts = [System.TimeSpan]::FromSeconds(([String] $GPSData.Sentence.Substring(5,5)).ToInt32())
                    echo $ts

                }
        }

        #Return object
        return $GPSData
	}
	End {
        #Put end here
	}
}

Export-ModuleMember -Function *
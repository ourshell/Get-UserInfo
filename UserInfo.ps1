#-- Name		: UserInfo.ps1
#-- Engine		: PowerShell 2.0+, .NET v3.5+, Minimum screen resolution: 1280x800
#-- Version		: 1.00 Stable
#-- Date		: 28.02.2019
#-- Changes		: n/a
#-- Usage		: Get-Help .\UserInfo.ps1
#-- Developer	: PS-Solutions.net
#-- License		: GNU General Public License | http://www.gnu.org/licenses/gpl-2.0.html
#-- Purpose		: Verify user domain activity
#-- References	: StackOverflow, Microsoft Blogs, 4SYSOPS, ServerFault

<#
.SYNOPSIS
Check users details in all domain controllers, force unlock.
Display basic lockout information, modify time, last logon, password set, etc.

.DESCRIPTION
Input username or a list of users from text file.
By default the script requires username as an input if no switch is specified.
Switch "-Export" always appends to existing file.

.Link
https://ps-solutions.net/index.php/userinfo/

.EXAMPLE
_
.\UserInfo.ps1 -User H24934
.\UserInfo.ps1 B17124 -Details -Unlock -ComputerOwner
.\UserInfo.ps1 B17124 -Details -Unlock -Server dc1.dev.net
.\UserInfo.ps1 B17124 -Details -Unlock -Domain dev.net -Export Results.txt

.EXAMPLE
_
# Enter password in plain text, then converts in secure string #
.\UserInfo.ps1 B17124 -Details -Unlock -Credential domain\user:password

# Prompts a window to type credentials #
.\UserInfo.ps1 B17124 -Details -Unlock -Credential domain\user

.EXAMPLE
_
.\UserInfo.ps1 -UsersFromFile users.txt -Details -Unlock
.\UserInfo.ps1 -UsersFromFile users.txt -Unlock -PDC
.\UserInfo.ps1 -UsersFromFile users.txt -Unlock -Server dc1.dev.net
.\UserInfo.ps1 -UsersFromFile users.txt -Unlock -Domain dev.net -PDC -Export Results.txt
#>

<# Examples of time stamps, replication and no replication values accros domain controllers.
## All time related values are returned in local time zone where the scrip is ran from.

accountExpires                       : 9223372036854775807 ## REPLICATES
badPasswordTime                      : 131534286956350997  ## NO!
Created                              : 02.12.2015 13:46:07 ## REPLICATES
createTimeStamp                      : 02.12.2015 13:46:07 ## REPLICATES
LastBadPasswordAttempt               : 25.10.2017 20:11:35 ## NO!
lastLogon                            : 131642164962127173  ## NO!
LastLogonDate                        : 20.02.2018 07:02:27 ## REPLICATES But no decent results.
lastLogonTimestamp                   : 131635801479750877  ## REPLICATES But no decent results.
Modified                             : 27.02.2018 19:20:27 ## NO!
modifyTimeStamp                      : 27.02.2018 19:20:27 ## NO!
PasswordLastSet                      : 29.06.2016 18:20:05 ## REPLICATES
pwdLastSet                           : 131116908057021544  ## REPLICATES
whenChanged                          : 27.02.2018 19:20:27 ## NO!
whenCreated                          : 02.12.2015 13:46:07 ## REPLICATES

#>

[cmdletbinding()]
Param(
[Parameter(ValuefromPipeline=$true, Mandatory=$false)][string]$User,
[Parameter(ValuefromPipeline=$true, Mandatory=$false)][string]$UsersFromFile,
[Parameter(ValuefromPipeline=$false, Mandatory=$false)][switch]$Details,
[Parameter(ValuefromPipeline=$false, Mandatory=$false)][switch]$Unlock,
[Parameter(ValuefromPipeline=$false, Mandatory=$false)][switch]$ComputerOwner,

[Parameter(ValuefromPipeline=$true, Mandatory=$false)][string][Alias("Server")]$Domain = $env:USERDNSDOMAIN,
[Parameter(ValuefromPipeline=$false, Mandatory=$false)][switch]$PDC,
[Parameter(ValuefromPipeline=$true, Mandatory=$false)][string]$Credential,
[Parameter(ValuefromPipeline=$true, Mandatory=$false)][string]$Export
)

$Valid = [int]($User -ne "") + [int]($UsersFromFile -ne "") + [int]($User -ne "" -and $PDC.IsPresent) + [int]($UsersFromFile -ne "" -and $ComputerOwner.IsPresent)

if ($Valid -ne 1) {
	Write-Host ("`nInvalid switch combination. Type ""Get-Help .\UserInfo-Unlock.ps1 -Examples"" for details.`n") -ForegroundColor Red
	Exit
}

Try { Import-Module ActiveDirectory } Catch { Write-Host $_ -ForegroundColor Red; Exit}

<# Known errors related to not enough permissions: ###
   The server was unable to process the request due to an internal error.
   The server has rejected the client credentials.
#>

if ($Credential -ne "") {
	if (($Credential.IndexOf(":") -gt 0) -and ($Credential.IndexOf(":") -ne $Credential.Length - 1)) {
		$SecurePassword = ConvertTo-SecureString $Credential.Substring($Credential.IndexOf(":") + 1) -AsPlainText -Force
		$SecureUsername = $Credential.Substring(0, $Credential.IndexOf(":"))
		$Creds = New-Object System.Management.Automation.PSCredential -ArgumentList $SecureUsername, $SecurePassword
	}
	else { $Creds = $Host.ui.PromptForCredential("Credentials required!", "`r`nInput credentials for domain:`r`n" + $Domain, $Credential, "") }
}

if ($Export -ne "") { $OutFile = $True } else { $OutFile = $False}

$StartTime = Get-Date
$Output = "`r`nStart Time: " + $StartTime.ToString("dd'/'MM'/'yyyy HH:mm:ss")
Write-Host $Output
if ($OutFile) { $Output >> $Export }

Function EndScript ($StartTime) {
	$EndTime = Get-Date
	$Output = "`r`nEnd Time: " + $EndTime.ToString("dd'/'MM'/'yyyy HH:mm:ss")
	Write-Host $Output
	if ($OutFile) { $Output >> $Export }
	
	$TotalTime = $EndTime - $StartTime
	$Output = "Execution time: " + $TotalTime.Days + "d " + $TotalTime.Hours.ToString("00:") + $TotalTime.Minutes.ToString("00:") + $TotalTime.Seconds.ToString("00") + "`r`n"
	Write-Host $Output
	if ($OutFile) { $Output >> $Export }
	Exit
}

$Error.Clear()
if ($Credential -eq "") { Try { $DomainInfo = Get-ADDomain -Server $Domain } Catch {} }
else { Try { $DomainInfo = Get-ADDomain -Server $Domain -Credential $Creds} Catch {} }

if (-not [string]::IsNullOrEmpty($Error)) {
	Write-Host ("`r`n$Error`r`n") -ForegroundColor Red
	if ($OutFile) { [String]$Error >> $Export }
	EndScript $StartTime
}

$Rdcs = $DomainInfo.ReadOnlyReplicaDirectoryServers
$dcs = $DomainInfo.ReplicaDirectoryServers + $Rdcs
#$dcs = $dcs[0..2]
$TotalDCs = $dcs.Count
$PrimaryDC = $DomainInfo.PDCEmulator
$NetBIOSName = $DomainInfo.NetBIOSName

If ((Get-Host).UI.RawUI.BufferSize.Width -lt 150) {
	$pswindow = (Get-Host).ui.rawui
	$newsize = $pswindow.buffersize
	#$newsize.height = 3000
	$newsize.width = 150
	$pswindow.buffersize = $newsize
	$newsize = $pswindow.windowsize
	#$newsize.height = 50
	$newsize.width = 150
	$pswindow.windowsize = $newsize
}

####### Single user details ######
if ($UsersFromFile -eq "" -and ($Details.IsPresent -or (!$Unlock.IsPresent -and !$ComputerOwner.IsPresent))) {
	
	$LatestlockoutTime = 0
	$LatestbadPasswordTime = 0
	$LatestLogon = 0
	
	####### First detailed output ######
	
	Write-Host "`r`nDCs=$TotalDCs`tReplicaDCs, " -NoNewLine
	Write-Host "PDC, " -NoNewLine -ForegroundColor Green
	Write-Host "ReadOnlyDCs`t" -NoNewLine -ForegroundColor Yellow
	$Output = "Enabled`t" + "Locked`t" + "Locked out date time`t" + "Last bad password`t" + "Count`t" + "Last Log on time"
	Write-Host $Output
	$Line = "`r`nDCs=$TotalDCs`t" + "ReplicaDCs, PDC, ReadOnlyDCs`t" + "Enabled`t" + "Locked`t" + "Locked out date time`t" + "Last bad password`t" + "Count`t" + "Last Log on time"
	if ($OutFile) { $Line >> $Export }
	
	$Output = ("======`t" + "============================`t" + "=======`t" +"======`t" + "====================`t" + "===================`t" + "=====`t" + "===================")
	Write-Host $Output
	if ($OutFile) { $Output >> $Export }
	
	$counter = 0
	foreach ($dc in $dcs) {
		$counter++
		$Output = "  " + $counter + "`t"
		$Line = $Output
		Write-Host $Output -NoNewLine
		
		if ($dc.Length -lt 8) { $Output = "$dc`t`t`t`t" }
		elseif ($dc.Length -lt 16) { $Output = "$dc`t`t`t" }
		elseif ($dc.Length -lt 24) { $Output = "$dc`t`t" }
		elseif ($dc.Length -lt 32) { $Output = "$dc`t" }
		else { $Output = $dc.Substring(0,28) + "...`t" }
		
		$Line += $Output
		if ($dc -eq $PrimaryDC) { Write-Host $Output -NoNewLine -ForegroundColor Green }
		elseif ($Rdcs -like $dc ) { Write-Host $Output -NoNewLine -ForegroundColor Yellow }
		else { Write-Host $Output -NoNewLine }
		
		$Error.Clear()
		if ($Credential -eq "") {
			Try {
				[Array]$UserInfoAllDCs += Get-ADUser $User -Server $dc -Properties DistinguishedName, `
				Enabled, LockedOut, lockoutTime, badPasswordTime, badPwdCount, lastLogon, GivenName, Surname, Created, Modified, pwdLastSet, accountExpires, logonCount, msDS-UserPasswordExpiryTimeComputed
			} Catch {}
		}
		else {
			Try {
				[Array]$UserInfoAllDCs += Get-ADUser $User -Server $dc -Credential $Creds -Properties DistinguishedName, `
				Enabled, LockedOut, lockoutTime, badPasswordTime, badPwdCount, lastLogon, GivenName, Surname, Created, Modified, pwdLastSet, accountExpires, logonCount, msDS-UserPasswordExpiryTimeComputed
			} Catch {}
		}
		
		if (-not [string]::IsNullOrEmpty($Error)) {
			[Array]$UserInfoAllDCs += "n/a"
			if ($Error -like "*contact the server*") {
				$Output = "The server is down or does not have the Active Directory Web Services running."
				$Line += $Output
				Write-Host $Output -ForegroundColor Red
				if ($OutFile) { $Line >> $Export }
			}
			elseif ($Error -like "*find an object*") {
				$Output = "$User - The user does not exist on this domain controller."
				$Line += $Output
				Write-Host $Output -ForegroundColor Yellow
				if ($OutFile) { $Line >> $Export }
			}
			else {
				$Line += $Error
				Write-Host $Error -ForegroundColor Red
				if ($OutFile) { $Line >> $Export }
			}
			Continue
		}
		
		$UserInfo = $UserInfoAllDCs[$counter - 1]
		$Enabled = $UserInfo.Enabled
		$LockedOut = $UserInfo.LockedOut
		
		$lockoutTime = $UserInfo.lockoutTime
		if ($lockoutTime -eq 0 -or [string]::IsNullOrEmpty($lockoutTime)) { $lockoutTime = "no info available" }
		else {
			if ($LatestlockoutTime -lt $lockoutTime) { $LatestlockoutTime = $lockoutTime }
			$lockoutTime = [DateTime]::FromFileTime($lockoutTime).ToString("dd'/'MM'/'yyyy HH:mm:ss")
		}
		
		$badPasswordTime = $UserInfo.badPasswordTime
		if ($badPasswordTime -eq 0 -or [string]::IsNullOrEmpty($badPasswordTime)) { $badPasswordTime = "no info available" }
		else {
			if ($LatestbadPasswordTime -lt $badPasswordTime) { $LatestbadPasswordTime = $badPasswordTime }
			$badPasswordTime = [DateTime]::FromFileTime($badPasswordTime).ToString("dd'/'MM'/'yyyy HH:mm:ss")
		}
		
		$badPwdCount = $UserInfo.badPwdCount
		if ([string]::IsNullOrEmpty($badPwdCount)) { $badPwdCount = "n/a" }
		
		$lastLogon = $UserInfo.lastLogon
		if ($lastLogon -eq 0 -or [string]::IsNullOrEmpty($lastLogon)) { $lastLogon = "no info available" }
		else {
			if ($LatestLogon -lt $lastLogon) { $LatestLogon = $lastLogon }
			$lastLogon = [DateTime]::FromFileTime($lastLogon).ToString("dd'/'MM'/'yyyy HH:mm:ss")
		}
		
		$Output = "$Enabled`t"
		$Line += $Output
		if ($Enabled) { Write-Host $Output -NoNewLine }
		else { Write-Host $Output -NoNewLine -ForegroundColor Red}
		
		if ($LockedOut) { $Output = " YES`t" }
		else { $Output = " NO`t"}
		$Line += $Output
		if ($LockedOut) { Write-Host $Output -NoNewLine -ForegroundColor Red }
		else { Write-Host $Output -NoNewLine }
		
		$Output = "$lockoutTime`t" + "$badPasswordTime`t"
		$Line += $Output
		Write-Host $Output -NoNewLine
		
		$Output = " $badPwdCount`t"
		$Line += $Output
		if ($badPwdCount -gt 0) { Write-Host $Output -NoNewLine -ForegroundColor Red }
		else { Write-Host $Output -NoNewLine }
		
		$Output = "$lastLogon"
		$Line += $Output
		Write-Host $Output
		if ($OutFile) { $Line >> $Export }
	}
	
	$UserExist = $False
	$CheckIfExist = $UserInfoAllDCs | Foreach-Object {$_ -ne "n/a"}
	foreach ($Check in $CheckIfExist) { $UserExist = $Check -or $UserExist }
	
	if (-not $UserExist) {
		$Output = "`r`nUser ""$User"" was not found in any domain controller from domain: $NetBIOSName`r`nDNSRoot: " + $DomainInfo.DNSRoot
		Write-Host $Output -ForegroundColor Yellow
		if ($OutFile) { $Output >> $Export }
		EndScript $StartTime
	}
	
	#### Single user, second detailed output ####
	
	Write-Host "`r`nDCs=$TotalDCs`tServers, " -NoNewLine
	Write-Host "PDC, " -NoNewLine -ForegroundColor Green
	Write-Host "ReadOnlyDCs`t" -NoNewLine -ForegroundColor Yellow
	$Output = "Modified date time`t" + "Last Password Set`t" + "Account expires on`t" + "Password expires on"
	Write-Host $Output

	$Line = "`r`nDCs=$TotalDCs`t" + "Servers, PDC, ReadOnlyDCs`t" + "Modified date time`t" + "Last Password Set`t" + "Account expires on`t" + "Password expires on"
	if ($OutFile) { $Line >> $Export }
	
	$Output = "======`t=========================`t" + "===================`t" + "===================`t" + "===================`t" + "==================="
	Write-Host $Output
	if ($OutFile) { $Output >> $Export }
	
	$LastCreated = 0
	$LastModified = 0
	$PasswordLastSet = 0
	$LastExpire = 0
	$LogonCount = 0
	$counter = 0
	
	foreach ($UserInfo in $UserInfoAllDCs) {
		$counter++
		$Output = "  " + $counter + "`t"
		$Line = $Output
		Write-Host $Output -NoNewLine
		
		if ($dc.Length -lt 8) { $Output = $dcs[$counter - 1] + "`t`t`t`t" }
		elseif ($dc.Length -lt 16) { $Output = $dcs[$counter - 1] + "`t`t`t" }
		elseif ($dc.Length -lt 24) { $Output = $dcs[$counter - 1] + "`t`t" }
		elseif ($dc.Length -lt 32) { $Output = $dcs[$counter - 1] + "`t" }
		else { $Output = $dcs[$counter - 1].Substring(0,28) + "...`t" }
		
		Write-Host $Output -NoNewLine
		$Line += $Output
		
		if ($UserInfo -eq "n/a") {
			$Output = "Skip! The previous query has failed on this domain controller."
			$Line += $Output
			Write-Host $Output -ForegroundColor Yellow
			if ($OutFile) { $Line >> $Export }
			Continue
		}
		
		$GivenName = $UserInfo.GivenName
		$Surname = $UserInfo.Surname
		$DistinguishedName = $UserInfo.DistinguishedName
		
		$Created = $UserInfo.Created
		if ($Created -eq 0 -or [string]::IsNullOrEmpty($Created)) { $Created = "no info available" }
		else {
			if ($LastCreated -lt $Created.ToFileTime()) { $LastCreated = $Created.ToFileTime() }
			$Created = [DateTime]::FromFileTime($Created.ToFileTime()).ToString("dd'/'MM'/'yyyy HH:mm:ss")
		}
		
		$Modified = $UserInfo.Modified
		if ($Modified -eq 0 -or [string]::IsNullOrEmpty($Modified)) { $Modified = "no info available" }
		else {
			if ($LastModified -lt $Modified.ToFileTime()) { $LastModified = $Modified.ToFileTime() }
			$Modified = [DateTime]::FromFileTime($Modified.ToFileTime()).ToString("dd'/'MM'/'yyyy HH:mm:ss")
		}
		
		$pwdLastSet = $UserInfo.pwdLastSet
		if ($pwdLastSet -eq 0 -or [string]::IsNullOrEmpty($pwdLastSet)) { $pwdLastSet = "no info available" }
		else {
			if ($PasswordLastSet -lt $pwdLastSet) { $PasswordLastSet = $pwdLastSet }
			$pwdLastSet = [DateTime]::FromFileTime($pwdLastSet).ToString("dd'/'MM'/'yyyy HH:mm:ss")
		}
		
		$AccountExpire = $UserInfo.accountExpires
		if ($AccountExpire -eq 9223372036854775807) {
			$AccountLastExpire = $AccountExpire
			$AccountExpire = "Never Expires`t"
		}
		elseif ($AccountExpire -eq 0 -or [string]::IsNullOrEmpty($AccountExpire)) {
			$AccountExpire = "no info available"
		}
		else {
			if ($AccountLastExpire -lt $AccountExpire) { $AccountLastExpire = $AccountExpire }
			$AccountExpire = [DateTime]::FromFileTime($AccountExpire).ToString("dd'/'MM'/'yyyy HH:mm:ss")
		}
		
		$PasswordExpire = $UserInfo.{msDS-UserPasswordExpiryTimeComputed}
		if ($PasswordExpire -eq 9223372036854775807) {
			$PasswordLastExpire = $PasswordExpire
			$PasswordExpire = "Never Expires"
		}
		elseif ($PasswordExpire -eq 0 -or [string]::IsNullOrEmpty($PasswordExpire)) {
			$PasswordExpire = "no info available"
		}
		else {
			if ($PasswordLastExpire -lt $PasswordExpire) { $PasswordLastExpire = $PasswordExpire }
			$PasswordExpire = [DateTime]::FromFileTime($PasswordExpire).ToString("dd'/'MM'/'yyyy HH:mm:ss")
		}
		
		if ($LogonCount -lt $UserInfo.logonCount) { $LogonCount = $UserInfo.logonCount }
		
		$Output = $Modified + "`t" + $pwdLastSet + "`t" + $AccountExpire + "`t" + $PasswordExpire
		$Line += $Output
		Write-Host $Output
		
		if ($OutFile) { $Line >> $Export }
	}
	
	########## Single user summary #########
	$Output = "`r`nSummary about user $GivenName $Surname | Login: $NetBIOSName\$User"
	Write-Host $Output
	if ($OutFile) { $Output >> $Export }
	
	$Output = "=" * $Output.Length
	Write-Host $Output
	if ($OutFile) { $Output >> $Export }
	
	# Try { $Output = (Get-TimeZone).DisplayName.Split("()")[1] } Catch {} ## Works on PowerShell 5.1
	$Output = "Time Zone Stats  : " + (Get-WmiObject -Class win32_timezone).Caption.Split("()")[1]
	Write-Host $Output
	if ($OutFile) { $Output >> $Export }
	
	if ($LastCreated -ne 0) { $Output = "Created on       : " + [DateTime]::FromFileTime($LastCreated).ToString("dd'/'MM'/'yyyy HH:mm:ss") }
	else { $Output = "Created on       : No info available" }
	Write-Host $Output
	if ($OutFile) { $Output >> $Export }
	
	if ($LastModified -ne 0) { $Output = "Last modified on : " + [DateTime]::FromFileTime($LastModified).ToString("dd'/'MM'/'yyyy HH:mm:ss") }
	else { $Output = "Last modified on : No info available" }
	Write-Host $Output
	if ($OutFile) { $Output >> $Export }
	
	if ($AccountLastExpire -eq 0) { $Output = "Account Expires  : No info available" }
	elseif ($AccountLastExpire -eq 9223372036854775807) { $Output = "Account Expires  : Never Expires" }
	else { $Output = "Account Expires  : " + [DateTime]::FromFileTime($AccountLastExpire).ToString("dd'/'MM'/'yyyy HH:mm:ss") }
	Write-Host $Output
	if ($OutFile) { $Output >> $Export }
	
	if ($PasswordLastSet -ne 0) { $Output = "Password Last Set: " + [DateTime]::FromFileTime($PasswordLastSet).ToString("dd'/'MM'/'yyyy HH:mm:ss") }
	else { $Output = "Password Last Set: No info available" }
	Write-Host $Output
	if ($OutFile) { $Output >> $Export }
	
	if ($PasswordLastExpire -eq 0) { $Output = "Password expires : No info available" }
	elseif ($PasswordLastExpire -eq 9223372036854775807) { $Output = "Password expires : Never Expires" }
	else { $Output = "Password expires : " + [DateTime]::FromFileTime($PasswordLastExpire).ToString("dd'/'MM'/'yyyy HH:mm:ss") }
	Write-Host $Output
	if ($OutFile) { $Output >> $Export }
	
	if ($LatestLogon -ne 0) { $Output = "Last log on      : " + [DateTime]::FromFileTime($LatestLogon).ToString("dd'/'MM'/'yyyy HH:mm:ss") }
	else { $Output = "Last Log on      : No info available" }
	Write-Host $Output
	if ($OutFile) { $Output >> $Export }
	
	if ($LatestbadPasswordTime -ne 0) { $Output = "Last bad password: " + [DateTime]::FromFileTime($LatestbadPasswordTime).ToString("dd'/'MM'/'yyyy HH:mm:ss") }
	else { $Output = "Last bad password: No info available" }
	Write-Host $Output
	if ($OutFile) { $Output >> $Export }
	
	if ($LatestlockoutTime) { $Output = "Last lockout     : " + [DateTime]::FromFileTime($LatestlockoutTime).ToString("dd'/'MM'/'yyyy HH:mm:ss") }
	else { $Output = "Last lockout     : No info available" }
	Write-Host $Output
	if ($OutFile) { $Output >> $Export }
	
	if ($LogonCount -eq 0) { $Output = "Logon counter    : No info available" }
	else { $Output = "Logon counter    : " + $LogonCount }
	Write-Host $Output
	if ($OutFile) { $Output >> $Export }
	
} # End single user, Details switch

## Single user, ComputerOwner switch
if ($UsersFromFile -eq "" -and $ComputerOwner.IsPresent) {
	if ([string]::IsNullOrEmpty($DistinguishedName)) {
		if ($Credential -eq "") {
			Try{ $UserInfo = Get-ADUser $User -Server $Domain -Properties GivenName, Surname, SamAccountName, DistinguishedName } Catch {}
		}
		else {
			Try{ $UserInfo = Get-ADUser $User -Server $Domain -Credential $Creds -Properties GivenName, Surname, SamAccountName, DistinguishedName } Catch {}
		}
		$GivenName = $UserInfo.GivenName
		$Surname = $UserInfo.Surname
		$SamAccountName = $UserInfo.SamAccountName
		$DistinguishedName = $UserInfo.DistinguishedName
	}
	
	$Output = "`r`nUser $GivenName $Surname | Login: $NetBIOSName\$SamAccountName owns following computers"
	Write-Host $Output
	if ($OutFile) { $Output >> $Export }
	
	$Output = "=" * $Output.Length
	Write-Host $Output
	if ($OutFile) { $Output >> $Export }
	
	$Error.Clear()
	if ($Credential -eq "") {
		Try { $Computers = Get-ADComputer -filter 'managedby -eq $DistinguishedName' -Server $Domain -Properties `
		Name, Enabled, OperatingSystem, DNSHostName, IPv4Address, whenCreated, whenChanged | Select-Object Name, Enabled, OperatingSystem, DNSHostName, IPv4Address, `
		@{Name="Object created on"; Expression={[DateTime]::FromFileTime($_.whenCreated.ToFileTime()).ToString("dd'/'MM'/'yyyy HH:mm:ss")}}, `
		@{Name="Last Logon/Change time"; Expression={[DateTime]::FromFileTime($_.whenChanged.ToFileTime()).ToString("dd'/'MM'/'yyyy HH:mm:ss")}} | Format-Table -AutoSize }
		Catch {}
	}
	else {
		Try { $Computers = Get-ADComputer -filter 'managedby -eq $DistinguishedName' -Server $Domain -Credential $Creds -Properties `
		Name, Enabled, OperatingSystem, DNSHostName, IPv4Address, whenCreated, whenChanged | Select-Object Name, Enabled, OperatingSystem, DNSHostName, IPv4Address, `
		@{Name="Object created on"; Expression={[DateTime]::FromFileTime($_.whenCreated.ToFileTime()).ToString("dd'/'MM'/'yyyy HH:mm:ss")}}, `
		@{Name="Last Logon/Change time"; Expression={[DateTime]::FromFileTime($_.whenChanged.ToFileTime()).ToString("dd'/'MM'/'yyyy HH:mm:ss")}} | Format-Table -AutoSize }
		Catch {}
	}
	
	if (-not [string]::IsNullOrEmpty($Error)) {
		Write-Host $Error -ForegroundColor Yellow
		if ($OutFile) { [String]$Error >> $Export }
	}
	elseif (-not [string]::IsNullOrEmpty($Computers)) {
		$Computers
		if ($OutFile) { $Computers >> $Export }
	}
	else {
		$Output = "`r`nThe user is not an owner of any computer.`r`n"
		Write-Host $Output -ForegroundColor Yellow
		if ($OutFile) { $Output >> $Export }
	}
}

##### Unlock single user from all domain controllers
if ($UsersFromFile -eq "" -and $Unlock.IsPresent) {
	$Output = "`r`nUnlock user ""$User"" in below domain controllers."
	Write-Host $Output
	if ($OutFile) { $Output >> $Export }
	
	$Output = "=" * $Output.Length
	Write-Host $Output
	if ($OutFile) { $Output >> $Export }
	
	$counter = 0
	foreach ($dc in $dcs) {
		$counter++
		$Output = "$counter of $TotalDCs in $dc : $User - "
		$Line = $Output
		Write-Host $Output -NoNewLine
		
		$Error.Clear()
		if ($Credential -eq "") { Try { Unlock-ADAccount -Identity $User -Server $dc } Catch {} }
		else { Try { Unlock-ADAccount -Identity $User -Server $dc -Credential $Creds } Catch {}	}
		
		if (-not [string]::IsNullOrEmpty($Error)) {
			if ($Error -like "*contact the server*") {
				$Output = "The server is down or does not have the Active Directory Web Services running."
				$Line += $Output
				Write-Host $Output -ForegroundColor Red
				if ($OutFile) { $Line >> $Export }
			}
			elseif ($Error -like "*find an object*") {
				$Output = "The user is not present on this domain controller."
				$Line += $Output
				Write-Host $Output -ForegroundColor Yellow
				if ($OutFile) { $Line >> $Export }
			}
			else {
				$Line += $Error
				Write-Host $Error -ForegroundColor Red
				if ($OutFile) { $Line >> $Export }
			}
			Continue
		}
		
		$Output = "The user has been unlocked."
		$Line += $Output
		Write-Host $Output
		if ($OutFile) { $Line >> $Export }
	}
} # End single user, Unlock switch

## Miltiple users from file, Details switch
if ($UsersFromFile -ne "" -and ($Details.IsPresent -or !$Unlock.IsPresent)) {
	Try { $Users = Get-Content $UsersFromFile -ErrorAction Stop | Where-Object {$_ -ne ""}}
	Catch {
		$Output = "`r`n" + $_ + "`r`n"
		Write-Host $Output -ForegroundColor Red
		if ($OutFile) { $Output >> $Export }
		EndScript $StartTime
	}
	
	if ($PDC.IsPresent) {$Domain = $PrimaryDC}
	$Output = "Query users from file ""$UsersFromFile"" in server/domain: $Domain`r`n"
	Write-Host $Output
	if ($OutFile) { $Output >> $Export }
	
	$TotalUsers = $Users.Count
	$Output = "No.=$TotalUsers`t" + "Users List`t" + "Enabled`t" + "Locked`t" + "Locked out [PDC!]`t" + "Bad Password [PDC!]`t" + "Count`t" + "Last Logon [NoRepl]`t" + "Last Modified [NoRepl]"
	Write-Host $Output
	if ($OutFile) { $Output >> $Export }
	
	$Output = "=======`t==========`t" + "=======`t" +"======`t" + "===================`t" + "===================`t" + "=====`t" + "===================`t" + "======================"
	Write-Host $Output
	if ($OutFile) { $Output >> $Export }
	
	$counter = 0
	$i = 0
	foreach ($User in $Users) {
		$counter++
		$Output = "  " + $counter + "`t"
		$Line = $Output
		Write-Host $Output -NoNewLine
		
		if ($User.Length -lt 8) { $Output = "$User`t`t" }
		elseif ($User.length -lt 16) { $Output = "$User`t" }
		else { $Output = $User.Substring(0,12) + "...`t" }
		
		$Line += $Output
		Write-Host $Output -NoNewLine
		
		$Error.Clear()
		if ($Credential -eq "") {
			Try {
				[Array]$AllUsers += Get-ADUser $User -Server $Domain -Properties SamAccountName, `
				Enabled, LockedOut, lockoutTime, badPasswordTime, badPwdCount, lastLogonTimestamp, GivenName, Surname, Created, Modified, pwdLastSet, accountExpires, logonCount, msDS-UserPasswordExpiryTimeComputed
			} 	## No replica properties across DCs - modified[pdc], lockoutTime [pdc], badPasswordTime[pdc], badPwdCount [pdc]
			Catch {}
		}
		else {
			Try {
				[Array]$AllUsers += Get-ADUser $User -Server $Domain -Credential $Creds -Properties SamAccountName, `
				Enabled, LockedOut, lockoutTime, badPasswordTime, badPwdCount, lastLogonTimestamp, GivenName, Surname, Created, Modified, pwdLastSet, accountExpires, logonCount, msDS-UserPasswordExpiryTimeComputed
			}
			Catch {}
		}
		
		if (-not [string]::IsNullOrEmpty($Error)) {
			if ($Error -like "*contact the server*") {
				$Output = "in $Domain - The server is down or does not have the Active Directory Web Services running."
				$Line += $Output
				Write-Host $Output -ForegroundColor Red
				if ($OutFile) { $Line >> $Export }
			}
			elseif ($Error -like "*find an object*") {
				$Output = "in $Domain - Does not exist."
				$Line += $Output
				Write-Host $Output -ForegroundColor Yellow
				if ($OutFile) { $Line >> $Export }
			}
			else {
				$Output = "in $Domain - $Error"
				$Line += $Output
				Write-Host $Output -ForegroundColor Red
				if ($OutFile) { $Line >> $Export }
			}
			Continue
		}
		
		$UserInfo = $AllUsers[$i++]
		$Enabled = $UserInfo.Enabled
		$LockedOut = $UserInfo.LockedOut
		
		$lockoutTime = $UserInfo.lockoutTime
		if ($lockoutTime -eq 0 -or [string]::IsNullOrEmpty($lockoutTime)) { $lockoutTime = "no info available" }
		else { $lockoutTime = [DateTime]::FromFileTime($lockoutTime).ToString("dd'/'MM'/'yyyy HH:mm:ss") }
		
		$badPasswordTime = $UserInfo.badPasswordTime
		if ($badPasswordTime -eq 0 -or [string]::IsNullOrEmpty($badPasswordTime)) { $badPasswordTime = "no info available" }
		else { $badPasswordTime = [DateTime]::FromFileTime($badPasswordTime).ToString("dd'/'MM'/'yyyy HH:mm:ss") }
		
		$badPwdCount = $UserInfo.badPwdCount
		if ([string]::IsNullOrEmpty($badPwdCount)) { $badPwdCount = "n/a" }
		
		$lastLogon = $UserInfo.lastLogonTimestamp
		if ($lastLogon -eq 0 -or [string]::IsNullOrEmpty($lastLogon)) { $lastLogon = "no info available" }
		else { $lastLogon = [DateTime]::FromFileTime($lastLogon).ToString("dd'/'MM'/'yyyy HH:mm:ss") }
		
		$Modified = $UserInfo.Modified
		if ($Modified -eq 0 -or [string]::IsNullOrEmpty($Modified)) { $Modified = "no info available" }
		else { $Modified = [DateTime]::FromFileTime($Modified.ToFileTime()).ToString("dd'/'MM'/'yyyy HH:mm:ss") }
		
		$Output = "$Enabled`t"
		$Line += $Output
		if ($Enabled) { Write-Host $Output -NoNewLine }
		else { Write-Host $Output -NoNewLine -ForegroundColor Red }
		
		if ($LockedOut) {
			$Output = " YES`t"
			$Line += $Output
			Write-Host $Output -NoNewLine -ForegroundColor Red
		}
		else {
			$Output = " NO`t"
			$Line += $Output
			Write-Host $Output -NoNewLine
		}
		
		$Output = "$lockoutTime`t"
		$Line += $Output
		Write-Host $Output -NoNewLine
		
		$Output = "$badPasswordTime`t"
		$Line += $Output
		Write-Host $Output -NoNewLine
		
		$Output = "$badPwdCount`t"
		$Line += $Output
		if ($badPwdCount -gt 0) { Write-Host $Output -NoNewLine -ForegroundColor Red }
		else { Write-Host $Output -NoNewLine }
		
		$Output = "$lastLogon`t"
		$Line += $Output
		Write-Host $Output -NoNewLine
		
		$Output = "$Modified"
		$Line += $Output
		Write-Host $Output
		if ($OutFile) { $Line >> $Export }
	}
} # End users from file, Details switch

## Unlock users from file.
if (($Unlock.IsPresent -and $UsersFromFile -ne "") ) {
	if ($PDC.IsPresent) { $Domain = $PrimaryDC }
	
	if ($UsersFromFile -ne "" -and ($Details.IsPresent -or !$Unlock.IsPresent) -and [string]::IsNullOrEmpty($AllUsers)) {
		$Output = "`r`nNone of the users in file ""$UsersFromFile"" are present in server/domain: $Domain`r`n"
		Write-Host $Output -ForegroundColor Yellow
		if ($OutFile) { $Output >> $Export }
		EndScript $StartTime
	}
	elseif ([string]::IsNullOrEmpty($AllUsers)) {
		Try { $Users = Get-Content $UsersFromFile -ErrorAction Stop | Where-Object {$_ -ne ""}}
		Catch {
			[String]$Output = "`r`n$_`r`n"
			Write-Host $Output -ForegroundColor Red
			if ($OutFile) { $Output >> $Export }
			EndScript $StartTime
		}
		$Output = "`r`nTotal number of preset users in file ""$UsersFromFile""" + ": " + $Users.Count + " | Unlock them in server/domain: $Domain"
	}
	else {
		$Users = $AllUsers.SamAccountName
		$Output = "`r`nTotal number of found accounts: " + $Users.Count + " - Unlock them in server/domain: $Domain"
	}
	
	$Line = $Output
	Write-Host $Output
	if ($OutFile) { $Line >> $Export }
	
	$Output = "=" * $Output.Length
	Write-Host $Output
	if ($OutFile) { $Output >> $Export }
	
	$counter = 0
	foreach ($User in $Users) {
		$counter++
		$Output = [String]$counter + " of " + $Users.Count + " in $Domain : $User - "
		$Line = $Output
		Write-Host $Output -NoNewLine
		
		$Error.Clear()
		if ($Credential -eq "") { Try { Unlock-ADAccount -Identity $User -Server $Domain } Catch {} }
		else { Try { Unlock-ADAccount -Identity $User -Server $Domain -Credential $Creds } Catch {} }
		
		if (-not [string]::IsNullOrEmpty($Error)) {
			if ($Error -like "*contact the server*") {
				$Output = "The server is down or does not have the Active Directory Web Services running."
				$Line += $Output
				Write-Host $Output -ForegroundColor Red
				if ($OutFile) { $Line >> $Export }
			}
			elseif ($Error -like "*find an object*") {
				$Output = "Does not exist."
				$Line += $Output
				Write-Host $Output -ForegroundColor Yellow
				if ($OutFile) { $Line >> $Export }
			}
			else {
				$Output = $Error
				$Line += $Output
				Write-Host $Output -ForegroundColor Red
				if ($OutFile) { $Line >> $Export }
				Write-Host  -ForegroundColor Red
			}
			Continue
		}
		
		$Output = "The account has been unlocked"
		$Line += $Output
		Write-Host $Output
		if ($OutFile) { $Line >> $Export }
	}
}

EndScript $StartTime

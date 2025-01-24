<#
.SYNOPSIS
Check users details in all domain controllers.
Display basic lockout information, modify time, last logon, password set, etc.

.DESCRIPTION
Get basic user stats - lockout, modify time, last logon, password set, etc.

.Link
https://ps-solutions.net/index.php/userinfo/

.EXAMPLE
.\UserInfo.ps1 -User evelin.banev
#>

<# Examples of time stamps, replication and no replication values accros domain controllers.

accountExpires - Replicated to all DCs - Attribute controlling account expiration.
badPasswordTime - Not replicated - DC-specific, not global.
Created - Replicated to all DCs - Timestamp of object creation.
createTimeStamp - Replicated to all DCs - Similar to Created.
LastBadPasswordAttempt - Not replicated - Same as badPasswordTime.
lastLogon - Not replicated - DC-specific logon time.
LastLogonDate - Selectively replicated - Computed using lastLogonTimestamp.
lastLogonTimestamp - Selectively replicated - Replicated to reduce replication traffic.
Modified - Replicated to all DCs - Tracks object modifications.
modifyTimeStamp - Replicated to all DCs - Similar to Modified.
PasswordLastSet - Replicated to all DCs on change - Changes only when the password is updated.
pwdLastSet - Replicated to all DCs on change - Same as PasswordLastSet.
whenChanged - Replicated to all DCs - Tracks object change timestamp.
whenCreated - Replicated to all DCs - Timestamp of object creation.

#>

Param(
    [Parameter(Mandatory=$true)][string]$User,
    [Parameter(Mandatory=$False)][string]$Server,
    [Parameter(Mandatory=$False)][string]$Domain
)

if ($Server -and $Domain) {
    Write-Output "You cannot specify both Server and Domain. Please provide only one."
}

Try {
    Import-Module ActiveDirectory -ErrorAction Stop
}
Catch {
    Write-Host $_ -ForegroundColor Red
    return "Please Install AD-DS module first."
}

if ($Server -and $Domain) {
    return "You cannot specify both Server and Domain. Please provide only one."
}
elseif (-not ($Server -or $Domain)) {
    # $UserDomain = Get-ADDomain -Current LoggedOnUser -ErrorAction Stop
    $UserDomain = ((whoami /fqdn 2>NULL) -split "," -match "\S" | Where-Object {$_.StartsWith("DC=")} | ForEach-Object {$_.SubString(3)}) -join "."

    if (-not $UserDomain) {
        return "Unable to get current user domain."
    }
    else {
        $Server = $UserDomain
    }
}
elseif ($Domain) {
    $Server = $Domain
}

Write-Host "Get Basic Domain Info . . .`r`n"

$DomainInfo = Get-ADDomain -Server $Server
$ForestInfo = Get-ADForest -Server $Server

$DCs = $DomainInfo.ReplicaDirectoryServers + "fake2" + $DomainInfo.ReadOnlyReplicaDirectoryServers

$TotalDCs = $dcs.Count
$PrimaryDC = $DomainInfo.PDCEmulator
$NetBIOSName = $DomainInfo.NetBIOSName

$Collection = @()

$Enabled, $Locked, $DisplayName, $UserName, $EmailAddress, $LockoutTime , $BadPassTime , $LastLogon, $Created, $Modified, $PasswordLastSet, $AccountExpires, $PasswordExpires = $null
$BadPass, $Logons = 0

Write-Host "Quering $($dcs.Count) servers:`r`n"

foreach ($dc in $DCs) {
    switch ($dc) {
        $ForestInfo.SchemaMaster { Write-Host "$dc - Schema Master" -ForegroundColor Cyan }
        $ForestInfo.DomainNamingMaster { Write-Host "$dc - Domain Naming Master" -ForegroundColor Cyan }
        $DomainInfo.PDCEmulator { Write-Host "$dc - PDC Emulator" -ForegroundColor Yellow }
        $DomainInfo.RIDMaster { Write-Host "$dc - RID Master" -ForegroundColor Yellow }
        $DomainInfo.InfrastructureMaster { Write-Host "$dc - Infrastructure Master" -ForegroundColor Yellow }
        default {
            if ($DomainInfo.ReplicaDirectoryServers -contains $dc) { Write-Host "$dc - Replica DC" -ForegroundColor Green }
            elseif ($DomainInfo.ReadOnlyReplicaDirectoryServers -contains $dc) { Write-Host "$dc - Read Only DC" }
            else { Write-Host "$dc - Unknown DC" -ForegroundColor Red}
        }
    }

    $query = $null

    Try {
        $query = Get-ADUser -Filter "DisplayName -eq '$User' -or SamAccountName -eq '$User' -or EmailAddress -eq '$User'" -Server $dc -Properties Enabled, LockedOut, lockoutTime, badPasswordTime, badPwdCount, lastLogon, SamAccountName, EmailAddress, DisplayName, Created, Modified, PasswordLastSet, accountExpires, logonCount, msDS-UserPasswordExpiryTimeComputed -ErrorAction Stop
        $query = $query | Select-Object -Property Enabled, LockedOut, badPwdCount, logonCount, lockoutTime, badPasswordTime, lastLogon, SamAccountName, EmailAddress, DisplayName, Created, Modified, PasswordLastSet, accountExpires, msDS-UserPasswordExpiryTimeComputed
    }
    Catch {
        $Collection += [PSCustomObject]@{
            Server          = $dc.Split(".")[0]
            DisplayName     = "Error"
            UserName        = "Error"
            EmailAddress    = "Error"
            Enabled         = "Error"
            Locked          = "Error"
            BadPass         = "Error"
            Logons          = "Error"
            LockoutTime     = "Error"
            BadPassTime     = "Error"
            LastLogon       = "Error"
            Created         = "Error"
            Modified        = "Error"
            PasswordLastSet = "Error"
            AccountExpires  = "Error"
            PasswordExpires = "Error"
        }
    
        Continue
    }

    $DisplayName = $query.DisplayName
    $UserName = $query.SamAccountName
    $EmailAddress = $query.EmailAddress

    $BadPass += [int]$query.badPwdCount
    $Logons += [int]$query.logonCount

    if ($query.LockedOut -gt $LockoutTime) { $LockoutTime = $query.lockoutTime }

    if ($query.lockoutTime -gt $LockoutTime) { $LockoutTime = $query.lockoutTime }
    if ($query.badPasswordTime -gt $BadPassTime) { $BadPassTime = $query.badPasswordTime }
    if ($query.lastLogon -gt $LastLogon) { $LastLogon = $query.lastLogon }
    if ($query.Created -gt $Created) { $Created = $query.Created }
    if ($query.Modified -gt $Modified) { $Modified = $query.Modified }
    if ($query.PasswordLastSet -gt $PasswordLastSet) { $PasswordLastSet = $query.PasswordLastSet }
    if ($query.accountExpires -gt $AccountExpires) { $AccountExpires = $query.accountExpires }
    if ($query.'msDS-UserPasswordExpiryTimeComputed' -gt $PasswordExpires) { $PasswordExpires = $query.'msDS-UserPasswordExpiryTimeComputed' }

    $Collection += [PSCustomObject]@{
        Server          = $dc.Split(".")[0]
        DisplayName     = $query.DisplayName
        UserName        = $query.SamAccountName
        EmailAddress    = $query.EmailAddress
        Enabled         = $query.Enabled
        Locked          = $query.LockedOut
        BadPass         = $query.badPwdCount
        Logons          = $query.logonCount
        LockoutTime     = if (-not $query.lockoutTime) {""} elseif ($query.lockoutTime -eq 9223372036854775807) {"Unknown"} else { [datetime]::FromFileTimeUtc($query.lockoutTime).ToLocalTime() }
        BadPassTime     = if (-not $query.badPasswordTime) {""} elseif($query.badPasswordTime -eq 9223372036854775807) {"Unknown"} else { [datetime]::FromFileTimeUtc($query.badPasswordTime).ToLocalTime() }
        LastLogon       = if (-not $query.lastLogon) {""} elseif ($query.lastLogon -eq 9223372036854775807) {"Unknown"} else { [datetime]::FromFileTimeUtc($query.lastLogon).ToLocalTime() }
        Created         = $query.Created
        Modified        = $query.Modified # Derived from 'whenChanged', already in local time
        PasswordLastSet = if (-not $query.PasswordLastSet) {""} else { $query.PasswordLastSet }
        AccountExpires  = if (-not $query.accountExpires) {"Expired"} elseif ($query.accountExpires -eq 9223372036854775807) {"Never"} else { [datetime]::FromFileTimeUtc($query.accountExpires).ToLocalTime() }
        PasswordExpires = if (-not $query.'msDS-UserPasswordExpiryTimeComputed') {"Expired"} elseif($query.'msDS-UserPasswordExpiryTimeComputed' -eq 9223372036854775807) {"Never"} else { [datetime]::FromFileTimeUtc($query.'msDS-UserPasswordExpiryTimeComputed').ToLocalTime() }
    }
}

# Get the result only if the account it disabled.
if ($Collection | Where-Object {$_.Enabled -eq $False}) { $Enabled = $False }
elseif ($Collection | Where-Object {$_.Enabled -eq $True}) { $Enabled = $True }

# Get the result only if the account it locked.
if ($Collection | Where-Object {$_.Locked -eq $True}) { $Locked = $True }
elseif ($Collection | Where-Object {$_.Locked -eq $False}) { $Locked = $False }

$UserInfo = [PSCustomObject]@{
    DisplayName     = $DisplayName
    UserName        = $UserName
    EmailAddress    = $EmailAddress
    Enabled         = $Enabled
    Locked          = $Locked
    BadPass         = $BadPass
    Logons          = $Logons
    LockoutTime     = if (-not $LockoutTime) {""} elseif ($LockoutTime -eq 9223372036854775807) {"Unknown"} else { [datetime]::FromFileTimeUtc($LockoutTime).ToLocalTime() }
    BadPassTime     = if (-not $BadPassTime) {""} elseif($BadPassTime -eq 9223372036854775807) {"Unknown"} else { [datetime]::FromFileTimeUtc($BadPassTime).ToLocalTime() }
    LastLogon       = if (-not $LastLogon) {""} elseif ($LastLogon -eq 9223372036854775807) {"Unknown"} else { [datetime]::FromFileTimeUtc($LastLogon).ToLocalTime() }
    Created         = $Created
    Modified        = $Modified
    PasswordLastSet = if (-not $PasswordLastSet) {""} else { $PasswordLastSet }
    AccountExpires  = if (-not $AccountExpires) {"Expired"} elseif ($AccountExpires -eq 9223372036854775807) {"Never"} else { [datetime]::FromFileTimeUtc($AccountExpires).ToLocalTime() }
    PasswordExpires = if (-not $PasswordExpires) {"Expired"} elseif($PasswordExpires -eq 9223372036854775807) {"Never"} else { [datetime]::FromFileTimeUtc($PasswordExpires).ToLocalTime() }
}

$Width = $Host.UI.RawUI.BufferSize.Width
$Height = $Host.UI.RawUI.BufferSize.Height

$Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size(1024, $Height)

$output = $Collection | Format-Table -Property * -AutoSize | Out-String
$MaxWidth = ($output -split "`n" | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum + 2

# Set the console buffer width to fit the output
$Host.UI.RawUI.BufferSize = New-Object Management.Automation.Host.Size([math]::Max($MaxWidth, $Width), $Heigh)

$Collection | Format-Table -Property * -AutoSize

$UserInfo | Format-List

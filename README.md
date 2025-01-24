Get user statistics from Active Directory.

Usage:
.\UserInfo.ps1 john.smith@mydomain.com
.\UserInfo.ps1 john.smith
.\UserInfo.ps1 "John Smith"

**Example Output:**

DisplayName     : John Smith
UserName        : john.smith
EmailAddress    : john.smith@mydomain.com
Enabled         : True
Locked          : False
BadPass         : 2
Logons          : 1865
LockoutTime     : 
BadPassTime     : 2025-01-24 11:06:42
LastLogon       : 2025-01-24 11:06:47
Created         : 2020-12-10 11:48:10
Modified        : 2025-01-21 17:57:58
PasswordLastSet : 2024-11-11 14:05:56
AccountExpires  : Never
PasswordExpires : 2025-02-09 14:05:56

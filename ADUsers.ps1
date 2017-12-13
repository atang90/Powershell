# ADUsers.ps1 
# Andrew, 12/13/2017 (last revision)

# Description of intent:
# Script that exports AD to a csv file in c:\tnsctemp 

# Import Active Directory Module
Import-Module activedirectory -ErrorAction Stop

# Get AD Users | Select for specific properties
Get-ADUser -Filter 'enabled -eq $true' -Properties CN,GivenName,SurName,DisplayName,SamAccountName,EmailAddress,LastLogon,MemberOf |
Select -Property CN,GivenName,SurName,DisplayName,SamAccountName,EmailAddress, @{name=”LastLogon”;expression={if ($_.LastLogon -eq 0) {"Null"} else {[DateTime]::FromFileTime($_.LastLogon)}}},@{name=”MemberOf”;expression={$_.memberof -join “;”}}|

# Export to csv file 
Export-CSV "C:\tnsctemp\ADUsers.csv" -NoTypeInformation -Encoding UTF8

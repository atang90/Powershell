# BDRSetup.ps1 
# Andrew, 09/06/2017 (last revision)

# Description of intent / purpose / general technique
# Powershell script to automate BDR setup - the script checks and then performs the following:
    # Change Time Zone
    # Enable RDP
    # Disable Firewall
    # Disable UAC
    # Disable IE SEC
    # Install Telnet Client
    # Disable Server Manager Open on Logon
    # Add svc_storeit Account
    # Add Hyper-V Role  
    # Install Google Chrome 
    # Copy Files From tnsc-dc11 To Desktop 
    # Change Computer Name

# Enable strictmode, which prevents whole categories of bugs
Set-StrictMode -Version Latest

# Change Time Zone
    function TZ()
    {
        Set-TimeZone -Name "Eastern Standard Time"
    } 

# Enable RDP

    function EnableRDP()
    {
	    function Get-RemoteDesktopConfig()
	    {
	        if ((Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server').fDenyTSConnections -eq 1) 
            {
                Write-Host "Current RDP Status: Connections Not Allowed" -ForegroundColor Green
            }
	        elseif ((Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication -eq 1) 
            {
                Write-Host "Current RDP Status: Only Secure Connections Allowed" -ForegroundColor Green
            } 
	        else 
            {
                Write-Host "Current RDP Status: All Connections Allowed" -ForegroundColor Green
            }
	    } 
	
        Get-RemoteDesktopConfig
	    $RemoteConfig = Get-RemoteDesktopConfig
	    $WatWeWnt = "Current RDP Status: All Connections Allowed"

	    if ($RemoteConfig -ne $WatWeWnt)
	    {
		    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" –Value 0 -erroraction silentlycontinue
            Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" –Value 0 -erroraction silentlycontinue
		    Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
	    }
	    Write-Host "RDP Is Already Enabled" -ForegroundColor Green
    }
  

# Disable Firewall

    function DisableFirewall()
	{
        if ((netsh advfirewall show publicprofile state) -like "*ON*")
        {
            Set-NetFirewallProfile -Profile Public -Enabled False
            Write-Host “Public Profile Firewall Has Been Disabled” -ForegroundColor Green
        }
        else
        {
            Write-Host “Public Profile Firewall Has Already Been Disabled” -ForegroundColor Green
        }

        if ((netsh advfirewall show privateprofile state) -like "*ON*")
        {
            Set-NetFirewallProfile -Profile Private -Enabled False
            Write-Host “Private Profile Firewall Has Been Disabled” -ForegroundColor Green
        }
        else
        {
            Write-Host “Private Profile Firewall Has Already Been Disabled” -ForegroundColor Green
        }
	}

# Disable UAC

    function DisableUAC()
    {
	    $Stat = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System").EnableLUA
        if ($Stat -ne 0)
        {
            Set-ItemProperty -Path “HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System” -Name “EnableLUA” -Value 0 -erroraction silentlycontinue
            Write-Host “User Account Control Settings Set To Never Notify” -ForegroundColor Green
        }
        else
        {
            Write-Host “User Account Control Settings Already Set To Never Notify” -ForegroundColor Green
        }
    }

# Disable IE SEC

    function Disable-IESEC()
    {
        $AdminKey = “HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}”
        $UserKey = “HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}”
        $AdmnSec = (Get-ItemProperty -Path $AdminKey).IsInstalled        
        $UsrSec = (Get-ItemProperty -Path $UserKey).IsInstalled 

        if ($AdmnSec -ne 0)
            {
                Set-ItemProperty -Path $AdminKey -Name “IsInstalled” -Value "0" -erroraction silentlycontinue
            }

        if ($UsrSec -ne 0)
            {
                Set-ItemProperty -Path $UserKey -Name “IsInstalled” -Value "0" -erroraction silentlycontinue
            }
        Write-Host “IE Enhanced Security Configuration (ESC) Has Been Disabled” -ForegroundColor Green
    }

# Install Telnet Client

    function InTelCl()
    {
	    if((Get-WindowsFeature -Name telnet-client).InstallState -EQ "Available")
        {
            Import-Module servermanager
            Install-WindowsFeature –Name telnet-client
	        Write-Host "Telnet Client Has Been Installed” -ForegroundColor Green
	    }
        else
        {
            Write-Host "Telnet Client Already Installed" -ForegroundColor Green
   
        }
    }

# Disable Server Manager Open on Logon

    function DisableServerManager() 
	{
        $DNOMan = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\ServerManager").DoNotOpenServerManagerAtLogon 
        if ($DNOMan -ne 1)
        {
    	    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\ServerManager" -Name "DoNotOpenServerManagerAtLogon" -Value 1
    	    Stop-Process -Name Explorer
            Write-Host "Server Manager Open On Logon Has Been Disabled" -ForegroundColor Green
	    }
        else
        {
            Write-Host "Server Manager Open On Logon Has Already Been Disabled" -ForegroundColor Green
        }
    }

# Add svc_storeit Account  

    function Addsvc_storeit()
	{
	    if (!(Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount = True"  | Where {$_.Name -like "*svc_storeit*"}))
         {
            $name = 'svc_storeit'
	        $server =[adsi]"WinNT://$env:computername"
	        $user=$server.Create("User","$name")
	        $password = 'TN$CM$P#1'
	        $user.SetPassword($password)
	        $user.SetInfo()
	        $user.Put('Description','svc_storeit')
	        $flag=$user.UserFlags.Value -bor 0x10000
	        $user.put('userflags',$flag)
	        $user.SetInfo() 
	        $group=[adsi]"WinNT://$env:computername/Administrators,Group"
	        $group.Add($user.path)
	        Write-Host “Svc_Storeit Account Has Been Added” -ForegroundColor Green
	        Write-Host “Svc_Storeit Account Has Been Added To Administrator Group” -ForegroundColor Green
        }
        else
        {
        write-host "svc_storeit account already exists" -ForegroundColor Green
        }
    }

# Add Hyper-V Role

    function AddHyperV()
	{
	    if((Get-WindowsFeature -Name Hyper-V).InstallState -EQ "Available")
        {
            Install-WindowsFeature –Name Hyper-V -IncludeManagementTools
	        Write-Host "Hyper-V Role Has Been Added” -ForegroundColor Green
	    }
        else
        {
            Write-Host "Hyper-V Role Already Installed" -ForegroundColor Green
        }
    }

# Install Google Chrome

    function InstallChrome()
    {
       if((Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName | Where DisplayName) -like "*Google Chrome*")
        {
	        Write-Host "Google Chrome Already Installed" -ForegroundColor Green
        }
        else
        {
	        $LocalTempDir = $env:TEMP
	        $ChromeInstaller = "ChromeInstaller.exe"
	        (new-object System.Net.WebClient).DownloadFile('http://dl.google.com/chrome/install/375.126/chrome_installer.exe', "$LocalTempDir\$ChromeInstaller") 
	        & "$LocalTempDir\$ChromeInstaller" /silent /install 
	        $Process2Monitor = "ChromeInstaller" 
	        Do 
	        { 
	            $ProcessesFound = (Get-Process | Where-Object {$Process2Monitor -contains $_.Name} | Select-Object -ExpandProperty Name)
	            If ($ProcessesFound) 
		        { 
		            "Still running: $($ProcessesFound -join ', ')" | Write-Host; Start-Sleep -Seconds 2 
		        } 
	            else 
		        { 
		            rm "$LocalTempDir\$ChromeInstaller" -ErrorAction SilentlyContinue 
		        } 
	
	        } 
	    Until (!$ProcessesFound)
        Write-Host “Google Chrome Has Been Installed” -ForegroundColor Green
        }
    }

# Copy Files From tnsc-dc11 To Desktop

    function Cpyfiles()
	{
        Import-Module BitsTransfer
	    New-PSDrive -Name M -PSProvider FileSystem -Root \\tnsc-dc11\mediakits -Credential (Get-Credential)
	    
        if ((Test-Path "C:\Users\Administrator\Desktop\Core-X64-6.1.1.137.exe") -eq $False)
        {
            Start-BitsTransfer -Source '\\tnsc-dc11\mediakits\MSP\StoreIT Tools\Rapid Recovery\RR Core\6.1.3.100 Core\Core-X64-6.1.3.100.exe' -Destination 'C:\Users\Administrator\Desktop\Core-X64-6.1.3.100.exe' -Description "Copy RR6 Core Installer to Desktop"
	        Write-Host “Core-X64.61.1.3.100.exe Has Been Copied To Desktop” -ForegroundColor Green
        }
        else
        {
            Write-Host "Core-X64.6.1.3.100.exe Has Already Been Copied To Desktop" -ForegroundColor Green
        }

        if ((Test-Path "C:\Users\Administrator\Desktop\Software-The Network Support Company.lic") -eq $False)
        {
            Start-BitsTransfer -Source '\\tnsc-dc11\mediakits\MSP\StoreIT Tools\Rapid Recovery\RR License\Software-The Network Support Company.lic' -Destination 'C:\Users\Administrator\Desktop\Software-The Network Support Company.lic' -Description "Copy RR License to Desktop"
	        Write-Host “Software-The Network Support Company.lic Has Been Copied To Desktop” -ForegroundColor Green
        }
        else
        {
            Write-Host "Software-The Network Support Company.lic Has Already Been Copied To Desktop" -ForegroundColor Green
        }

        if ((Test-Path "C:\Users\Administrator\Desktop\HP_Sum2017.04.iso") -eq $False)
        {
            Start-BitsTransfer -Source '\\tnsc-dc11\mediakits\MSP\StoreIT Tools\HP Service Pack\SPP2017.04.iso' -Destination 'C:\Users\Administrator\Desktop\HP_Sum2017.04.iso' -Description "Copy HP Sum to Desktop"
	        Write-Host “HP Sum Has Been Copied To Desktop” -ForegroundColor Green
        }
        else
        {
            Write-Host "HP Sum Has Already Been Copied To Desktop" -ForegroundColor Green
        }
        Remove-PSDrive -Name M
    }

# Change Computer Name

    function ChgNme()
	{
        $continue = Read-Host -Prompt "Do You Want To Change Computer Name? (Y/N):"
        If(($continue -eq "Y")-or($continue -eq "y"))
		{ 
	        $computerName = GWMI Win32_ComputerSystem 
	        Write-Host "Current Computer Name:" $computerName -ForegroundColor Green
	        $name = Read-Host -Prompt "Enter New Computer Name:" -ForegroundColor Green
	        Write-host "New Computer Name " $Name -ForegroundColor Green
	        $Go=Read-Host -Prompt "Proceed With Computer Name Change? (Y/N):" 
	        If(($Go -eq "Y")-or($Go -eq "y"))
		    {
		        $computername.Rename($name)
		    }
	        $Reboot=Read-host -Prompt "Computer Must Be Restarted For All Changes To Take Effect. Do You Want To Restart Now? (Y/N):" 
	        If(($Reboot -eq "Y")-or($Reboot -eq "y"))
		    {
		        restart-computer 
		    }
        }
        elseif(($continue -eq "N")-or($continue -eq "n"))
        {
            $Reboot=Read-host -Prompt "Computer Must Be Restarted For All Changes To Take Effect. Do You Want To Restart Now? (Y/N):" 
	        If(($Reboot -eq "Y")-or($Reboot -eq "y"))
		    {
		        restart-computer 
		    }
        }
    }

$OSVersion = (get-itemproperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName
    If($OSVersion -like "*Server*")
    {
        TZ
        EnableRDP
        DisableFirewall
        DisableUAC
        Disable-IESEC
        InTelCl
        DisableServerManager 
        Addsvc_storeit
        InstallChrome -erroraction silentlycontinue
        AddHyperV
        Cpyfiles
        ChgNme -erroraction silentlycontinue
    }
    else
    {
        Write-Host "This Script Is Intended For Server Setup - Please Run Script On A Server OS" -ForegroundColor Green
    }

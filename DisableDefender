# DisableDefender.ps1 
# Andrew, 11/27/2018 (last revision)

# Description of intent / purpose / general technique
# Powershell script to Disable Windows Defender
    # Checks for Windows 7 or 10:
        # Checks Win 10 for DisableAntiSpyware Registry Entry 
            # Adds Entry if missing -- Flips to 1 if Entry exists and is 0
        
        # Checks Win 7 for DisableAntiSpyware Value 
            #Flips to 1 if 0

# Enable strictmode, which prevents whole categories of bugs

Set-StrictMode -Version Latest
function Test-RegistryValue() 
{
    param (
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$Path,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$Value
    )
    try 
    {
        Get-ItemProperty -Path $Path -Name $Value -ErrorAction Stop | Out-Null
        return $true
    }
    catch 
    {
        return $false
    }

}

function MachOS()
{
    $MachOS = (Get-WmiObject Win32_OperatingSystem).Caption 
    if ($MachOS -like  "Microsoft Windows 10*")
    {
        $Win10Path = 'HKLM:\Software\Policies\Microsoft\Windows Defender'
        if (!(Test-RegistryValue -Path $Win10Path -Value "DisableAntiSpyware"))
        {   
            Write-Host "Machine OS is " $MachOS -ForegroundColor Green
            Write-Host "Disabling Windows Defender..." -ForegroundColor Green
            New-ItemProperty -Path $Win10Path -Name "DisableAntiSpyware" -Value 1 -PropertyType "DWord"
        }
         
        elseif ((Test-RegistryValue -Path $Win10Path -Value "DisableAntiSpyware") -and ((Get-ItemProperty -Path $Win10Path).DisableAntiSpyware -eq '0'))
        {
            Set-ItemProperty -Path $Win10Path -Name "DisableAntiSpyware" -Value 1
        }
        else
        {
            Write-Host "Windows Defender is Already Disabled" -ForegroundColor Yellow
        }
    }

    elseif ($MachOS -like "Microsoft Windows 7*")
    {
        $Win7Path ='HKLM:\Software\Microsoft\Windows Defender'
        if ((Get-ItemProperty -Path $Win7Path).DisableAntiSpyware -eq '0')
        {
        Write-Host "Machine OS is " $MachOS -ForegroundColor Green
        Write-Host "Disabling Windows Defender..." -ForegroundColor Green
        Set-ItemProperty -Path $Win7Path -Name "DisableAntiSpyware" -Value 1 
        }

        else
        {
            Write-Host "Windows Defender is Already Disabled" -ForegroundColor Yellow
        }
    }
}

MachOS

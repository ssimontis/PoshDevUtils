#Requires -Version 5.0
#Requires -RunAsAdministrator

Set-StrictMode -Version Latest
Set-ExecutionPolicy Unrestricted -Scope CurrentUser -Confirm

Import-Module -Name PowerShellGet 
Import-Module -Name Carbon
Import-Module -Name PSReadLine
Import-Module -Name IISAdministration
Import-Module -Name 'posh-git'
Import-Module -Name PoshDevUtils

#HyperV setup
$wifi = Get-NetAdapter -Name 'Wi-Fi'
$eth = Get-NetAdapter -Name 'Ethernet'

$diskDirectory = Install-CDirectory -Path E:\iso\disks
$isoFile = E:\iso\en_windows_10_business_edition_version_1809_updated_april_2019_x64_dvd_62b47844.iso
$vmDirectory = Install-CDirectory -Path E:\iso\vm

$wifiSwitch = New-VMSwitch -Name ExternalWirelessSwitch -NetAdapterName $wifi.Name -AllowManagementOS $true

$vm = New-VM -Name "N3ServerBox" -MemoryStartupBytes 8GB -Generation 2 -NewVHDPath (Join-Path -Path $diskDirectory -ChildPath 'n3.vhdx') -NewVHDSizeBytes 60GB -SwitchName $wifiSwitch.Name -Path $vmDirectory 
$drive = Add-VMDvdDrive -VM $vm -Path $isoFile
Set-VMFirmware -VM $vm -FirstBootDevice $drive -EnableSecureBoot $true 
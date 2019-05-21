#Requires -Version 5.0
#Requires -RunAsAdministrator

Set-StrictMode -Version Latest
Set-ExecutionPolicy Unrestricted -Scope CurrentUser -Confirm

Install-PackageProvider -Name NuGet -RequiredVersion 2.8.5.206 -Force
Install-PackageProvider -Name ChocolateyGet
Install-Module -Name PowerShellGet -Force -MinimumVersion 2.1.3
Install-Module -Name Carbon -AllowClobber
Install-Module -Name IISAdministration
Install-Module -Name PSReadLine -Force
Import-PackageProvider ChocolateyGet

Install-Package -ProviderName Chocolatey -Name Chocolatey

PowerShellGet\Install-Module posh-git -AllowPrerelease -Force

Import-Module -Name PowerShellGet 
Import-Module -Name Carbon
Import-Module -Name PSReadLine
Import-Module -Name IISAdministration
Import-Module -Name 'posh-git'
Import-Module -Name PoshDevUtils


$iisRestartReqd = Install-IIS
$vmRestartReqd = Install-HyperV
$nextScript = (Get-RootedPath -Path "SiteSetup.ps1")

if ($iisRestartReqd -or $vmRestartReqd) {
  Resume-AfterRestart -ResumeScript $nextScript
}

Invoke-Expression ".\$nextScript"
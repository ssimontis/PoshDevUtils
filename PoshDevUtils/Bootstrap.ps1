#Requires -Version 5.1
#Requires -RunAsAdministrator

Set-ExecutionPolicy Unrestricted -Scope CurrentUser -Confirm

Install-PackageProvider -Name NuGet -RequiredVersion 2.8.5.206 -Force
Install-PackageProvider -Name ChocolateyGet
Install-Module -Name PowerShellGet -Force -MinimumVersion 2.1.3
Install-Module -Name Carbon -AllowClobber
Install-Module -Name IISAdministration
Install-Module -Name DockerMsftProvider -Force

Import-PackageProvider ChocolateyGet
Install-Package -ProviderName Chocolatey -Name Chocolatey


PowerShellGet\Install-Module posh-git -Scope CurrentUser -AllowPrerelease -Force


Import-Module -Name DockerMsftProvider -Force
Import-PackageProvider -Name DockerMsftProvider -Force

#Requires -Version 5.0
#Requires -Modules PSReadLine, PowerShellGet, posh-git, IISAdministration, DockerMsftProvider, VSSetup, MSI, Pscx, Carbon
#Requires -RunAsAdministrator

Set-StrictMode -Version Latest

Import-Module PSReadLine, PowerShellGet, posh-git, IISAdministration, DockerMsftProvider, VSSetup, MSI, Pscx, Carbon

function Get-LatestModule {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position=0)]
        [String]
        [ValidateNotNullOrEmpty()]
        $Name,
        [Parameter()]
        [Boolean]
        $AllowPrerelease=$false,
        [Parameter()]
        [Boolean]
        $CanClobber=$false
    )
    Write-Verbose "Attempting to install/update module $Name"

    if (-Not (Get-Module -ListAvailable -Name $Name)) {
        Write-Verbose "Module $Name not found...installing"
        Install-Module -Name $Name -Scope CurrentUser -AllowPrerelease:$AllowPrerelease -AllowClobber:$CanClobber
        Write-Verbose "Module $Name installed successfully." -Verbose
    }
    else {
        Write-Verbose "Module $Name already installed...checking for updates."
        Update-Module -Name $Name -AllowPrerelease:$AllowPrerelease
        Write-Verbose "Module $Name update check completed successfully." -Verbose
    }
}

function UpdateDependencies {
    [CmdletBinding()]
    Param()
    Write-Verbose "Updating all required modules for script..."
    Get-LatestModule -Name "PSReadLine"
    Get-LatestModule -Name "PowerShellGet"
    Get-LatestModule -Name "posh-git" -AllowPrerelease $true
    Get-LatestModule -Name "IISAdministration" -AllowPrerelease $true
    Get-LatestModule -Name "VSSetup" -AllowPrerelease $true
    Get-LatestModule -Name "DockerMsftProvider" -AllowPrerelease $true
    Get-LatestModule -Name "MSI" -AllowPrerelease $true
    Get-LatestModule -Name "Pscx" -CanClobber $true
    Get-LatestModule -Name "Carbon" -CanClobber $true
    Write-Verbose "Updating all required modules for script...done. Please restart PowerShell"
}


function Install-WinFeature($name) {
    Write-Verbose "Installing Windows Feature $name and dependencies..."
    Enable-WindowsOptionalFeature -Online -FeatureName $name -All -NoRestart
    Write-Verbose "Installing Windows Feature $name and dependencies...DONE" -Verbose
}

function Install-IIS() {
    Install-WinFeature "IIS-WebServer"
    Install-WinFeature "IIS-ASPNET45"
    Install-WinFeature "IIS-WebServerRole"
    Install-WinFeature "IIS-CommonHttpFeatures"
    Install-WinFeature "IIS-HttpErrors"
    Install-WinFeature "IIS-ApplicationDevelopment"
    Install-WinFeature "IIS-HealthAndDiagnostics"
    Install-WinFeature "IIS-HttpLogging"
    Install-WinFeature "IIS-HttpTracing"
    Install-WinFeature "WebServerManagementTools"
    Install-WinFeature "IIS-StaticContent"
    Install-WinFeature "IIS-WebSockets"
    Install-WinFeature "IIS-ApplicationInit"
    Install-WinFeature "Microsoft-Windows-NetFx4-US-OC-Package"
    Install-WinFeature "IIS-NetFxExtensibility45"
    Install-WinFeature "IIS-ISAPIExtensions"
    Install-WinFeature "IIS-ISAPIFilter"
    Install-WinFeature "IIS-HttpCompressionStatic"
    Write-Verbose "Installing Web Platform Installer..."
    & "C:\Program Files\Microsoft\Web Platform Installer\WebpiCmd-x64.exe" /install /Products:WDeployNoSMO /AcceptEULA /SuppressPostFinish
    Write-Verbose "Installing Web Platform Installer...DONE" -Verbose
}

$WebManager = Get-IISServerManager
$invalidAppPoolCharsRegex = [Microsoft.Web.Administration.ApplicationPoolCollection]::InvalidApplicationPoolNameCharacters()

function Confirm-ValidAppPoolName{
    [OutputType([Bool])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [String]
        [ValidateNotNullOrEmpty()]
        $Name
    )
    $invalidCharTests = @{}
    $invalidAppPoolCharsRegex | % { $invalidCharTests.Add($_, ($Name -match [Regex]::Escape($_))) }
    $illegalChars = ($invalidCharTests.GetEnumerator() | ? { $_.Value -eq $true}) | % {$_.Key}

    if ($illegalChars.Count -gt 0) {
        $illegalStr = [string]$illegalChars
        Write-Error "$Name is not a valid application pool name: invalid characters: $illegalStr"
        return $false
    }

    return $true
}
function New-AppPool {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [String]
        [ValidateNotNullOrEmpty()]
        $Name,
        [Parameter(Mandatory = $false)]
        [Switch]
        $Force
    )

    Write-Verbose "Creating application pool $Name..."
    $exists = Test-Path "IIS:\AppPools\$Name"

    if ($exists -And -Not $Force ) {
        Write-Error "Application pool $Name already exists and -Force was not specified. Application pool may be configured incorrectly."
        return
    }
    elif ($exists -and $Force) {
        Uninstall-CIisAppPool -Name $Name
    }

    if (-not (Confirm-ValidAppPoolName -Name $Name)) {
        return
    }

    Install-CIisAppPool -Name $Name
    Write-Verbose "Creating application pool $Name...DONE"
}

function New-Website {
    [CmdletBinding(SupportsShouldProcess = $true)]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [String]
        [ValidateNotNullOrEmpty()]
        $Name,
        [Parameter(Mandatory = $true, Position = 1)]
        [String]
        [ValidateNotNullOrEmpty()]
        $Path,
        [Parameter(Mandatory = $true, Position = 2)]
        [String]
        [ValidateNotNullOrEmpty()]
        $Host,
        [Parameter(Mandatory = $true, Position = 3)]
        [Int]
        [ValidateRange(0, 65535)]
        $Port,
        [Parameter(Mandatory = $false, Position = 4)]
        [String]
        [ValidateSet("http", "https")]
        $Protocol="http",
        [Parameter(Mandatory = $false)]
        [String]
        $AppPoolName = $Name,
        [Parameter(Mandatory = $false)]
        [String]
        $IpAddress = "*",
        [Parameter(Mandatory = $false)]
        [Switch]
        $Force
    )
    DynamicParam {
        if ($Protocol -eq "https") {
            $thumbprintAttr = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $thumbprintAttr.Mandatory = $true
            $thumbprintAttr.HelpMessage = "Specify the MD5 thumbprint for the certificate to be associated with this site's binding."
            $thumbprintAttr.Position = 5
            $lengthAttr = New-Object -TypeName System.Management.Automation.ValidateLengthAttribute(40, 40)

            $thumbprintAttrList = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
            $thumbprintAttrList.Add($thumbprintAttr)
            $thumbprintAttrList.Add($lengthAttr)
            $thumbrintParam = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter('CertThumbprint', [String], $thumbprintAttrList)

            $locationAttr = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $locationAttr.Mandatory = $true
            $locationAttr.HelpMessage = "Specify the name of the certificate store where the specified certificate lives."
            $locationAttr.Position = 6
            $locationSetAttr = New-Object -TypeName System.Management.Automation.ValidateSetAttribute("TrustedPublisher", "Root", "TrustedDevices", "My", "CA", "AuthRoot", "TrustedPeople", "My", "SmartCardRoot", "Trust", "Homegroup Machine Certificates")

            $locationAttrList = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
            $locationAttrList.Add($locationAttr)
            $locationAttrList.Add($locationSetAttr)
            $storeLocationParam = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter('CertStoreLocation', [String], $locationAttrList)

            $paramDictionary = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameterDictionary
            $paramDictionary.Add('CertThumbprint', $thumbrintParam)
            $paramDictionary.Add('CertStoreLocation', $storeLocationParam)

            return $paramDictionary
        }
    }
    Process {
        Write-Verbose "Creating IIS website $Name..."

        Write-Verbose "Verifying physical path $Path exists..."
        Install-CDirectory -Path $Path
        Write-Verbose "Verifying physical path $Path exists...DONE"

        $existing = (Get-CIisWebsite -Name $Name).Length
        if ($existing -ne 0 -and -not $Force) {
            Write-Error "Site $Name already exists and the -Force switch was not passed. The site may not be configured properly."
            return
        }
        elif ($existing) {
            Write-Verbose "Site $Name already exists; removing site..."
            Uninstall-CIisWebsite -Name $Name
            Write-Verbose "Site $Name already exists; removing site...DONE"
        }

        $bindExpr = "${IpAddress}:${Port}:${Host}"
        $siteParams = @{
            Name = $Name
            BindingInformation = $bindExpr
            PhysicalPath = $Path
            Protocol = $Protocol
            Passthru = $true
        }

        if ($PSBoundParameters.CertThumbprint -and $PSBoundParameters.CertStoreLocation) {
            $thumb = $PSBoundParameters.CertThumbprint
            $store = $PSBoundParameters.CertStoreLocation
            $certPath = "cert:\$store\$thumb"
            Write-Verbose "Validating certificate $certPath for use with HTTPS binding on site $Name..."

            try {
                Get-ChildItem -Path $certPath
            }
            catch {
                Write-Error "No certificate found at $certPath...creation of site $Name failed."
                return
            }

            $siteParams.Add('CertificateThumbPrint', $PSBoundParameters.CertThumbprint)
            $siteParams.Add('CertStoreLocation', "Cert:\$PSBoundParameters.CertStoreLocation")
            Write-Verbose "Validating certificate $certPath for use with HTTPS binding on site $Name...DONE"
        }

        Write-Verbose "Creating site $Name..."
        $site = New-IISSite @siteParams
        Write-Verbose "Creating site $Name...DONE"

        if ((Get-IISAppPool -Name $AppPoolName).Length -eq 0) {
            Write-Error "Cannot set application pool for site ${Name}: application pool $AppPoolName does not exist."
            return
        }

        $site.Applications['/'].ApplicationPoolName = $AppPoolName
        Write-Verbose "Set application pool $AppPoolName for site $Name"
        $site.ServerAutoStart = $true

        Write-Verbose "Starting site $Name..."
        $site.Start()
        Write-Verbose "Starting site $Name...DONE. Listening on $bindExpr"

        Write-Verbose "Site $Name created successfully at $Path"
    }
}

function Get-EnumValues {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [String]
        [ValidateNotNullOrEmpty()]
        $Enum
    )
    $enumValues = @{}
    [enum]::GetValues([type]$Enum) | % { $enumValues.Add($_, $_.value__) }

    return $enumValues
}

function startSite($name) {
    $site = Get-IISSite -Name $name

        if ($null -eq $site) {
            Write-Error "Site $name does not exist."
            return
        }

    if ($site.State -eq [Microsoft.Web.Administration.ObjectState]::Started -or $site.State -eq [Microsoft.Web.Administration.ObjectState]::Starting) {
        Write-Verbose "Site $name is already running."
        return
    }

        Write-Verbose "Starting site $name..."
        $site.Start()
        Write-Verbose "Starting site $name...DONE"
}

function Start-Sites {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)]
        [String[]]
        $Name
    )

    if ($Name.Length -eq 0) {
        Write-Verbose "Starting all sites..."
        Get-IISSite | % { startSite $_ }
        Write-Verbose "Starting all sites...DONE"
        return
    }

    Write-Verbose "Starting selected sites..."
    $Name | % { startSite $_ }
    Write-Verbose "Starting selected sites...DONE"
}


function stopSite($name) {
    $site = Get-IISSite -Name $name

    if ($null -eq $site) {
        Write-Error "Site $name does not exist."
        return
    }

    if ($site.State -eq [Microsoft.Web.Administration.ObjectState]::Stopped -or $site.State -eq [Microsoft.Web.Administration.ObjectState]::Stopping) {
        Write-Verbose "Site $name is already stopped."
        return
    }

    Write-Verbose "Stopping site $name..."
    $site.Stop()
    Write-Verbose "Stopping site $name...DONE"
}

function Stop-Sites {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)]
        [String[]]
        $Name
    )

    if ($Name.Length -eq 0) {
        Write-Verbose "Stopping all sites..."
        Get-IISSite | % { stopSite $_ }
        Write-Verbose "Stopping all sites...DONE"
        return
    }

    Write-Verbose "Stopping selected sites..."
    $Name | % {	stopSite $_ }
    Write-Verbose "Stopping selected sites...DONE"
}

function recycleAppPool($name) {
    $pool = IISAdministration\Get-IISAppPool -Name $name

    if ($null -eq $pool) {
        Write-Error "Application pool $name does not exist."
        return
    }

    Write-Verbose "Recycling application pool $name..."
    $pool.Recycle()
    Write-Verbose "Recycling application pool $name...DONE"
}

function Restart-AppPools {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipeline = $true)]
        [String[]]
        $Name
    )

    if ($Name.Length -eq 0) {
        Write-Verbose "Recycling all application pools..."
        IISAdministration\Get-IISAppPool | % { recycleAppPool $_ }
        Write-Verbose "Recycling all application pools...DONE"
        return
    }

    Write-Verbose "Recycling selected application pools..."
    $Name | % { recycleAppPool $_ }
    Write-Verbose "Recycling selected application pools...DONE"
}

function removeSite($name) {
    $site = Get-IISSite -Name $name

    if ($null -eq $site) {
        Write-Error "Site $name does not exist."
        return
    }

    Write-Verbose "Removing site $name..."
    $WebManager.Remove($site)
    Write-Verbose "Removing site $name...DONE"
}

function Remove-Sites {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [String[]]
        $Name
    )
    Write-Verbose "Removing selected sites..."
    $Name | % { removeSite $_ }
    $WebManager.CommitChanges()
    Write-Verbose "Removing selected sites...DONE"
}

function New-TrustedSelfSignedCert {
    [CmdletBinding()]
    Param(
        [Parameters(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,
        [Parameter(Mandatory = $true, Position = 2, ValueFromPipeline = $true)]
        [String]
        [ValidateNotNullOrEmpty()]
        $ExportDirectory,
        [Parameter(Mandatory = $false, Position = 3)]
        [datetime]
        [ValidateScript({ $_ -gt (Get-Date)})]
        $expiration = (Get-Date).AddYears(1),
        [Parameter(Mandatory = $false, Position = 4)]
        [Int32]
        [ValidateRange("Positive")]
        $KeyLength = 2048
    )
    Write-Verbose "Generating certificate..."

    Write-Verbose "Ensuring directory $ExportDirectory exists..."
    Install-CDirectory $ExportDirectory
    Write-Verbose "Ensuring directory $ExportDirectory exists...DONE"

    Write-Verbose "Generating X509 cert..."
    $rootCert = New-SelfSignedCertificate -DnsName $Name -KeyLength $KeyLength -KeyAlgorithm 'RSA' -HashAlgorithm 'SHA256' \
    -KeyExportPolicy 'Exportable' -NotAfter $expiration -CertStoreLocation "Cert:\LocalMachine\My" \
    -KeyUsage 'CertSign','CRLSign' -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1") -FriendlyName $Name
    Write-Verbose "Generating X509 cert...DONE"
    $rootFile = Join-Path -Path $ExportDirectory -ChildPath "$Name.crt"

    Write-Verbose "Exporting public key of certificate to $rootFile..."
    Export-Certificate -Cert $rootCert -FilePath $rootFile
    Write-Verbose "Exporting public key of certificate to $rootFile...DONE"

    Write-Verbose "Importing certificate into trusted root store..."
    Import-Certificate -CertStoreLocation 'Cert:\LocalMachine\Root' -FilePath $rootFile
    Write-Verbose "Importing certificate into trusted root store...DONE"

    Write-Verbose "Generating certificate ${rootCert.Thumbprint}...DONE"

    $rootCert.Thumbprint
}

function New-SelfSignedTlsCert {
  [CmdletBinding()]
  Param(
    [Parameters(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
    [ValidateNotNullOrEmpty()]
    [String]
    $Name,
    [Parameter(Mandatory = $true, Position = 1)]
    [String]
    [ValidateNotNullOrEmpty()]
    $DnsName,
    [Parameter(Mandatory = $true, Position = 2, ValueFromPipeline = $true)]
    [String]
    [ValidateNotNullOrEmpty()]
    $ExportDirectory,
    [Parameter(Mandatory = $true, Position = 3, ValueFromPipeline = $true)]
    [String]
    [ValidateNotNullOrEmpty()]
    $SignerThumbprint,
    [Parameter(Mandatory = $true, Position = 4)]
    [securestring]
    [ValidateNotNullOrEmpty()]
    $Password,
    [Parameter(Mandatory = $false, Position = 4)]
    [datetime]
    [ValidateScript( { $_ -gt (Get-Date) })]
    $expiration = (Get-Date).AddYears(1),
    [Parameter(Mandatory = $false, Position = 4)]
    [Int32]
    [ValidateRange("Positive")]
    $KeyLength = 2048
  )
  Write-Verbose "Generating certificate..."

  Write-Verbose "Ensuring directory $ExportDirectory exists..."
  Install-CDirectory $ExportDirectory
  Write-Verbose "Ensuring directory $ExportDirectory exists...DONE"

  Write-Verbose "Fetching trusted signing certificate with thumbprint $SignerThumbprint..."
  $rootCA = Get-ChildItem "Cert:\LocalMachine\Root\$SignerThumprint"

  if ($null -eq $rootCA) {
      Write-Error "No trusted cert with thumbprint $SignerThumbprint was found."
      return
  }

  Write-Verbose "Generating X509 cert..."
  $localCert = New-SelfSignedCertificate -DnsName $DnsName -KeyLength $KeyLength -KeyAlgorithm 'RSA' -HashAlgorithm 'SHA256' \
  -KeyExportPolicy 'Exportable' -NotAfter $expiration -CertStoreLocation "Cert:\LocalMachine\My" -Signer $rootCA
  -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1") -FriendlyName "$Name self-signed local cert"
  Write-Verbose "Generating X509 cert...DONE"
  $certFile = Join-Path -Path $ExportDirectory -ChildPath "$Name.crt"
  $certExportFile = Join-Path $ExportDirectory -ChildPath "$Name.pfx"

  Write-Verbose "Exporting certificate and key to $rootFile..."
  Export-Certificate -Cert $localCert -FilePath $certFile
  Export-PfxCertificate -Cert $localCert -FilePath $certExportFile -Password $Password
  Write-Verbose "Exporting public key and pfx of certificate to $rootFile...DONE"

  Write-Verbose "Generating certificate ${localCert.Thumbprint}...DONE"

  $localCert.Thumbprint
}

function Install-Chocolatey {
    [CmdletBinding()]
    Param()
    Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
}

function Install-ChocolateyPackage {
    [CmdletBInding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [String]
        [ValidateNotNullOrEmpty()]
        $PackageName,
        [Parameter(Mandatory = $false, Position = 1)]
        [String]
        $Parameters
    )
    $cmd = "choco install $PackageName -y"

    if (-not [string]::IsNullOrWhiteSpace($Parameters)) {
        $cmd += " --parameters $Parameters"
    }
}

function Assert-ProgramInstalled {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]
        [ValidateNotNullOrEmpty()]
        $ProgramName,
        [switch]
        $Wildcard
    )
    Write-Verbose "Searching for an installation record of program $ProgramName"

    $name = $ProgramName
    if ($Wildcard) {
        $name = '*' + $ProgramName + '*'
    }

    $result = Get-CProgramInstallInfo -Name $name

    $null -ne $results -and $results.Count -gt 0
}

function Assert-CommandPresent {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]
        [ValidateNotNullOrEmpty()]
        $Command
    )
    Write-Verbose "Testing if command $Command exists..."

    $Command | Get-Command -ErrorAction SilentlyContinue

    $?
}

function New-IisApplication {
    [CMdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]
        [ValidateNotNullOrEmpty()]
        $ParentSiteName,
        [Parameter(Mandatory = $true, Position = 1)]
        [string]
        [ValidateNotNullOrEmpty()]
        $AppName,
        [Parameter(Mandatory = $true, Position = 2)]
        [string]
        [ValidateNotNullOrEmpty()]
        $AppPoolName,
        [Parameter(Mandatory = $true, Position = 3)]
        [string]
        [ValidateScript( { Test-Path -Path $_ -IsValid })]
        $AppPath,
        [switch]
        $Force
    )
    Write-Verbose "Creating IIS Application $AppName within site $ParentSiteName..."

    $site = Get-CIisWebsite -Name $ParentSiteName

    if ($null -eq $site) {
        Write-Error "Website $ParentSiteName does not exist."
        return
    }

    $existingApp = $site.Applications | Where-Object { $_.Path -eq "/$AppName"}

    if ($null -ne $existingApp -and (-not $Force)) {
        Write-Error "Application already exists at virtual path /$AppName for site $ParentSiteName. Specify -Force switch to remove."
        return
    }
    elseif ($null -ne $existingApp) {
        Write-Verbose "Application already exists at path /$AppName of site $ParentSiteName and will be removed."
        $manager = $existingApp.ServerManager
        $existingApp.Delete()
        $manager.CommitChanges()
        Write-Verbose "Application at path /$AppName deleted successfully."
    }

    $pool = Get-CIisAppPool -Name $AppPoolName

    if ($null -eq $pool) {
        Write-Error "Application pool $AppPoolName does not exist."
        return
    }

    Install-CIisApplication -SiteName $ParentSiteName -VirtualPath $AppName -PhysicalPath $AppPath -AppPoolName $AppPoolName
    Write-Verbose "Creating IIS Application $AppName within site $ParentSiteName...DONE"
}

function Invoke-XdtTransform {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]
        [ValidateScript( { Test-Path $_ })]
        $WebConfigFile,
        [Parameter(Mandatory = $true, Position = 1)]
        [string]
        [ValidateScript( { Test-Path $_ })]
        $TransformFile,
        [Parameter(Mandatory = $true, Position = 2)]
        [string]
        [ValidateScript( { Test-Path $_ -IsValid })]
        $WebConfigDestinationPath
    )
    $ConvertParams = @{
        Path = $WebConfigFile
        XdtPath = $TransformFile
        Destination = $WebConfigDestinationPath
        Verbose = $Verbose
    }

    Write-Verbose "Applying XDT Transform $TransformFile to web.config in directory $WebConfigDestinationPath"
    Convert-CXmlFile @ConvertParams
    Write-Verbose "$WebConfigDestinationPath transformed successfully via file $TransformFile"
}



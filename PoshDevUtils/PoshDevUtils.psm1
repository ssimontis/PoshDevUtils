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
        [Parameter(Mandatory = $false)]
        [switch]
        $Prerelease,
        [Parameter(Mandatory = $false)]
        [switch]
        $Clobber
    )
    Process {
        Write-Verbose "Attempting to install/update module $Name..."

        if ($null -eq (Get-Module -ListAvailable -Name $Name)) {
            Write-Verbose "Module $Name not found...installing"
            Install-Module -Name $Name -Scope CurrentUser -AllowPrerelease:$Prerelease -AllowClobber:$Clobber
            Write-Verbose "Module $Name installed successfully."
        }
        else {
            Write-Verbose "Module $Name already installed...checking for updates."
            Update-Module -Name $Name -AllowPrerelease:$Prerelease
            Write-Verbose "Module $Name update check completed successfully."
        }
    }
}



function Sync-ProcessPath {
    [CmdletBinding()]
    Param()
    Process {
        Write-Verbose "Updating process module path data..."
        $env:PSModulePath = (Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Session Manager\Environment' -Name PSModulePath).PSModulePath
        Write-Verbose "Process module path data updated successfully to $env:PSModulePath"
    }
}

function Update-Dependencies {
    [CmdletBinding()]
    Param()
    Process {
        Write-Verbose "Updating all required modules for script..."
        Get-LatestModule -Name "PSReadLine"
        Get-LatestModule -Name "PowerShellGet"
        Get-LatestModule -Name "posh-git" -Prerelease
        Get-LatestModule -Name "IISAdministration" -Prerelease
        Get-LatestModule -Name "VSSetup" -Prerelease
        Get-LatestModule -Name "DockerMsftProvider" -Prerelease
        Get-LatestModule -Name "MSI" -Prerelease
        Get-LatestModule -Name "Pscx" -Clobber
        Get-LatestModule -Name "Carbon" -Clobber
        Write-Verbose "Updating all required modules for script...done."
        Sync-ProcessPath
    }
}

function Get-RootedPath {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]
        [ValidateNotNullOrEmpty()]
        $Path
    )
    Process {
        if (-not ([System.IO.Path]::IsPathRooted($Path))) {
            $Path = Join-Path -Path $PSScriptRoot -ChildPath $Path
        }

        $Path
    }
}

function Test-IsPoshScript {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]
        [ValidateScript({ Test-Path -Path (Get-RootedPath -Path $_) -PathType Leaf })]
        $Path
    )
    Process {
        [System.IO.Path]::GetExtension($Path).Contains(".PS1", [StringComparison]::InvariantCultureIgnoreCase)
    }
}

function Resume-AfterRestart {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]
        [ValidateScript({ Test-IsPoshScript -Path $_  })]
        $ResumeScript
    )
    Process {
        $taskTrigger = New-ScheduledTaskTrigger -AtStartup
        $taskAction = New-ScheduledTaskAction -Execute Powershell.exe -Argument "-ExecutionPolicy Bypass -File $ResumeScript"
        $taskUserId = New-ScheduledTaskPrincipal -UserId System -RunLevel Highest -LogonType ServiceAccount
        Register-ScheduledTask -Force -TaskName RestartResumeScript -Action $taskAction -Principal $taskUserId -Trigger $taskTrigger
    }
}

function Install-WinFeature {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]
        [ValidateScript({$null -ne (Get-WindowsOptionalFeature -Online -FeatureName $_) })]
        $Name
    )
    Process {
        if ($null -eq (Get-WindowsOptionalFeature -Online -FeatureName $Name | Where-Object { $_.Status -eq 'Enabled' })) {
            Write-Verbose "Installing Windows Feature $Name and dependencies..."
            $result = Enable-WindowsOptionalFeature -Online -FeatureName $Name -All -NoRestart -WarningAction  SilentlyContinueow
            Write-Verbose "Installing Windows Feature $Name and dependencies...DONE"
            if ($result.RestartNeeded) { 1 } else { 0 }
        }
    }
}

function Install-IIS {
    [CmdletBinding()]
    Param()
    Process {
        $restartReqd = 0
        $restartReqd += Install-WinFeature "IIS-WebServer"
        $restartReqd += Install-WinFeature "IIS-ASPNET"
        $restartReqd += Install-WinFeature "IIS-ASPNET45"
        $restartReqd += Install-WinFeature "IIS-WebServerRole"
        $restartReqd += Install-WinFeature "IIS-CommonHttpFeatures"
        $restartReqd += Install-WinFeature "IIS-HttpErrors"
        $restartReqd += Install-WinFeature "IIS-HttpRedirect"
        $restartReqd += Install-WinFeature "IIS-ApplicationDevelopment"
        $restartReqd += Install-WinFeature "IIS-HealthAndDiagnostics"
        $restartReqd += Install-WinFeature "IIS-HttpLogging"
        $restartReqd += Install-WinFeature "IIS-HttpTracing"
        $restartReqd += Install-WinFeature "IIS-WebServerManagementTools"
        $restartReqd += Install-WinFeature "IIS-StaticContent"
        $restartReqd += Install-WinFeature "IIS-WebSockets"
        $restartReqd += Install-WinFeature "IIS-ApplicationInit"
        $restartReqd += Install-WinFeature "IIS-ManagementConsole"
        $restartReqd += Install-WinFeature "IIS-Security"
        $restartReqd += Install-WinFeature "IIS-Performance"
        $restartReqd += Install-WinFeature "NetFx4-AdvSrvs"
        $restartReqd += Install-WinFeature "NetFx4Extended-ASPNET45"
        $restartReqd += Install-WinFeature "Microsoft-Windows-NetFx4-US-OC-Package"
        $restartReqd += Install-WinFeature 'Microsoft-Windows-NetFx4-WCF-US-OC-Package'
        $restartReqd += Install-WinFeature "IIS-NetFxExtensibility45"
        $restartReqd += Install-WinFeature "IIS-ISAPIExtensions"
        $restartReqd += Install-WinFeature "IIS-ISAPIFilter"
        $restartReqd += Install-WinFeature "IIS-HttpCompressionStatic"

        Write-Verbose "Installing Web Platform Installer..."
        & "C:\Program Files\Microsoft\Web Platform Installer\WebpiCmd-x64.exe" /install /Products:WDeployNoSMO /AcceptEULA /SuppressPostFinish
        Write-Verbose "Installing Web Platform Installer...DONE" -Verbose

        $restartReqd -gt 0
    }
}

function Install-HyperV {
    [CmdletBinding()]
    Param()
    Process {
        $restartReqd = 0
        Write-Verbose "Installing Windows components for HyperV and containers..."
        $restartReqd += Install-WinFeature "Containers"
        $restartReqd += Install-WinFeature "Microsoft-Hyper-V-All"
        Write-Verbose "Installing Windows components for HyperV and containers...DONE"

        $restartReqd -gt 0
    }
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
    Process {
        $invalidCharTests = @{}
        $invalidAppPoolCharsRegex | ForEach-Object { $invalidCharTests.Add($_, ($Name -match [Regex]::Escape($_))) }
        $illegalChars = ($invalidCharTests.GetEnumerator() | Where-Object { $_.Value -eq $true}) | ForEach-Object {$_.Key}

        if ($illegalChars.Count -gt 0) {
            $illegalStr = [string]$illegalChars
            Write-Error "$Name is not a valid application pool name: invalid characters: $illegalStr"
            return $false
        }

        $true
    }
}

function New-AppPool {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [String]
        [ValidateScript({ Confirm-ValidAppPoolName -Name $Name })]
        $Name,
        [Parameter(Mandatory = $false)]
        [Switch]
        $Force
    )
    Process {
        Write-Verbose "Creating application pool $Name..."
        $exists = Test-Path "IIS:\AppPools\$Name"

        if ($exists -and -not $Force ) {
            Write-Error "Application pool $Name already exists and -Force was not specified. Application pool may be configured incorrectly."
            return
        }
        elseif ($exists -and $Force) {
            Uninstall-CIisAppPool -Name $Name
        }

        Install-CIisAppPool -Name $Name
        Write-Verbose "Creating application pool $Name...DONE"
    }
}

function New-Website {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [String]
        [ValidateNotNullOrEmpty()]
        $Name,
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true)]
        [String]
        [ValidateNotNullOrEmpty()]
        $Path,
        [Parameter(Mandatory = $true, Position = 2, ValueFromPipelineByPropertyName = $true)]
        [String]
        [ValidateNotNullOrEmpty()]
        $Host,
        [Parameter(Mandatory = $true, Position = 3, ValueFromPipelineByPropertyName = $true)]
        [Int32]
        [ValidateRange(0, 65535)]
        $Port,
        [Parameter(Mandatory = $false, Position = 4, ValueFromPipelineByPropertyName = $true)]
        [String]
        [ValidateSet("http", "https")]
        $Protocol="http",
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
        [String]
        $AppPoolName = $Name,
        [Parameter(Mandatory = $false, ValueFromPipelineByPropertyName = $true)]
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
            $thumbprintAttr.ValueFromPipelineByPropertyName = $true
            $lengthAttr = New-Object -TypeName System.Management.Automation.ValidateLengthAttribute(40, 40)

            $thumbprintAttrList = New-Object -TypeName System.Collections.ObjectModel.Collection[System.Attribute]
            $thumbprintAttrList.Add($thumbprintAttr)
            $thumbprintAttrList.Add($lengthAttr)
            $thumbrintParam = New-Object -TypeName System.Management.Automation.RuntimeDefinedParameter('CertThumbprint', [String], $thumbprintAttrList)

            $locationAttr = New-Object -TypeName System.Management.Automation.ParameterAttribute
            $locationAttr.Mandatory = $true
            $locationAttr.HelpMessage = "Specify the name of the certificate store where the specified certificate lives."
            $locationAttr.Position = 6
            $locationAttr.ValueFromPipelineByPropertyName = $true
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

        $existing = $null -eq (Get-CIisWebsite -Name $Name)
        if ($existing -and -not $Force) {
            Write-Error "Site $Name already exists and the -Force switch was not passed. The site may not be configured properly."
            return
        }
        elseif ($existing) {
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

            $siteParams.Add('CertificateThumbPrint', $thumb)
            $siteParams.Add('CertStoreLocation', "Cert:\$PSBoundParameters.CertStoreLocation")
            Write-Verbose "Validating certificate $certPath for use with HTTPS binding on site $Name...DONE"
        }

        Write-Verbose "Creating site $Name..."
        $site = New-IISSite @siteParams
        Write-Verbose "Creating site $Name...DONE"

        if ($null -eq (Get-IISAppPool -Name $AppPoolName)) {
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
    Process {
        $enumValues = @{}
        [enum]::GetValues([type]$Enum) | ForEach-Object { $enumValues.Add($_, $_.value__) }

        $enumValues
    }
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
    Process {
        if ($Name.Length -eq 0) {
            $Name = Get-IISSite
        }

        Write-Verbose "Starting selected sites..."
        $Name | ForEach-Object { startSite $_ }
        Write-Verbose "Starting selected sites...DONE"
    }
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
    Process {
        if ($Name.Length -eq 0) {
            $Name = Get-IISSite
        }

        Write-Verbose "Stopping selected sites..."
        $Name | ForEach-Object { stopSite $_ }
        Write-Verbose "Stopping selected sites...DONE"
    }
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
        $Name = IISAdministration\Get-IISAppPool
    }

    Write-Verbose "Recycling selected application pools..."
    $Name | ForEach-Object { recycleAppPool $_ }
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
    Process {
        Write-Verbose "Removing selected sites..."
        $Name | ForEach-Object { removeSite $_ }
        $WebManager.CommitChanges()
        Write-Verbose "Removing selected sites...DONE"
    }
}

function New-TrustedSelfSignedCert {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Name,
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true)]
        [String]
        [ValidateScript({ Test-Directory -Path $_ -PathType Container -IsValid})]
        $ExportDirectory,
        [Parameter(Mandatory = $false, Position = 2, ValueFromPipelineByPropertyName = $true)]
        [datetime]
        [ValidateScript({ $_ -gt (Get-Date) })]
        $expiration = (Get-Date).AddYears(1),
        [Parameter(Mandatory = $false, Position = 3, ValueFromPipelineByPropertyName = $true)]
        [Int32]
        [ValidateRange("Positive")]
        $KeyLength = 2048
    )
    Process {
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
}

function New-SelfSignedTlsCert {
  [CmdletBinding()]
  Param(
    [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
    [ValidateNotNullOrEmpty()]
    [String]
    $Name,
    [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true)]
    [String]
    [ValidateNotNullOrEmpty()]
    $DnsName,
    [Parameter(Mandatory = $true, Position = 2, ValueFromPipelineByPropertyName = $true)]
    [String]
    [ValidateScript({ Test-Directory -Path $_ -PathType Container -IsValid })]
    $ExportDirectory,
    [Parameter(Mandatory = $true, Position = 3, ValueFromPipelineByPropertyName = $true)]
    [String]
    [ValidateNotNullOrEmpty()]
    $SignerThumbprint,
    [Parameter(Mandatory = $true, Position = 4, ValueFromPipelineByPropertyName = $true)]
    [securestring]
    [ValidateNotNullOrEmpty()]
    $Password,
    [Parameter(Mandatory = $false, Position = 5, ValueFromPipelineByPropertyName = $true)]
    [datetime]
    [ValidateScript( { $_ -gt (Get-Date) })]
    $expiration = (Get-Date).AddYears(1),
    [Parameter(Mandatory = $false, Position = 6, ValueFromPipelineByPropertyName = $true)]
    [Int32]
    [ValidateRange("Positive")]
    $KeyLength = 2048
  )
  Process {
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
    -KeyExportPolicy 'Exportable' -NotAfter $expiration -CertStoreLocation "Cert:\LocalMachine\My" -Signer $rootCA \
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
}

function Install-Chocolatey {
    [CmdletBinding()]
    Param()
    Process {
        Invoke-Expression ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    }
}

function Install-ChocolateyPackage {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [String]
        [ValidateNotNullOrEmpty()]
        $PackageName,
        [Parameter(Mandatory = $false, Position = 1, ValueFromPipelineByPropertyName = $true)]
        [String]
        $Parameters
    )
    Process {
        $cmd = "choco install $PackageName -y"

        if (-not [string]::IsNullOrWhiteSpace($Parameters)) {
            $cmd += " --parameters $Parameters"
        }
    }
}

function Assert-ProgramInstalled {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]
        [ValidateNotNullOrEmpty()]
        $ProgramName,
        [Parameter(Mandatory = $false)]
        [switch]
        $Wildcard
    )
    Process {
    Write-Verbose "Searching for an installation record of program $ProgramName"

    $name = $ProgramName
    if ($Wildcard) {
        $name = '*' + $ProgramName + '*'
    }

    $result = Get-CProgramInstallInfo -Name $name

    $null -ne $results -and $results.Count -gt 0
}
}

function Assert-CommandPresent {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]
        [ValidateNotNullOrEmpty()]
        $Command
    )
    Write-Verbose "Testing if command $Command exists..."

    $Command | Get-Command -ErrorAction SilentlyContinue

    $?
}

function New-IisApplication {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]
        [ValidateScript({ Test-CIisWebsite -Name $ParentSiteName })]
        $ParentSiteName,
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true)]
        [string]
        [ValidateNotNullOrEmpty()]
        $AppName,
        [Parameter(Mandatory = $true, Position = 2, ValueFromPipelineByPropertyName = $true)]
        [string]
        [ValidateScript({ Test-CIisAppPool -Name $_ })]
        $AppPoolName,
        [Parameter(Mandatory = $true, Position = 3, ValueFromPipelineByPropertyName = $true)]
        [string]
        [ValidateScript( { Test-Path -Path $_ -IsValid })]
        $AppPath,
        [Parameter(Mandatory = $false)]
        [switch]
        $Force
    )
    Process {
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
}

function Invoke-XdtTransform {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]
        [ValidateScript( { Test-Path $_ })]
        $WebConfigFile,
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true)]
        [string]
        [ValidateScript( { Test-Path $_ })]
        $TransformFile,
        [Parameter(Mandatory = $true, Position = 2, ValueFromPipelineByPropertyName = $true)]
        [string]
        [ValidateScript( { Test-Path $_ -IsValid })]
        $WebConfigDestinationPath
    )
    Process {
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
}

Enum NetFrameworkVersions {
    NET45 = 378389
    NET451 = 378758
    NET451ALT = 378675
    NET452 = 379893
    NET46 = 393295
    NET46ALT = 393297
    NET461 = 394254
    NET461ALT = 394271
    NET462 = 394802
    NET462ALT = 394806
    NET47 = 460798
    NET47ALT = 460805
    NET471 = 461308
    NET471ALT = 461310
    NET472 = 461808
    NET472ALT = 461814
    NET48 = 528040
    NET48ALT = 528049
}

Enum NetFrameworkMinimumVersions {
    NET45 = 378389
    NET451 = 378675
    NET452 = 379893
    NET46 = 3932945
    NET461 = 394254
    NET462 = 394802
    NET47 = 460798
    NET471 = 461308
    NET472 = 461808
    NET48 = 528040
}

function Get-NetFxVersion {
    [CmdletBinding()]
    Param()
    Process {
        Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse |
            Get-ItemProperty -Name Version, Release -ErrorAction 0 |
            Where-Object { $_.PSChildName -match '^(?![SW])\p{L}'} |
            Select PSChildName, Version, Release, @{
                name = "Product"
                expression = {
                    switch ($_.Release) {

                    }
                }
            }

    }
}

function Get-RegistryKey {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]
        [ValidateScript({ Test-Path -Path $_ -PathType Container })]
        $KeyPath
    )
    Process {
        Get-Item -Path $KeyPath | Select-Object -ExpandProperty Property
    }
}

function Confirm-EmptyDirectory {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]
        [ValidateScript({ Test-Path -Path $_ -PathType Container})]
        $Directory
    )
    Process {
        (GetChildItem -Path "$KeyPath\*" -Force |
            Select-Object -First 1 |
            Measure-Object).Count -eq 0
    }
}

function Test-CommandInPath {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]
        [ValidateNotNullOrEmpty()]
        $Command
    )
    Process {
        $null -ne (Get-Command -Name $Command -ErrorAction SilentlyContinue)
    }
}

function Test-ProgramVersion {
    [OutputType([bool])]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]
        [ValidateNotNullOrEmpty()]
        $Command,
        [Parameter(Mandatory = $true, Position = 1)]
        [string]
        [ValidateScript({ $_ -as [version] })]
        $MinVersion
    )
    Process {
        $cmd = Get-Command -Name $Command -ErrorAction SilentlyContinue

        if ($null -eq $cmd) { return $false }

        $currentVersion = $cmd.Version
        $reqdVersion = [version]$MinVersion

        $currentVersion -ge $reqdVersion
    }
}

Enum MatchType {
    Exact = 0
    StartsWith = 1
    EndsWith = 2
    Contains = 3
}
function Get-InstalledProgram {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ParameterSetName = "ByName")]
        [string]
        [ValidateNotNullOrEmpty()]
        $ProgramName,
        [Parameter(Mandatory = $false, Position = 1, ValueFromPipelineByPropertyName = $true, ParameterSetName = "ByName")]
        [MatchType]
        $MatchStyle = [MatchType]::Exact,
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ParameterSetName = "ByInstallId")]
        [string]
        [ValidateScript({ $_ -as [System.Guid]})]
        $ProgramId
    )
    Process {
        if ($ProgramId) {
            switch ($MatchStyle) {
                [MatchType]::Exact { Get-WmiObject -Class Win32_Product -ComputerName . |
                                    Where-Object -FilterScript { $_.Name -eq $ProgramName}}
                [MatchType]::StartsWith { Get-WmiObject -Class Win32_Product -ComputerName . |
                                    Where-Object -FilterScript { $_.Name -like "$ProgramName*"}}
                [MatchType]::EndsWith { Get-WmiObject -Class Win32_Product -ComputerName . |
                                    Where-Object -FilterScript { $_.Name -like "*$ProgramName" }}
                [MatchType]::ContainsWith { Get-WmiObject -Class Win32_Product -ComputerName . |
                                    Where-Object -FilterScript { $_.Name -like "*$ProgramName*" }}
        }
    }
        else {
            Get-WmiObject -Class Win32_Product -ComputerName . |
                Where-Object -FilterScript { $_.IdentifyingNumber -eq $ProgramId}
        }
    }
}

function Remove-Program {
    [CmdletBinding()]
    Param(
        [ParameterAttribute(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [PSObject]
        [ValidateScript({$null -ne $_ -and $_ -as [Win32_Product] })]
        $Program
    )
}

function Copy-Folder {
    [CmdletBinding()]
    Param(
        [ParameterAttribute(Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [string]
        [ValidateScript({ Test-Path -Path $_ -PathType Container})]
        $SourceDirectory,
        [ParameterAttribute(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true)]
        [string]
        [ValidateScript({ Test-Path -Path $_ -PathType Container -IsValid})]
        $DestinationDirectory,
        [ParameterAttribute(Mandatory = $false, Position = 2, ValueFromPipelineByPropertyName = $true)]
        [switch]
        $Overwrite
    )
    Process {
        Copy-Item -Path $SourceDirectory -Recurse -Force:$Overwrite -Destination $DestinationDirectory
    }
}

function Copy-File {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [string]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf})]
        $SourceFile,
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true)]
        [string]
        [ValidateScript({ Test-Path -Path $_ -PathType Container -IsValid})]
        $DestinationDirectory,
        [Parameter(Mandatory = $false, Position = 2, ValueFromPipelineByPropertyName = $true)]
        [switch]
        $Overwrite
    )
    Process {
        Copy-Item -Path $SourceFile -Force:$Overwrite -Destination $DestinationDirectory
    }
}

function Restart-Process {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]
        [ValidateScript({ (Get-Process -Name $_ | Selet-Object -First 1 | Measure-Object).Count -gt 0})]
        $ProcessName
    )
    Process {
        $Process = Get-Process -Name $ProcessName
        $id = $Process.Id
        $commandLine = (Get-WmiObject -Class Win32_Process -Filter "Handle=$id").$commandLine
        $path = $commandLine.Split(' ')[0]
        $arguments = $commandLine.Split(' ')[1]

        $Process.Kill()
        $Process.WaitForExit()

        Start-Process -FilePath $path -ArgumentList $arguments
    }
}

function Test-Url {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]
        [ValidateNotNullOrEmpty()]
        $Url
    )
    Process {
        $parsedUrl = $null
        if ([System.Uri]::TryCreate($Url, 'Absolute', $parsedUrl)) {
            $parsedUrl.Scheme -match 'http[s]?'
        }
        $false
    }
}

function Invoke-Download {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [string]
        [ValidateScript({ Test-Url -Url $_ })]
        $Url,
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true)]
        [string]
        [ValidateScript({ Test-Path -Path $_ -IsValid -PathType Leaf})]
        $Destination
    )
    Begin {
        $ProgressPreference = SilentlyContinue
    }
    Process {
        Invoke-WebRequest -Method Get -OutFile $Destination -PassThru -Uri $Url -UseBasicParsing
    }
    End {
        $ProgressPreference = Continue
    }
}

function Clear-FolderContents {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]
        [ValidateScript({ Test-Path -Path $_ -PathType Container})]
        $Directory
    )
    Process {
        $Size = (Get-ChildItem $Directory | Measure-Object -Property Length -Sum).Sum
        Get-ChildItem $Directory | Remove-Item -Force -ErrorAction SilentlyContinue -Recurse
        Write-Verbose "Removed ${Size:0.0} MB from $Directory"
    }
}

function Set-FileExtension {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
        $File,
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true)]
        [string]
        [ValidateNotNullOrEmpty]
        $NewExtension
    )
    Process {
        if (-not $File.StartsWith(".", [System.StringComparison]::InvariantCultureIgnoreCase)) {
            $File = ".$File"
        }
        $newFile = [System.IO.Path]::ChangeExtension($File, $NewExtension)
        $newFile
    }
}

function Invoke-DisposableScope {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [object]
        [ValidateScript({ $null -ne $_ -and $_ -is [System.IDisposable]})]
        $Resource,
        [Parameter(Mandatory = $true, Position = 1)]
        [scriptblock]
        $ScopeScript
    )
    Process {
        try {
            . $ScopeScript
        }
        finally {
            if ($null -ne $Resource) {
                $Resource.Dispose()
            }
        }
    }
}

function Get-VisualStudioBootstrapper {
    [CmdletBinding()]
    Param()
    Process {
        $tempDir = New-CTempDirectory -Prefix 'n3'
        Invoke-WebRequest 'https://visualstudio.microsoft.com/thank-you-downloading-visual-studio/?sku=enterprise&rel=16&utm_medium=microsoft&utm_source=docs.microsoft.com&utm_campaign=link+cta&utm_content=download+commandline+parameters+vs2019+rc#' -OutFile c:\file.ext
    }
}

function Get-WebPageContent {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]
        [ValidateScript({ Test-Url -Url $_ })]
        $PageUrl
    )
    Process {
        . Invoke-DisposableScope ($webClient = New-Object System.Net.WebClient) {
            $webClient.DownloadString($PageUrl)
        }
    }
}

function Get-WebPageLinks {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]
        [ValidateScript({ Test-Url -Url $_ })]
        $PageUrl,
        [Parameter(Mandatory = $false)]
        [switch]
        $RunJavascript
    )
    Process {
        (Invoke-WebRequest -UseBasicParsing:$RunJavascript -Uri $PageUrl).Links.Href
    }
}

function Get-Profile {
    [CmdletBinding()]
    Param()
    Process {
        if (!(Test-Path -Path $profile -PathType leaf)) {
            New-Item -Path $profile -ItemType 'file' -Force
        }

        Get-Content -Path $profile
    }
}

function Add-ProfileData {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [string]
        [ValidateScript({ Test-Path -Path $profile -PathType leaf})]
        $Data
    )
    Process {
        $Commands | Add-Content -Path $profile
    }
}

function Add-ContentToFile {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ParameterSetName = "AppendText")]
        [string]
        [ValidateNotNullOrEmpty()]
        $AppendText,
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true, ParameterSetName = "AppendFile")]
        [string]
        [ValidateScript({ Test-Path -Path $_ -PathType leaf })]
        $AppendFile,
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true, ParameterSetName = "AppendText")]
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true, ParameterSetName = "AppendFile")]
        [string]
        [ValidateScript({ Test-Path -Path $_ -PathType leaf -IsValid})]
        $DestinationFile
    )
    Process {
        if (!(Test-Path -Path $DestinationFile -PathType leaf)) {
            New-Item -Path $DestinationFile -ItemType File
        }

        if ($AppendText) {
            Add-Content -Path $DestinationFile -Value $AppendText
        }
        else {
            Get-Content -Path $AppendFile | Add-Content -Path $DestinationFile
        }
    }
}

function Send-FormEncodedPost {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipeline = $true)]
        [hashtable]
        [ValidateNotNullOrEmpty()]
        $FormData,
        [Parameter(Mandatory = $true, Position = 1)]
        [string]
        [ValidateScript({ Test-Url -Url $_})]
        $PostUrl,
        [Parameter(Mandatory = $false)]
        [hashtable]
        [AllowEmptyCollection()]
        [AllowNull()]
        $Headers,
        [Parameter(Mandatory = $false)]
        [securestring]
        [AllowEmptyString()]
        [AllowNull()]
        $BearerToken
    )
    Process {
        $requestData = @{
            Method = Post
            Uri = $PostUrl
            SslProtocol = Tls12
            Form = FormData
            TimeoutSec = 30
            MaximumRetryCount = 3
        }

        if ($null -ne $Headers -and $Headers.Count -gt 0) {
            $requestData.Headers = $Headers
        }
        if ($null -ne $BearerToken) {
            $requestData.Token = $BearerToken
            $requestData.Authentication = OAuth
        }

        Invoke-RestMethod @requestData
    }
}

enum UpdateBehavior {
    Upsert = 0
    Prepend = 1
    Append = 2
    Replace = 3
    SetIfMissing = 4
}

function Update-EnvironmentVariable {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [string]
        [ValidateNotNullOrEmpty()]
        $VariableName,
        [Parameter(Mandatory = $true, Position = 1, ValueFromPipelineByPropertyName = $true)]
        [string]
        [ValidateNotNullOrEmpty()]
        $Value,
        [Parameter(Mandatory = $false, Position = 2, ValueFromPipelineByPropertyName = $true)]
        [UpdateBehavior]
        $UpdateStrategy = [UpdateBehavior]::Upsert,
        [Parameter(Mandatory = $false, Position = 3, ValueFromPipelineByPropertyName = $true)]
        [System.EnvironmentVariableTarget]
        $VariableType = [System.EnvironmentVariableTarget]::Process
    )
    Process {
        $currentValue = [System.Environment]::GetEnvironmentVariable($VariableName, $VariableType)

        switch ($UpdateStrategy) {
            ([UpdateBehavior]::Upsert) {
                [System.Environment]::SetEnvironmentVariable($VariableName, $Value, $VariableType)
            }
            ([UpdateBehavior]::Prepend) {
                if ($null -eq $currentValue) {
                    Write-Error "$VariableName could not be set to value $Value in $VariableType scope because it does not exist."
                    return
                }
                [System.Environment]::SetEnvironmentVariable($VariableName, "$Value$currentValue", $VariableType)
            }
            ([UpdateBehavior]::Append) {
                if ($null -eq $currentValue) {
                    Write-Error "$VariableName could not be set to value $Value in $VariableType scope because it does not exist."
                    return
                }
                [System.Environment]::SetEnvironmentVariable($VariableName, "$currentValue$Value", $VariableType)
            }
            ([UpdateBehavior]::Replace) {
                if ($null -eq $currentValue) {
                    Write-Error "$VariableName could not be set to value $Value in $VariableType scope because it does not exist."
                    return
                }
                [System.Environment]::SetEnvironmentVariable($VariableName, "$Value", $VariableType)
            }
            ([UpdateBehavior]::SetIfMissing) {
                if ($null -eq $currentValue) {
                    [System.Environment]::SetEnvironmentVariable($VariableName, $Value, $VariableType)
                    return
                }
                Write-Error "$VariableName in scope $VariableType already exists and will not be set."
            }
        }
    }
}

function Install-Scoop {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $false, Position = 0, ValueFromPipelineByPropertyName = $true)]
        [string]
        [ValidateScript({ Test-Path -Path $_ -PathType container -IsValid})]
        $InstallDirectory = $null,
        [Parameter(Mandatory = $false, Position = 1, ValueFromPipelineByPropertyName = $true)]
        [string]
        [ValidateScript({ Test-Path -Path $_ -PathType Container -IsValid })]
        $GlobalProgramDirectory = $null
    )
    Process {
        if ($null -ne $InstallDirectory) {
            $env:SCOOP = $InstallDirectory
            [System.Environment]::SetEnvironmentVariable('SCOOP', $env:SCOOP, 'User')
        }

        if ($null -ne $GlobalProgramDirectory) {
            $env:SCOOP_GLOBAL = $GlobalProgramDirectory
            [System.Environment]::SetEnvironmentVariable('SCOOP_GLOBAL', $env:SCOOP_GLOBAL, 'Machine')
        }

        Invoke-Expression (New-Object net.WebClient).DownloadString('https://get.scoop.sh')
    }
}

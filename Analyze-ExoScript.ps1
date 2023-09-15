<#
    .SYNOPSIS
    Analyze-ExoScript.ps1

    Michel de Rooij
    michel@eightwone.com

    THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE
    ENTIRE RISK OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS
    WITH THE USER.

    Version 1.31, September 15th, 2023

    .DESCRIPTION
    This script can analyze Exchange Online Management scripts, indicating if all contained Exchange 
    commands are supported with REST-based cmdlets. If there are no Exchange cmdlets found which require 
    RPSSession, the script can run without -UseRPSSession and Basic authentication can be disabled on the 
    client as it no longer needs to connect using WinRM. Note that UseRPSSession is only available per
    version 2.0.6-Preview3 of the Exchange Online Management module.

    On the initial run, the external file containing information on cmdlets supporting REST and which require RPS,
    will be created by connecting once to Exchange Online and once using RPSSession. The external file will be 
    tagged with the current version of the Exchange Online Management module. This way, when an updated module has
    been installed, you can be notified of the update and refresh the cmdlet information file.

    Important: Your current role assignments determine which cmdlets are available to you in Exchange Online.
    Make sure you run the script in at least the security context used to execute the script.

    Output consists of objects with the following properties:
    - Cmdlet is the name of the Exchange Online cmdlet found
    - Type can consists of:
      - REST indicates an REST-based cmdlet
      - RPS indicates an RPS-only cmdlet
      - RPS (Map:...) indicates an RPS-based cmdlet which can be refactored to the indicated REST-based cmdlet 
    - Parameters are the parameters used in the command
    - File is the file analyzed
    - Line is the line where the cmdlet is located

    .LINK
    http://eightwone.com

    .NOTES
            

    Revision History
    --------------------------------------------------------------------------------
    1.0      Initial release
    1.1      Added Certificate parameters etc for unattended usage
             Changed File parameter to support paths
    1.2      Added missing default Connect + REST-based cmdlets for analysis
             Added seperate column for REST-backed > REST-based mapping opportunities
    1.21     Fixed processing non-Exchange cmdlets
    1.22     Fixed output issue when showing all cmdlets
    1.3      Removed RPS due to deprecation in Exchange Online
             Added UserPrincipalName parameter for interactive logon
    1.31     Refresh can now be used without specifying File to just update the cmdlet set

    .PARAMETER File
    Name of the PowerShell Exchange Online Management script file(s) to analyze.

    .PARAMETER ShowAll
    This switch tells the script to report all cmdlets, not only the Exchange Online Management ones.

    .PARAMETER Refresh
    Tells the script to refresh the cmdlet information files.

    .PARAMETER UserPrincipalName

    .PARAMETER Organization

    .PARAMETER AppId

    .PARAMETER CertificateFile

    .PARAMETER CertificateThumbprint

    .PARAMETER CertificatePassword

    .EXAMPLE
    Analyze-ExoScript.ps1 -File Permissions.ps1 
    Analyzes the Permissions.ps1 script, and outputs the detected Exchange Online cmdlets and their REST/RPS details.

    .EXAMPLE
    Get-ChildItem -Path C:\temp\*.ps1 | Analyze-ExoScript.ps1 
    Analyzes the PowerShell scripts in c:\temp and outputs the detected Exchange Online cmdlets and their REST/RPS details

#>
#Requires -Version 3
[cmdletbinding(
    DefaultParameterSetName = 'DefaultAuth'
)]
param(
    [parameter( Mandatory= $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName= 'DefaultAuth')] 
    [parameter( Mandatory= $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName= 'OAuthCertThumb')] 
    [parameter( Mandatory= $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName= 'OAuthCertFile')] 
    [parameter( Mandatory= $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true, ParameterSetName= 'OAuthCertSecret')] 
    [ValidateScript({ Test-Path -Path $_ -PathType Any})]
    [String[]]$File,
    [parameter( Mandatory= $false, ParameterSetName= 'DefaultAuth')] 
    [parameter( Mandatory= $false, ParameterSetName= 'OAuthCertThumb')] 
    [parameter( Mandatory= $false, ParameterSetName= 'OAuthCertFile')] 
    [parameter( Mandatory= $false, ParameterSetName= 'OAuthCertSecret')] 
    [Switch]$ShowAll,
    [parameter( Mandatory= $true, ParameterSetName= 'DefaultAuthRefresh')] 
    [parameter( Mandatory= $true, ParameterSetName= 'OAuthCertThumbRefresh')] 
    [parameter( Mandatory= $true, ParameterSetName= 'OAuthCertFileRefresh')] 
    [parameter( Mandatory= $true, ParameterSetName= 'OAuthCertSecretRefresh')] 
    [Switch]$Refresh,
    [parameter( Mandatory= $false, ParameterSetName= 'DefaultAuth')] 
    [parameter( Mandatory= $false, ParameterSetName= 'OAuthCertThumb')] 
    [parameter( Mandatory= $false, ParameterSetName= 'OAuthCertFile')] 
    [parameter( Mandatory= $false, ParameterSetName= 'OAuthCertSecret')] 
    [parameter( Mandatory= $false, ParameterSetName= 'DefaultAuthRefresh')] 
    [parameter( Mandatory= $false, ParameterSetName= 'OAuthCertThumbRefresh')] 
    [parameter( Mandatory= $false, ParameterSetName= 'OAuthCertFileRefresh')] 
    [parameter( Mandatory= $false, ParameterSetName= 'OAuthCertSecretRefresh')] 
    [String]$UserPrincipalName,
    [parameter( Mandatory= $true, ParameterSetName= 'OAuthCertThumb')] 
    [parameter( Mandatory= $true, ParameterSetName= 'OAuthCertThumbRefresh')] 
    [String]$CertificateThumbprint,
    [parameter( Mandatory= $true, ParameterSetName= 'OAuthCertFile')] 
    [parameter( Mandatory= $true, ParameterSetName= 'OAuthCertFileRefresh')] 
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf})]
    [String]$CertificateFile,
    [parameter( Mandatory= $false, ParameterSetName= 'OAuthCertFile')] 
    [parameter( Mandatory= $false, ParameterSetName= 'OAuthCertFileRefresh')] 
    [System.Security.SecureString]$CertificatePassword,
    [parameter( Mandatory= $true, ParameterSetName= 'OAuthCertThumb')] 
    [parameter( Mandatory= $true, ParameterSetName= 'OAuthCertFile')] 
    [parameter( Mandatory= $true, ParameterSetName= 'OAuthCertSecret')] 
    [parameter( Mandatory= $true, ParameterSetName= 'OAuthCertThumbRefresh')] 
    [parameter( Mandatory= $true, ParameterSetName= 'OAuthCertFileRefresh')] 
    [parameter( Mandatory= $true, ParameterSetName= 'OAuthCertSecretRefresh')] 
    [string]$Organization,
    [parameter( Mandatory= $true, ParameterSetName= 'OAuthCertThumb')] 
    [parameter( Mandatory= $true, ParameterSetName= 'OAuthCertFile')] 
    [parameter( Mandatory= $true, ParameterSetName= 'OAuthCertSecret')] 
    [parameter( Mandatory= $true, ParameterSetName= 'OAuthCertThumbRefresh')] 
    [parameter( Mandatory= $true, ParameterSetName= 'OAuthCertFileRefresh')] 
    [parameter( Mandatory= $true, ParameterSetName= 'OAuthCertSecretRefresh')] 
    [string]$AppId
)
#Requires -Version 3.0
begin {

    If(!( Get-Module -Name ExchangeOnlineManagement -ListAvailable)) {
        Throw ('Exchange Online Management module not present')
    }

    If(!( Get-Command -Name Get-ExoMailbox -ErrorAction SilentlyContinue)) {
        Throw ('Exchange Online Management module does not seem to be loaded')
    }

    $EXOModule= Get-Module -Name (Get-Command -Name Get-ExoMailbox).Module 

    # Get module version from manifest, including preview tag
    $exoModuleRoot = (Get-Item $EXOModule.Path).Directory.Parent.FullName
    $exoModuleManifestPath = Join-Path -Path $exoModuleRoot -ChildPath 'ExchangeOnlineManagement.psd1'
    $isExoModuleManifestPathValid = Test-Path -Path $exoModuleManifestPath
    If(!( $isExoModuleManifestPathValid)) {
        Write-Verbose ('Module manifest path invalid ({0}), skipping extracting prerelease info' -f $exoModuleManifestPath)
        $EXOModuleVersion= $EXOModule.Version.ToString()
    }
    Else {
        $exoModuleManifestContent = Get-Content -Path $exoModuleManifestPath
        $preReleaseInfo = $exoModuleManifestContent -match "Prerelease = '(.*)'"
        If( $preReleaseInfo) {
            $EXOModuleVersion= '{0}-{1}' -f $EXOModule.Version, $preReleaseInfo[0].Split('=')[1].Trim().Trim("'")
        }
        Else {
            $EXOModuleVersion= $EXOModule.Version.ToString()
        }
    }

    Write-Host ('ExchangeOnlineManagement module {0} installed' -f $EXOModuleVersion)

    $DataFile= Join-Path -Path $PSScriptRoot -Child ('EXO-CmdletInfo.xml')

    If(!( Test-Path -Path $DataFile) -or $Refresh) {

        If( $Refresh) {
            Write-Verbose ('Refreshing cmdlet information')
        }
        Else {
            Write-Verbose ('Cmdlet information file not found, collecting cmdlet information')
        }

        $AuthParams= @{
            Organization= $Organization
            AppId= $AppId
            Certificate= $Certificate
            CertificateFilePath= $CertificateFile
            CertificatePassword= $CertificatePassword
            CertificateThumbprint= $CertificateThumbprint
            UserPrincipalName= $UserPrincipalName
        }

        # Connect to retrieve EXO cmdlets 
#        $ExoSession= Get-PSSession | Where-Object {$_.CurrentModuleName -eq (Get-Command -Name Get-Mailbox).Module.Name}
#        $User= $ExoSession.Runspace.ConnectionInfo.Credential.UserName
#        Write-Verbose ('Connected using {0}' -f $User)

        # Connect using REST, re-using account used to connect to first session
        Write-Host ('Connecting to Exchange Online')
        ExchangeOnlineManagement\Connect-ExchangeOnline -ShowBanner:$False @AuthParams
        If(!( Get-Command -Name Get-Mailbox -ErrorAction SilentlyContinue)) {
            Throw ('We do not seem to be connected to Exchange Online Management session, exiting')
        }
        $CmdREST= Get-Command -Module (Get-Command -Name Get-Mailbox).Module | Select Name,@{n='Type';e={'RESTbacked'}}
        Write-Verbose ('REST session returned {0} cmdlets' -f $CmdREST.count)

        $CmdDefault= Get-Command -Module (Get-Command -Name Connect-ExchangeOnline).Module | Select Name,@{n='Type';e={'RESTbased'}}

        # Cleanup
        Remove-Module -Name (Get-Command -Name Get-Mailbox).Module

        # Make a unique list of cmdlets
        $CmdletInfo= [pscustomobject]@{
            EXOVersion= $EXOModuleVersion
            Cmdlets= $CmdREST + $CmdDefault | Sort-Object -Property Type,Name -Unique 
        }
        Write-Verbose ('Exporting cmdlet information to {0}' -f $DataFile)
        $CmdletInfo | Export-CliXml -Path $DataFile -Force 
    }
    Else {
        Write-Verbose ('Loading cmdlet information from {0}' -f $DataFile)
        $CmdletInfo= Import-CliXml -Path $DataFile
        If( $CmdletInfo.EXOVersion -ne $EXOModuleVersion) {
            Write-Warning ('Exchange Online Management module ({0}) and stored information ({1}) version mismatch: Use -Refresh to update this information' -f $EXOModuleVersion, $CmdletInfo.EXOVersion)
        }
    }

    # Cmdlet mapping opportunity, eg Get-MailboxFolderStatistics -> Get-ExoMailboxFolderStatistics - mind the PropertySet though
    $CmdletMap= @{
        'Get-CasMailbox'='Get-EXOCasMailbox';
        'Get-Mailbox'='Get-EXOMailbox';
        'Get-MailboxFolderPermission'='Get-EXOMailboxFolderPermission';
        'Get-MailboxFolderStatistics'='Get-EXOMailboxFolderStatistics';
        'Get-MailboxPermission'='Get-EXOMailboxPermission';
        'Get-MailboxStatistics'='Get-EXOMailboxStatistics';
        'Get-MobileDeviceStatistics'='Get-EXOMobileDeviceStatistics';
        'Get-Recipient'='Get-EXORecipient';
        'Get-RecipientPermission'='Get-EXORecipientPermission'
    }

    # Create hashtable for easy lookups
    $ExoCmdlet= @{}
    $ExoAltCmdlet= @{}

    $CmdletInfo.Cmdlets | Sort-Object -Property Type,Name -Descending | ForEach-Object { 
        $ExoCmdlet[ $_.Name]= $_.Type
        If( $CmdletMap[ $_.Name]) {
            $ExoAltCmdlet[ $_.Name]= $CmdletMap[ $_.Name]
        }
    }
}

process {

    ForEach( $Entry in $File) {

        $Path= Convert-Path -Path $Entry
        Get-ChildItem -Path (Convert-Path -Path $Entry) | ForEach {
        
            Write-Verbose ('Parsing {0} for tokens' -f $_.Name)
            $AST = [System.Management.Automation.Language.Parser]::ParseFile( $_.FullName, [ref]$null, [ref]$null)

            $CmdsInFile= $AST.FindAll({$args[0].GetType().Name -like 'CommandAst'}, $true)
            ForEach( $Cmd in $CmdsInFile) {
                If( $Cmd.CommandElements[0].Value) {
                    $Type= $ExoCmdlet[ $Cmd.CommandElements[0].Value]
                    $Alt= $CmdletMap[ $Cmd.CommandElements[0].Value]
                }
                Else {
                    $Type= $null
                    $Alt= $null
                }
                If($Type -or $ShowAll) {
                    [pscustomobject]@{
                        Command = $Cmd.CommandElements[0].Value
                        Type= $Type
                        Parameters = $Cmd.CommandElements.ParameterName
                        File= $_.Name
                        Alt= $Alt
                        Line= $Cmd.Extent.StartLineNumber
                    }
                }
            }
        }
    }

}
end {

}
                  
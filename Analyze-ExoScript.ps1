<#
    .SYNOPSIS
    Analyze-ExoScript.ps1

    Michel de Rooij
    michel@eightwone.com

    THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE
    ENTIRE RISK OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS
    WITH THE USER.

    Version 1.0, May 25th, 2022

    .DESCRIPTION
    This script can analyze Exchange Online Management scripts, indicating if all contained Exchange 
    commands are supported with REST-based cmdlets. If there are no Exchange cmdlets found which require 
    RPSSession, the script can run without -UseRPSSession and Basic authentication can be disabled on the 
    client as it no longer needs to connect using WinRM.

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

    .PARAMETER File
    Name of the PowerShell Exchange Online Management script file(s) to analyze.

    .PARAMETER ShowAll
    This switch tells the script to report all cmdlets, not only the Exchange Online Management ones.

    .PARAMETER Refresh
    Tells the script to refresh the cmdlet information files.

    .EXAMPLE
    Analyze-ExoRpsScript.ps1 -File Permissions.ps1 
    Analyzes the Permissions.ps1 script, and outputs the detected Exchange Online cmdlets and their REST/RPS details.

    .EXAMPLE
    Get-ChildItem -Path C:\temp\*.ps1 | Analyze-ExoRpsScript.ps1 
    Analyzes the PowerShell scripts in c:\temp and outputs the detected Exchange Online cmdlets and their REST/RPS details

#>
[cmdletbinding(
)]
param(
    [parameter( Mandatory= $true, ValueFromPipeline = $true, ValueFromPipelineByPropertyName = $true)]
    [ValidateScript({ Test-Path -Path $_ -PathType Leaf})]
    [String[]]$File,
    [parameter( Mandatory= $false)] 
    [Switch]$ShowAll,
    [parameter( Mandatory= $false)] 
    [Switch]$Refresh
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

        # Connect twice to retrieve cmdlets for REST and RPS, and determine which ones require RPS.
        Write-Host ('Connecting to Exchange Online using RPS')
        ExchangeOnlineManagement\Connect-ExchangeOnline -UseRPSSession -ShowBanner:$False
        If(!( Get-Command -Name Get-Mailbox -ErrorAction SilentlyContinue)) {
            Throw ('We do not seem to be connected to Exchange Online Management session, exiting')
        }
        If(!( (Get-Module -Name (Get-Command -Name Get-Mailbox -ErrorAction SilentlyContinue).Module).Description -like '*Implicit Remoting*')) {
            Throw ('Exchange Online Management session not connected with UseRPSSession')
        }
        $CmdRPS= Get-Command -Module (Get-Command -Name Get-Mailbox).Module | Select Name,@{n='Type';e={'RPS'}}

        $ExoSession= Get-PSSession | Where-Object {$_.CurrentModuleName -eq (Get-Command -Name Get-Mailbox).Module.Name}
        $User= $ExoSession.Runspace.ConnectionInfo.Credential.UserName
        Write-Verbose ('Connected using {0}' -f $User)

        # Connect using REST, re-using account used to connect to first session
        Write-Host ('Connecting to Exchange Online using regular connection, re-using account {0}' -f $User)
        ExchangeOnlineManagement\Connect-ExchangeOnline -UserPrincipalName $User -ShowBanner:$False
        If(!( Get-Command -Name Get-Mailbox -ErrorAction SilentlyContinue)) {
            Throw ('We do not seem to be connected to Exchange Online Management session, exiting')
        }
        $CmdREST= Get-Command -Module (Get-Command -Name Get-Mailbox).Module | Select Name,@{n='Type';e={'REST'}}

        # Make a unique list of cmdlets, where REST prevails when existing in both sets
        $CmdletInfo= [pscustomobject]@{
            EXOVersion= $EXOModuleVersion
            Cmdlets= $CmdREST + $CmdRPS | Sort-Object -Unique Name
        }
        Write-Verbose ('Exporting cmdlet information to {0}' -f $DataFile)
        $CmdletInfo | Export-CliXml -Path $DataFile -Force 
    }
    Else {
        Write-Verbose ('Loading cmdlet information from {0}' -f $DataFile)
        $CmdletInfo= Import-CliXml -Path $DataFile
        If( $CmdletInfo.EXOVersion -ne $EXOModuleVersion) {
            Write-Warning ('Exchange Online Management module and cmdlet information version mismatch' -f $EXOModuleVersion, $CmdletInfo.EXOVersion)
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
    $CmdletInfo.Cmdlets | ForEach-Object { 
        If( $_.Type -eq 'RPS') {
            If( $CmdletMap[ $_.Name]) {
                $ExoCmdlet[ $_.Name]= '{0} (Map:{1})' -f $_.Type, $CmdletMap[ $_.Name]
            }
            Else {
                $ExoCmdlet[ $_.Name]= $_.Type 
            }
        }
        Else {
            $ExoCmdlet[ $_.Name]= $_.Type 
        }
    }
}

process {

    ForEach( $Entry in $File) {

        $Path= Convert-Path -Path $Entry

        Write-Verbose ('Parsing {0} for tokens' -f $Path)
        $AST = [System.Management.Automation.Language.Parser]::ParseFile( $Path, [ref]$null, [ref]$null)

        $CmdsInFile= $AST.FindAll({$args[0].GetType().Name -like 'CommandAst'}, $true)
        ForEach( $Cmd in $CmdsInFile) {
            If($ExoCmdlet[ $Cmd.CommandElements[0].Value] -or $ShowAll) {
                [pscustomobject]@{
                    Cmdlet = $Cmd.CommandElements[0].Value
                    Type= $ExoCmdlet[ $Cmd.CommandElements[0].Value]
                    Parameters = $Cmd.CommandElements.ParameterName
                    File= $Entry
                    Line= $Cmd.Extent.StartLineNumber
                }
            }
        }
    }

}
end {

}

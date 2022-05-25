# Analyze-ExoScript

## Getting Started

Script to analyze Exchange Online Management scripts, indicating contained EXO cmdlets are REST or RPS based.
Idea is that when there are no Exchange cmdlets found requiring UseRPSSession, the script can run with Basic authentication 
disabled on the WinRM client. Other usage scenarios are cross-referencing scripts vs Echange commands, or scanning
scripts to assist in tailoring RBAC permissions.

On the initial run, the external file containing information on cmdlets supporting REST and which require RPS,
will be created by connecting once to Exchange Online and once using RPSSession. The external file will be 
tagged with the current version of the Exchange Online Management module. This way, when an updated module has
been installed, you can be notified of the update and refresh the cmdlet information file.

Important: Your current role assignments determine which cmdlets are available to you in Exchange Online.
Make sure you run the script in at least the security context used to execute the script.

### About

For more information on this script, as well as usage and examples, see the related blog article, 
[Analyzing Exchange Online scripts](https://eightwone.com/2022/05/25/analyzing-exchange-online-scripts/).

## License

This project is licensed under the MIT License - see the LICENSE for details.

Important: Your current role assignments determine which cmdlets are available to you in Exchange Online.
Make sure you run the script in at least the security context used to execute the script.


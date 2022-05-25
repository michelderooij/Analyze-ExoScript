# Analyze-ExoScript
Script to analyze Exchange Online Management scripts, indicating contained EXO cmdlets are REST or RPS based

If there are no Exchange cmdlets found which require RPSSession, the script can run without -UseRPSSession, Basic authentication
can be disabled on the client as it no longer needs to connect using WinRM.

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

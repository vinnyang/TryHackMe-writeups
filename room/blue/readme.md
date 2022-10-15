### [nmap.init](./nmap.init)

### Metersploit
- `exploit/windows/smb/ms17_010_eternalblue`
	- payload - `windows/x64/shell/reverse_tcp`
- escalate
	- `post/multi/manage/shell_to_meterpreter`
		- Will get `NT AUTHORITY\SYSTEM` if ran successfully, then

Verify that we have escalated to NT AUTHORITY\SYSTEM. Run getsystem to confirm this. Feel free to open a dos shell via the command 'shell' and run 'whoami'.
This should return that we are indeed system. Background this shell afterwards and select our meterpreter session for usage again.

List all of the processes running via the 'ps' command. Just because we are system doesn't mean our process is. Find a process towards the bottom of this list that is running at NT AUTHORITY\SYSTEM and write down the process id (far left column).

Migrate to this process using the 'migrate PROCESS_ID' command where the process id is the one you just wrote down in the previous step. This may take several attempts, migrating processes is not very stable. If this fails, you may need to re-run the conversion process or reboot the machine and start once again. If this happens, try a different process next time.

Within our elevated meterpreter shell, run the command 'hashdump'. This will dump all of the passwords on the machine as long as we have the correct privileges to do so.

### "the location where passwords are stored within Windows"
1. C:\windows\system32\config\SAM (Registry: HKLM/SAM)
2. System memory

### "an excellent location to loot"
- Users
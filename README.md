# dns-resolver
A basic DNS resolver written in Go. Ref John Crickett's coding [challenges](https://codingchallenges.fyi/challenges/challenge-dns-resolver).

**Usage: ./dns codingchallenges.fyi**

```
Querying 192.36.148.17 for codingchallenges.fyi
Querying 161.232.11.42 for codingchallenges.fyi
Querying 192.36.148.17 for ns-2045.awsdns-63.co.uk
Querying 43.230.48.1 for ns-2045.awsdns-63.co.uk
Querying 205.251.193.127 for ns-2045.awsdns-63.co.uk
Querying 205.251.199.253 for codingchallenges.fyi
Here is what we found
54.230.111.49
54.230.111.112
54.230.111.39
54.230.111.127
```

**Verify with: nslookup codingchallenges.fyi**

```
Server:		2001:2020:82ff:8000::1
Address:	2001:2020:82ff:8000::1#53

Non-authoritative answer:
Name:	codingchallenges.fyi
Address: 54.230.111.127
Name:	codingchallenges.fyi
Address: 54.230.111.112
Name:	codingchallenges.fyi
Address: 54.230.111.39
Name:	codingchallenges.fyi
Address: 54.230.111.49
```

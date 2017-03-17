# tools for NS hijacking on AWS

```
# generate a list of NS records (requires AWS auth)
py .\dumpns.py

# check for possible NS hijack using a dumped list for a hosted zone
py .\hijackdns.py -t domain.com -s .\nslist.txt

# check also but append subdomain list to target domain
py .\hijackdns.py -t domain.com -s .\subdomains.txt -a

# check zone and recordset data straight from Route53 (requires AWS auth)
py .\hijackdns.py -r
```

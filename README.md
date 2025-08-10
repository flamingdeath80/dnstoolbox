Python script that checks MX, SPF (includes DNS lookup count), DMARC policy (includes aspf and adkim alignment), DKIM (checks commons selectors: default, selector1, selector2)

It also checks MTA-STS and BIMI records, if their corresponding HTTPS hosted files exist

Dependancies:

dnspython, requests, sys, re

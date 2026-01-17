# Python script that checks MX, SPF (includes DNS lookup count), DMARC policy (includes aspf and adkim alignment), DKIM (checks common selectors: default, selector1, selector2)
# It also checks MTA-STS and BIMI records, if their corresponding HTTPS hosted files exist
# The quality of the checked records are indicated by traffic light colourisation

# Dependancies:
# dnspython, requests, sys, re

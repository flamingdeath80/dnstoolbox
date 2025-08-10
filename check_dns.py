#!/usr/bin/env python3
import dns.resolver
import requests
import sys
import re

# ANSI colours
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

def get_dns_records(domain, record_type):
    try:
        answers = dns.resolver.resolve(domain, record_type)
        return [rdata.to_text().strip('"') for rdata in answers]
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
        return []

def fetch_url(url):
    try:
        r = requests.get(
            url,
            headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                              "(KHTML, like Gecko) Chrome/124.0 Safari/537.36",
                "Accept": "*/*"
            },
            timeout=5,
            allow_redirects=True
        )
        return r.status_code, r.text
    except requests.RequestException as e:
        return None, str(e)

def colour_result(records, status="ok"):
    if status == "missing":
        return RED + str(records) + RESET
    elif status == "warn":
        return YELLOW + str(records) + RESET
    else:
        return GREEN + str(records) + RESET

def count_spf_lookups(spf_record):
    # Count DNS mechanisms/modifiers that cause lookups
    # https://tools.ietf.org/html/rfc7208#section-5
    # include, a, mx, ptr, exists, redirect
    lookup_mechanisms = re.findall(r'(include:|a\b|mx\b|ptr\b|exists:|redirect=)', spf_record)
    return len(lookup_mechanisms)

def check_mx(domain):
    mx_records = get_dns_records(domain, 'MX')
    return mx_records, "ok" if mx_records else "missing"

def check_spf(domain):
    txt_records = get_dns_records(domain, 'TXT')
    spf_records = [r for r in txt_records if r.startswith('v=spf1')]
    if not spf_records:
        return ["No SPF record found"], "missing"
    spf = spf_records[0]
    lookup_count = count_spf_lookups(spf)
    if lookup_count > 10:
        status = "warn"  # yellow warning
    else:
        status = "ok"
    return [spf, f"DNS Lookups: {lookup_count}"], status

def check_dkim(domain, selectors=['default', 'selector1', 'selector2']):
    all_records = []
    found = False
    for selector in selectors:
        dkim_domain = f"{selector}._domainkey.{domain}"
        dkim_records = get_dns_records(dkim_domain, 'TXT')
        if dkim_records:
            found = True
            for rec in dkim_records:
                all_records.append(f"{selector}: {rec}")
    if not found:
        return ["No DKIM record found for selectors: " + ", ".join(selectors)], "missing"
    return all_records, "ok"

def check_dmarc(domain):
    dmarc_domain = f"_dmarc.{domain}"
    dmarc_records = get_dns_records(dmarc_domain, 'TXT')
    if not dmarc_records:
        return ["No DMARC record found"], "missing"

    record_str = " ".join(dmarc_records).lower()

    # Get enforcement
    policy = None
    if "p=" in record_str:
        policy = record_str.split("p=")[1].split(";")[0].strip()

    # Get alignment flags (defaults are relaxed)
    aspf = "r"
    adkim = "r"
    if "aspf=" in record_str:
        aspf = record_str.split("aspf=")[1].split(";")[0].strip()
    if "adkim=" in record_str:
        adkim = record_str.split("adkim=")[1].split(";")[0].strip()

    # Build status message
    status_msg = f"Policy={policy.upper() if policy else 'MISSING'}, ASPF={aspf.upper()}, ADKIM={adkim.upper()}"

    # Determine colour status
    if not policy or policy == "none":
        status = "missing"
    elif policy in ("quarantine", "reject"):
        if aspf == "s" and adkim == "s":
            status = "ok"
        else:
            status = "warn"
    else:
        status = "warn"

    return dmarc_records + [status_msg], status

def check_mta_sts(domain):
    mta_sts_domain = f"_mta-sts.{domain}"
    mta_sts_records = get_dns_records(mta_sts_domain, 'TXT')
    if mta_sts_records:
        url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
        status_code, _ = fetch_url(url)
        if status_code == 200:
            return mta_sts_records + [f"Policy file found at {url}"], "ok"
        elif status_code:
            return mta_sts_records + [f"Policy file missing or inaccessible ({status_code})"], "missing"
        else:
            return mta_sts_records + [f"Error fetching policy file"], "missing"
    return ["No MTA-STS record found"], "missing"

def check_bimi(domain):
    bimi_domain = f"default._bimi.{domain}"
    bimi_records = get_dns_records(bimi_domain, 'TXT')
    if bimi_records:
        logo_url = None
        for rec in bimi_records:
            parts = rec.split(';')
            for part in parts:
                part = part.strip()
                if part.startswith('l='):
                    logo_url = part[2:]
        if logo_url:
            status_code, _ = fetch_url(logo_url)
            if status_code == 200:
                return bimi_records + [f"Logo found at {logo_url}"], "ok"
            elif status_code:
                return bimi_records + [f"Logo missing or inaccessible ({status_code})"], "missing"
            else:
                return bimi_records + [f"Error fetching logo"], "missing"
    return ["No BIMI record found"], "missing"

def main():
    if len(sys.argv) > 1:
        domain = sys.argv[1]
    else:
        domain = input("Enter domain to check: ").strip()

    print("\n--- DNS & Policy Check Results ---")
    for label, check_func in [
        ("MX Records", check_mx),
        ("SPF Record", check_spf),
        ("DKIM Record (selectors=default, selector1, selector2)", check_dkim),
        ("DMARC Record", check_dmarc),
        ("MTA-STS Record", check_mta_sts),
        ("BIMI Record", check_bimi),
    ]:
        records, status = check_func(domain)
        print(f"{label}: {colour_result(records, status)}")

if __name__ == "__main__":
    main()

#!/usr/bin/env bash
# Are the blacklists in dnsbl-check.php still alive?
#
#   bash audit-dnsbls.sh
#
# Each DNSBL publishes test points: 127.0.0.2 is ALWAYS listed and 127.0.0.1 is
# NEVER listed. A zone that fails the first test has stopped publishing data and
# would silently report every address as clean — which is exactly what happened to
# checkers that kept querying SORBS after it shut down in 2024.
#
# Run this every few months, and whenever you add a zone. Anything that fails should
# come out of dnsbl_zones() in dnsbl-check.php.
#
# This tests from YOUR resolver, which may not be the one your server uses. A list
# can pass here and still time out or refuse queries from a hosting provider's
# resolver, so a pass is necessary, not sufficient.

ZONES="
zen.spamhaus.org
bl.spamcop.net
b.barracudacentral.org
dnsbl-1.uceprotect.net
dnsbl.dronebl.org
bl.blocklist.de
psbl.surriel.com
truncate.gbudb.net
dnsbl.spfbl.net
bl.mailspike.net
"

lookup() {   # lookup <name> -> prints answers, one per line
  nslookup -type=A "$1" 2>/dev/null \
    | sed -n '/^Name:/,$p' \
    | grep -i '^Address' \
    | sed 's/.*:[[:space:]]*//' \
    | tr -d '\r'
}

printf '%-26s %-16s %-16s %s\n' ZONE LISTED-TEST CLEAN-TEST VERDICT
printf '%-26s %-16s %-16s %s\n' -------------------------- ---------------- ---------------- -------

for z in $ZONES; do
  hit=$(lookup "2.0.0.127.$z" | head -1)
  miss=$(lookup "1.0.0.127.$z" | head -1)

  if [ -z "$hit" ]; then
    verdict="DEAD or refusing - remove it, or expect 'unavailable'"
  elif case "$hit" in 127.255.255.*) true ;; *) false ;; esac; then
    verdict="refusing this resolver ($hit)"
  elif [ -n "$miss" ]; then
    verdict="BROKEN - lists everything, remove it"
  else
    verdict="ok"
  fi

  printf '%-26s %-16s %-16s %s\n' "$z" "${hit:-none}" "${miss:-none}" "$verdict"
done

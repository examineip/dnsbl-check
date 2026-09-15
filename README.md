# dnsbl-check

Check an IPv4 address against DNS blacklists and the Tor exit list — without the false
"clean" and false "listed" results most blacklist checkers produce.

One dependency-free PHP file you can use as a **library**, from the **command line**, or as an
**HTTP endpoint**. It powers the [IP reputation check on ExamineIP](https://tools.examineip.com/ip-reputation/).

```
$ php dnsbl-check.php 203.0.113.7
```

---

## Why another blacklist checker?

Because the easy way to write one gives wrong answers, and the wrong answers look right.
These are the mistakes this code is built to avoid:

| Mistake | What goes wrong | What dnsbl-check does |
|---|---|---|
| Treating any answer as "listed" | Lists answer `127.255.255.x` when they **refuse** a query (rate limit, or a resolver they don't accept). Naive code reports a listing. | Reports `unavailable` and tells you to check the list directly. |
| Treating a failed query as "not listed" | A timeout or SERVFAIL returns nothing, which looks like a clean result. | PHP's `dns_get_record()` returns `false` on failure and `[]` for a genuine NXDOMAIN — the two are kept apart. |
| Querying dead lists | SORBS shut down in 2024, but its zones still resolve and answer nothing, so every address reads clean. | Dead zones are removed, and `audit-dnsbls.sh` tests every zone's test points so you can catch the next one. |
| Counting Spamhaus PBL as abuse | The Policy Block List covers most residential ranges **by design**. Counting it tells nearly every home user they have a problem. | PBL-only results are reported as `policy`, not `listed`. |
| Reading Mailspike as a blacklist | Mailspike publishes **good** reputation on the same zone (`.14`–`.18`), so a well-behaved sender gets an answer. | `.14` and above is `clean`; lower is `listed`. |
| Hanging on one slow list | A zone whose nameservers vanish costs a full resolver timeout, every time. | A time budget (12 s by default); anything skipped is reported `unavailable`, never clean. |
| Pretending to check Tor | Guessing from ISP names. | Checks the Tor Project's published exit list, cached for an hour. |

---

## Requirements

- PHP 7.4 or newer
- Outbound DNS from the machine it runs on
- cURL (optional — only for the Tor check, which skips itself without it)

**IPv4 only.** DNS blacklists are indexed by IPv4 address.

---

## Usage

### Library

```php
require 'dnsbl-check.php';

$result = dnsbl_check('203.0.113.7');

if (isset($result['error'])) {
    echo $result['error'];
} elseif ($result['counts']['listed'] > 0) {
    echo "Listed on {$result['counts']['listed']} list(s)";
}
```

Options:

```php
dnsbl_check($ip, [
    'zones'       => dnsbl_zones(),  // your own list, same shape
    'tor'         => true,           // check the Tor exit list
    'rdns'        => true,           // look up reverse DNS
    'time_budget' => 12.0,           // seconds before remaining zones are skipped
]);
```

### Command line

```
php dnsbl-check.php 203.0.113.7
```

Prints JSON. Exit code `0` = not listed anywhere, `1` = listed on at least one list, `2` = invalid input —
handy in monitoring scripts:

```
php dnsbl-check.php "$MAIL_SERVER_IP" > /dev/null || echo "Check the blacklists"
```

### HTTP endpoint

Put the file on a PHP server and request:

```
GET /dnsbl-check.php?ip=203.0.113.7
```

With no `ip`, it checks the caller's own address (`REMOTE_ADDR`). Forwarding headers are deliberately
ignored because they can be forged; if you run behind a proxy you control, adapt that line.

---

## Output

```json
{
  "ip": "203.0.113.7",
  "lists": [
    {
      "name": "Spamhaus ZEN",
      "zone": "zen.spamhaus.org",
      "desc": "Combined spam, exploit and policy list",
      "delist": "https://check.spamhaus.org/",
      "codes": ["127.0.0.10"],
      "status": "policy",
      "meaning": "On the Policy Block List, which covers most home connections by design. ...",
      "ms": 41
    }
  ],
  "counts": { "listed": 0, "clean": 9, "policy": 1, "unavailable": 0, "total": 10 },
  "tor":    { "checked": true, "exit": false, "age": 812, "note": "Not on the current Tor exit node list." },
  "rdns":   "host.example.net",
  "risk":   { "level": "clean", "strikes": 0, "reasons": ["On Spamhaus PBL, which is normal for a home connection."] },
  "took":   1210
}
```

| `status` | Meaning |
|---|---|
| `clean` | The list answered and the address is not on it |
| `listed` | The address is on the list |
| `policy` | Spamhaus PBL only — normal for home connections |
| `unavailable` | No usable answer (refused, timed out, or skipped). **Not** a clean result |

`risk.level` is `clean`, `caution` (1–2 strikes) or `flagged` (3+). Each listing is one strike; a Tor exit
node is two.

---

## Lists checked

| List | Zone | Delisting |
|---|---|---|
| Spamhaus ZEN | `zen.spamhaus.org` | [check.spamhaus.org](https://check.spamhaus.org/) |
| SpamCop | `bl.spamcop.net` | [spamcop.net](https://www.spamcop.net/bl.shtml) |
| Barracuda | `b.barracudacentral.org` | [barracudacentral.org](https://www.barracudacentral.org/rbl/removal-request) |
| UCEPROTECT L1 | `dnsbl-1.uceprotect.net` | [uceprotect.net](https://www.uceprotect.net/en/rblcheck.php) |
| DroneBL | `dnsbl.dronebl.org` | [dronebl.org](https://dronebl.org/lookup) |
| blocklist.de | `bl.blocklist.de` | [blocklist.de](https://www.blocklist.de/en/delist.html) |
| PSBL | `psbl.surriel.com` | [psbl.org](https://psbl.org/remove) |
| GBUdb Truncate | `truncate.gbudb.net` | [gbudb.com](http://www.gbudb.com/truncate/index.jsp) |
| SPFBL | `dnsbl.spfbl.net` | [spfbl.net](https://spfbl.net/en/dnsbl/) |
| Mailspike | `bl.mailspike.net` | [mailspike.org](https://www.mailspike.org/iplookup.html) |

Deliberately left out: **SORBS** (shut down in 2024) and **SpamRats** (drops queries from some networks,
costing a timeout per lookup — add it back if it answers from yours).

### ⚠️ Usage policies

Most DNSBLs are free for **low-volume, non-commercial** use and have their own terms. Spamhaus in
particular refuses queries that arrive via large public resolvers (such as 8.8.8.8 or 1.1.1.1) and
requires a paid Data Query Service account for commercial or high-volume use. If Spamhaus always comes
back `unavailable`, that is usually why — run your own recursive resolver or use their service.
**Check each list's terms before using this in production.**

---

## Keeping the list honest

Lists die quietly. Every DNSBL publishes test points: `127.0.0.2` is always listed and `127.0.0.1` never is.

```
bash audit-dnsbls.sh
```

checks both for every zone and flags anything dead, refusing, or broken. Run it every few months and
whenever you add a zone. It uses **your** resolver, which may not be your server's — a zone passing the
audit is necessary, not sufficient.

---

## Tests

```
php tests/interpret-test.php
```

Covers refusals, the Spamhaus PBL/abuse split, Mailspike's reputation scale, and input validation —
no network or framework needed.

---

## Licence

MIT — see [LICENSE](LICENSE).

Built by [ExamineIP](https://examineip.com/), which has free IP, DNS and network tools at
[tools.examineip.com](https://tools.examineip.com/) and a guide to
[getting an IP address removed from a blacklist](https://examineip.com/ip-address-blacklist/).

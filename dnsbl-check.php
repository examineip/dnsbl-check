<?php
/**
 * dnsbl-check — check an IPv4 address against DNS blacklists and the Tor exit list,
 * without the false "clean" and false "listed" results most checkers produce.
 *
 * Three ways to use it:
 *
 *   Library   require 'dnsbl-check.php';  $result = dnsbl_check('203.0.113.7');
 *   CLI       php dnsbl-check.php 203.0.113.7
 *   HTTP      GET /dnsbl-check.php?ip=203.0.113.7
 *
 * Requires PHP 7.4+. The Tor check uses cURL if available and skips itself if not.
 *
 * MIT licence — https://github.com/examineip/dnsbl-check
 */

const DNSBL_TOR_LIST_URL  = 'https://check.torproject.org/torbulkexitlist';
const DNSBL_TOR_TTL       = 3600;   // seconds to cache the Tor exit list
const DNSBL_TIME_BUDGET   = 12.0;   // stop querying after this many seconds and say so

/**
 * The blacklists queried by default. Each zone answered its 127.0.0.2 test point
 * when this list was last audited (see audit-dnsbls.sh).
 *
 * Deliberately absent:
 *   SORBS     — shut down in 2024. The zones still resolve but return nothing,
 *               so a checker that still queries them reports every address clean.
 *   SpamRats  — answers normally from some networks and silently drops queries
 *               from others (seen from a shared-hosting resolver: a 9-second
 *               timeout on every lookup). Add it back if it answers from yours.
 *
 * Check each list's usage policy before querying it from a commercial service or at
 * volume. Spamhaus in particular only allows low-volume, non-commercial use of its
 * public mirrors.
 */
function dnsbl_zones(): array
{
    return array(
        array('name' => 'Spamhaus ZEN',   'zone' => 'zen.spamhaus.org',       'desc' => 'Combined spam, exploit and policy list',  'delist' => 'https://check.spamhaus.org/'),
        array('name' => 'SpamCop',        'zone' => 'bl.spamcop.net',         'desc' => 'Addresses reported by spam recipients',   'delist' => 'https://www.spamcop.net/bl.shtml'),
        array('name' => 'Barracuda',      'zone' => 'b.barracudacentral.org', 'desc' => 'Barracuda Reputation Block List',         'delist' => 'https://www.barracudacentral.org/rbl/removal-request'),
        array('name' => 'UCEPROTECT L1',  'zone' => 'dnsbl-1.uceprotect.net', 'desc' => 'Single addresses caught sending spam',    'delist' => 'https://www.uceprotect.net/en/rblcheck.php'),
        array('name' => 'DroneBL',        'zone' => 'dnsbl.dronebl.org',      'desc' => 'Compromised machines and open proxies',   'delist' => 'https://dronebl.org/lookup'),
        array('name' => 'blocklist.de',   'zone' => 'bl.blocklist.de',        'desc' => 'Addresses reported attacking services',   'delist' => 'https://www.blocklist.de/en/delist.html'),
        array('name' => 'PSBL',           'zone' => 'psbl.surriel.com',       'desc' => 'Passive Spam Block List (spamtrap hits)', 'delist' => 'https://psbl.org/remove'),
        array('name' => 'GBUdb Truncate', 'zone' => 'truncate.gbudb.net',     'desc' => 'Sources that only ever send spam',        'delist' => 'http://www.gbudb.com/truncate/index.jsp'),
        array('name' => 'SPFBL',          'zone' => 'dnsbl.spfbl.net',        'desc' => 'Community-reported reputation list',      'delist' => 'https://spfbl.net/en/dnsbl/'),
        array('name' => 'Mailspike',      'zone' => 'bl.mailspike.net',       'desc' => 'Mail sending reputation, good and bad',   'delist' => 'https://www.mailspike.org/iplookup.html'),
    );
}

/** Validate a public IPv4 address. Returns an error message, or null if it is usable. */
function dnsbl_validate_ip(string $ip): ?string
{
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        return 'Supply a single IPv4 address. DNS blacklists are indexed by IPv4.';
    }
    if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
        return 'That is a private or reserved address, so it has no public reputation.';
    }
    return null;
}

/** 203.0.113.7 -> 7.113.0.203, the form DNSBL zones are queried with. */
function dnsbl_reverse_ipv4(string $ip): string
{
    return implode('.', array_reverse(explode('.', $ip)));
}

/**
 * Interpret the A records a zone returned for an address.
 *
 * Returns array('status' => clean|listed|policy|unavailable, 'meaning' => string).
 *
 *  - 127.255.255.x is NOT a listing. It is the list refusing to answer (rate limit,
 *    or a resolver it does not accept queries from). Naive code reads it as "listed".
 *  - Spamhaus ZEN return codes 127.0.0.10 and .11 are the Policy Block List: most
 *    residential ranges are on it by design, so it is reported as "policy", not abuse.
 *  - Mailspike publishes good reputation as well as bad on the same zone, on a scale
 *    from .10 (worst) to .18 (best). .14 and above is neutral to good and is not a
 *    listing; anything lower, including a plain .2, is.
 */
function dnsbl_interpret(string $zone, array $codes): array
{
    foreach ($codes as $c) {
        if (strpos($c, '127.255.255.') === 0) {
            return array('status' => 'unavailable',
                         'meaning' => 'The list refused this query (rate limit, or it does not accept queries from this resolver). Check it directly.');
        }
    }
    if (!$codes) {
        return array('status' => 'clean', 'meaning' => 'Not listed.');
    }

    $last = function (string $c): int { return (int) substr($c, strrpos($c, '.') + 1); };

    if ($zone === 'bl.mailspike.net') {
        foreach ($codes as $c) {
            if ($last($c) < 14) {
                return array('status' => 'listed', 'meaning' => 'Poor mail sending reputation.');
            }
        }
        return array('status' => 'clean', 'meaning' => 'Rated neutral to good as a mail sender, which is not a listing.');
    }

    if ($zone === 'zen.spamhaus.org') {
        $why = array();
        $abuse = false;
        foreach ($codes as $c) {
            $n = $last($c);
            if ($n === 2 || $n === 3)       { $why[] = 'known spam source (SBL)';               $abuse = true; }
            elseif ($n >= 4 && $n <= 7)     { $why[] = 'compromised device or proxy (XBL/CSS)'; $abuse = true; }
            elseif ($n === 9)               { $why[] = 'hijacked network range (DROP)';         $abuse = true; }
            elseif ($n === 10 || $n === 11) { $why[] = 'end-user address (PBL)'; }
            else                            { $abuse = true; }
        }
        if (!$abuse) {
            return array('status' => 'policy',
                         'meaning' => 'On the Policy Block List, which covers most home connections by design. It only matters when sending mail directly from this address instead of through a mail provider.');
        }
        $why = array_values(array_unique($why));
        return array('status' => 'listed', 'meaning' => $why ? ucfirst(implode('; ', $why)) . '.' : 'Listed.');
    }

    return array('status' => 'listed', 'meaning' => 'Listed on this blacklist.');
}

/**
 * Query one DNSBL name. Returns the list of A-record addresses, or FALSE if the query
 * itself failed (timeout, SERVFAIL). An empty array is a genuine "not listed".
 * Treating both as clean is the most common false all-clear in DNSBL checkers.
 */
function dnsbl_query(string $name)
{
    $records = @dns_get_record($name, DNS_A);
    if ($records === false) {
        return false;
    }
    $codes = array();
    foreach ($records as $r) {
        if (isset($r['ip'])) {
            $codes[] = $r['ip'];
        }
    }
    return $codes;
}

/** Check an address against the Tor Project's published exit list (cached for an hour). */
function dnsbl_tor_exit(string $ip, ?string $cacheFile = null): array
{
    $cacheFile = $cacheFile ?? sys_get_temp_dir() . '/dnsbl-check-tor-exits.txt';
    $fresh = is_readable($cacheFile) && (time() - filemtime($cacheFile) < DNSBL_TOR_TTL);

    if (!$fresh && function_exists('curl_init')) {
        $ch = curl_init(DNSBL_TOR_LIST_URL);
        curl_setopt_array($ch, array(
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT        => 8,
            CURLOPT_CONNECTTIMEOUT => 4,
            CURLOPT_USERAGENT      => 'dnsbl-check (+https://github.com/examineip/dnsbl-check)',
        ));
        $body = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($body !== false && $code === 200 && strlen($body) > 100) {
            @file_put_contents($cacheFile, $body);
        }
    }

    if (!is_readable($cacheFile)) {
        return array('checked' => false, 'exit' => null, 'age' => null,
                     'note' => 'Could not fetch the Tor exit list, so this check was skipped.');
    }

    $hit = preg_match('/^' . preg_quote($ip, '/') . '$/m', (string) file_get_contents($cacheFile)) === 1;
    return array(
        'checked' => true,
        'exit'    => $hit,
        'age'     => time() - filemtime($cacheFile),
        'note'    => $hit ? 'On the current Tor exit node list.' : 'Not on the current Tor exit node list.',
    );
}

/**
 * Check an IPv4 address. Options:
 *   zones        array   zone definitions (default dnsbl_zones())
 *   tor          bool    check the Tor exit list (default true)
 *   rdns         bool    look up reverse DNS (default true)
 *   time_budget  float   seconds before remaining zones are skipped (default 12)
 */
function dnsbl_check(string $ip, array $opts = array()): array
{
    $ip = trim($ip);
    $opts += array('zones' => dnsbl_zones(), 'tor' => true, 'rdns' => true, 'time_budget' => DNSBL_TIME_BUDGET);

    if (($error = dnsbl_validate_ip($ip)) !== null) {
        return array('ip' => $ip, 'error' => $error);
    }

    $reversed = dnsbl_reverse_ipv4($ip);
    $started  = microtime(true);
    $lists    = array();
    $counts   = array('listed' => 0, 'clean' => 0, 'policy' => 0, 'unavailable' => 0, 'total' => count($opts['zones']));

    foreach ($opts['zones'] as $z) {
        $row = array('name' => $z['name'], 'zone' => $z['zone'], 'desc' => $z['desc'] ?? '', 'delist' => $z['delist'] ?? '', 'codes' => array());

        // A list whose nameservers have gone away costs a full resolver timeout each.
        // Stop rather than hang, and report the rest as unchecked — never as clean.
        if (microtime(true) - $started > $opts['time_budget']) {
            $row += array('status' => 'unavailable', 'meaning' => 'Skipped: earlier lookups used up the time budget. Check this list directly.', 'ms' => 0);
            $counts['unavailable']++;
            $lists[] = $row;
            continue;
        }

        $t0 = microtime(true);
        $codes = dnsbl_query($reversed . '.' . $z['zone']);
        if ($codes === false) {
            $verdict = array('status' => 'unavailable', 'meaning' => 'The list did not answer (timeout or server failure). Check it directly.');
        } else {
            $row['codes'] = $codes;
            $verdict = dnsbl_interpret($z['zone'], $codes);
        }
        $row += $verdict + array('ms' => (int) round((microtime(true) - $t0) * 1000));
        $counts[$verdict['status']]++;
        $lists[] = $row;
    }

    $tor = $opts['tor'] ? dnsbl_tor_exit($ip) : array('checked' => false, 'exit' => null, 'age' => null, 'note' => 'Tor check disabled.');

    $rdns = null;
    if ($opts['rdns']) {
        $host = @gethostbyaddr($ip);
        if ($host && $host !== $ip) {
            $rdns = $host;
        }
    }

    $reasons = array();
    $strikes = $counts['listed'];
    if ($counts['listed'])      { $reasons[] = 'Listed on ' . $counts['listed'] . ' of ' . $counts['total'] . ' blacklists queried.'; }
    if ($counts['policy'])      { $reasons[] = 'On Spamhaus PBL, which is normal for a home connection.'; }
    if ($counts['unavailable']) { $reasons[] = $counts['unavailable'] . ' list(s) did not give an answer, so the result is incomplete.'; }
    if (!empty($tor['exit']))   { $strikes += 2; $reasons[] = 'Published Tor exit node.'; }
    if ($opts['rdns'] && $rdns === null) { $reasons[] = 'No reverse DNS record, which many mail servers penalise on its own.'; }

    $level = $strikes === 0 ? 'clean' : ($strikes <= 2 ? 'caution' : 'flagged');

    return array(
        'ip'     => $ip,
        'lists'  => $lists,
        'counts' => $counts,
        'tor'    => $tor,
        'rdns'   => $rdns,
        'risk'   => array('level' => $level, 'strikes' => $strikes, 'reasons' => $reasons),
        'took'   => (int) round((microtime(true) - $started) * 1000),
    );
}

/* ---------- entry points: only when this file is run directly, not when included ---------- */

$__dnsbl_main = isset($_SERVER['SCRIPT_FILENAME']) && realpath($_SERVER['SCRIPT_FILENAME']) === realpath(__FILE__);

if ($__dnsbl_main && PHP_SAPI === 'cli') {
    $result = dnsbl_check($argv[1] ?? '');
    echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE), PHP_EOL;
    // Exit codes: 0 = not listed anywhere, 1 = listed on at least one list, 2 = invalid input.
    exit(isset($result['error']) ? 2 : ($result['counts']['listed'] > 0 ? 1 : 0));
}

if ($__dnsbl_main) {
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    // Defaults to the caller's own address. REMOTE_ADDR is used deliberately: forwarding
    // headers such as X-Forwarded-For can be forged unless you sit behind a proxy you control.
    $ip = isset($_GET['ip']) && $_GET['ip'] !== '' ? (string) $_GET['ip'] : ($_SERVER['REMOTE_ADDR'] ?? '');
    $result = dnsbl_check($ip);
    if (isset($result['error'])) {
        http_response_code(400);
    }
    echo json_encode($result, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
}

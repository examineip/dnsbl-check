<?php
/**
 * Offline tests for the parts of dnsbl-check that are easy to get wrong.
 * No network, no framework:   php tests/interpret-test.php
 */

require __DIR__ . '/../dnsbl-check.php';

$failures = 0;
$passes = 0;

function check(string $label, $actual, $expected): void
{
    global $failures, $passes;
    if ($actual === $expected) {
        $passes++;
        return;
    }
    $failures++;
    echo "FAIL  $label\n      expected: " . var_export($expected, true) . "\n      actual:   " . var_export($actual, true) . "\n";
}

$status = function (string $zone, array $codes): string {
    return dnsbl_interpret($zone, $codes)['status'];
};

// Refusals are never listings, on any zone.
check('Spamhaus refusal 127.255.255.254',  $status('zen.spamhaus.org', array('127.255.255.254')), 'unavailable');
check('Spamhaus refusal 127.255.255.252',  $status('zen.spamhaus.org', array('127.255.255.252')), 'unavailable');
check('refusal on another zone',           $status('bl.spamcop.net', array('127.255.255.255')), 'unavailable');
check('refusal wins over a real code',     $status('zen.spamhaus.org', array('127.0.0.2', '127.255.255.254')), 'unavailable');

// Empty answer = genuinely not listed.
check('empty answer is clean',             $status('bl.spamcop.net', array()), 'clean');

// Spamhaus ZEN: PBL is policy, everything else is abuse.
check('ZEN PBL .10 is policy',             $status('zen.spamhaus.org', array('127.0.0.10')), 'policy');
check('ZEN PBL .11 is policy',             $status('zen.spamhaus.org', array('127.0.0.11')), 'policy');
check('ZEN PBL .10 + .11 is policy',       $status('zen.spamhaus.org', array('127.0.0.10', '127.0.0.11')), 'policy');
check('ZEN SBL .2 is listed',              $status('zen.spamhaus.org', array('127.0.0.2')), 'listed');
check('ZEN XBL .4 is listed',              $status('zen.spamhaus.org', array('127.0.0.4')), 'listed');
check('ZEN DROP .9 is listed',             $status('zen.spamhaus.org', array('127.0.0.9')), 'listed');
check('ZEN PBL + SBL is listed',           $status('zen.spamhaus.org', array('127.0.0.11', '127.0.0.2')), 'listed');
check('ZEN unknown code is listed',        $status('zen.spamhaus.org', array('127.0.0.20')), 'listed');

// Mailspike: .14-.18 is good reputation, lower is a listing.
check('Mailspike .14 is clean',            $status('bl.mailspike.net', array('127.0.0.14')), 'clean');
check('Mailspike .18 is clean',            $status('bl.mailspike.net', array('127.0.0.18')), 'clean');
check('Mailspike .10 is listed',           $status('bl.mailspike.net', array('127.0.0.10')), 'listed');
check('Mailspike .13 is listed',           $status('bl.mailspike.net', array('127.0.0.13')), 'listed');
check('Mailspike plain .2 is listed',      $status('bl.mailspike.net', array('127.0.0.2')), 'listed');

// Any other zone: any non-refusal answer is a listing.
check('SpamCop .2 is listed',              $status('bl.spamcop.net', array('127.0.0.2')), 'listed');

// Address handling.
check('reverse IPv4',                      dnsbl_reverse_ipv4('203.0.113.7'), '7.113.0.203');
check('public IPv4 accepted',              dnsbl_validate_ip('8.8.8.8'), null);
check('private IPv4 rejected',             dnsbl_validate_ip('192.168.1.1') !== null, true);
check('loopback rejected',                 dnsbl_validate_ip('127.0.0.1') !== null, true);
check('IPv6 rejected',                     dnsbl_validate_ip('2001:4860:4860::8888') !== null, true);
check('garbage rejected',                  dnsbl_validate_ip('not-an-ip') !== null, true);
check('dnsbl_check returns error field',   isset(dnsbl_check('10.0.0.1')['error']), true);

// Zone list sanity: no retired SORBS zones, every entry complete.
$zones = dnsbl_zones();
check('ten zones by default',              count($zones), 10);
check('no SORBS zones',                    count(array_filter($zones, function ($z) { return stripos($z['zone'], 'sorbs') !== false; })), 0);
check('every zone has name/zone/delist',   count(array_filter($zones, function ($z) { return !empty($z['name']) && !empty($z['zone']) && !empty($z['delist']); })), count($zones));

echo "\n$passes passed, $failures failed\n";
exit($failures ? 1 : 0);

<?php
declare(strict_types=1);

/**
 * DNS providers. ALL provider API calls happen here, on the control server.
 * Agents never hold a DNS credential and never talk to a provider.
 *
 * Model:
 *   DNS ACCOUNT  = one provider + one credential, configured once by an admin
 *                  (Settings -> DNS accounts). Secrets are sealed at rest and
 *                  write-only in the UI.
 *   DNS TARGET   = one hostname kept pointed at one agent, through an account.
 *                  Usually just a name; a provider that needs per-host auth
 *                  (FreeDNS) declares target_fields.
 *
 * 'creates' = one account credential can create brand-new names in its
 * domain. Only those accounts offer random subdomain generation, because an
 * update-only protocol (dyndns2, DuckDNS) can't push to a name that doesn't
 * already exist at the provider.
 */

function providers(): array
{
    return [
        'cloudflare' => [
            'label'   => 'Cloudflare',
            'creates' => true,
            'verify'  => 'api',
            'fields'  => [
                ['key' => 'api_token', 'label' => 'API token', 'type' => 'secret', 'required' => true,
                 'help' => 'My Profile → API Tokens → "Edit zone DNS" template, limited to the zone(s) you use.'],
                ['key' => 'zone_id', 'label' => 'Zone ID (optional)', 'type' => 'text',
                 'help' => 'Leave blank to look the zone up from each hostname.'],
            ],
            'target_fields' => [],
        ],
        'powerdns' => [
            'label'   => 'PowerDNS (Authoritative HTTP API)',
            'creates' => true,
            'verify'  => 'api',
            'fields'  => [
                ['key' => 'api_url', 'label' => 'API URL', 'type' => 'text', 'required' => true,
                 'help' => 'e.g. http://10.20.0.53:8081 (webserver + api enabled in pdns.conf). /api/v1 is added for you.'],
                ['key' => 'api_key', 'label' => 'API key', 'type' => 'secret', 'required' => true,
                 'help' => 'The api-key value from pdns.conf.'],
                ['key' => 'server_id', 'label' => 'Server ID', 'type' => 'text', 'default' => 'localhost'],
                ['key' => 'zone', 'label' => 'Zone (optional)', 'type' => 'text',
                 'help' => 'Leave blank to pick the longest matching zone automatically.'],
                ['key' => 'notify', 'label' => 'Send NOTIFY to secondaries after each change', 'type' => 'bool'],
            ],
            'target_fields' => [],
        ],
        'dyndns2' => [
            'label'   => 'DynDNS-compatible (No-IP, Dynu, Dyn, ChangeIP, OVH, custom)',
            'creates' => false,
            'verify'  => 'resolver',
            'fields'  => [
                ['key' => 'preset', 'label' => 'Service', 'type' => 'select', 'required' => true,
                 'options' => array_map(fn($p) => $p['label'], dyndns2_presets())],
                ['key' => 'update_url', 'label' => 'Update URL (custom only)', 'type' => 'text',
                 'help' => 'Must contain {hostname} and {ip}. Ignored unless Service is Custom.'],
                ['key' => 'username', 'label' => 'Username', 'type' => 'text'],
                ['key' => 'password', 'label' => 'Password / update key', 'type' => 'secret'],
            ],
            'target_fields' => [],
        ],
        'duckdns' => [
            'label'   => 'DuckDNS',
            'creates' => false,
            'verify'  => 'resolver',
            'fields'  => [
                ['key' => 'token', 'label' => 'Account token', 'type' => 'secret', 'required' => true],
            ],
            'target_fields' => [],
        ],
        'freedns' => [
            'label'   => 'FreeDNS (afraid.org)',
            'creates' => false,
            'verify'  => 'resolver',
            'fields'  => [],
            // afraid.org issues an update token per host, so it lives on the target.
            'target_fields' => [
                ['key' => 'host_token', 'label' => 'Host update token', 'type' => 'secret', 'required' => true,
                 'help' => 'From "Dynamic DNS" → the random token in that host\'s v2 update URL.'],
            ],
        ],
        'none' => [
            'label'   => 'None — track the IP only (allowlist feeds, alerts)',
            'creates' => false,
            'verify'  => 'none',
            'fields'  => [],
            'target_fields' => [],
        ],
    ];
}

function dyndns2_presets(): array
{
    return [
        'noip'     => ['label' => 'No-IP',    'url' => 'https://dynupdate.no-ip.com/nic/update?hostname={hostname}&myip={ip}'],
        'dynu'     => ['label' => 'Dynu',     'url' => 'https://api.dynu.com/nic/update?hostname={hostname}&myip={ip}'],
        'dyn'      => ['label' => 'Dyn (Oracle)', 'url' => 'https://members.dyndns.org/v3/update?hostname={hostname}&myip={ip}'],
        'changeip' => ['label' => 'ChangeIP', 'url' => 'https://nic.changeip.com/nic/update?hostname={hostname}&myip={ip}'],
        'ovh'      => ['label' => 'OVH DynHost', 'url' => 'https://www.ovh.com/nic/update?system=dyndns&hostname={hostname}&myip={ip}'],
        'custom'   => ['label' => 'Custom (enter URL)', 'url' => ''],
    ];
}

function provider_meta(string $provider): array
{
    $p = providers()[$provider] ?? null;
    if (!$p) {
        throw new InvalidArgumentException("unknown provider $provider");
    }
    return $p;
}

/**
 * Validates and merges a submitted account form. Secret fields left blank
 * keep their stored value (write-only fields are never rendered back).
 * @return array{0: array, 1: string[]}  [config, errors]
 */
function provider_account_from_input(string $provider, array $in, array $existing = []): array
{
    $meta = provider_meta($provider);
    $cfg = [];
    $errors = [];
    foreach ($meta['fields'] as $f) {
        $k = $f['key'];
        $v = $in[$k] ?? null;
        switch ($f['type']) {
            case 'bool':
                $cfg[$k] = !empty($v);
                break;
            case 'secret':
                $v = trim((string)$v);
                $cfg[$k] = $v !== '' ? $v : (string)($existing[$k] ?? '');
                break;
            case 'select':
                $v = (string)$v;
                $opts = $f['options'];
                $cfg[$k] = array_key_exists($v, $opts) ? $v : '';
                break;
            default:
                $cfg[$k] = trim((string)$v);
                if ($cfg[$k] === '' && isset($f['default'])) {
                    $cfg[$k] = $f['default'];
                }
        }
        if (!empty($f['required']) && ($cfg[$k] === '' || $cfg[$k] === null)) {
            $errors[] = $f['label'] . ' is required.';
        }
    }
    $domain = strtolower(trim((string)($in['domain'] ?? ($existing['domain'] ?? '')), " ."));
    if ($domain !== '' && !valid_hostname($domain)) {
        $errors[] = 'Domain for generated names is not a valid domain.';
    }
    $cfg['domain'] = $domain;

    if ($provider === 'dyndns2') {
        if (($cfg['preset'] ?? '') === 'custom') {
            $u = $cfg['update_url'] ?? '';
            if (!preg_match('#^https?://#i', $u) || strpos($u, '{hostname}') === false || strpos($u, '{ip}') === false) {
                $errors[] = 'Custom update URL must start with http(s):// and contain {hostname} and {ip}.';
            }
        }
    }
    if ($provider === 'powerdns') {
        if (!preg_match('#^https?://#i', $cfg['api_url'] ?? '')) {
            $errors[] = 'PowerDNS API URL must start with http:// or https://';
        }
        if (!preg_match('/^[A-Za-z0-9._-]+$/', $cfg['server_id'] ?? '')) {
            $errors[] = 'PowerDNS server ID has invalid characters.';
        }
    }
    return [$cfg, $errors];
}

/** @return array{0: array, 1: string[]} */
function provider_target_from_input(string $provider, array $in, array $existing = []): array
{
    $meta = provider_meta($provider);
    $cfg = [];
    $errors = [];
    foreach ($meta['target_fields'] as $f) {
        $k = $f['key'];
        $v = trim((string)($in['tf_' . $k] ?? ''));
        if ($f['type'] === 'secret' && $v === '') {
            $v = (string)($existing[$k] ?? '');
        }
        $cfg[$k] = $v;
        if (!empty($f['required']) && $v === '') {
            $errors[] = $f['label'] . ' is required for this provider.';
        }
    }
    return [$cfg, $errors];
}

/** A random, DNS-safe label: 12 chars of [a-z0-9] minus look-alikes (~60 bits). */
function random_dns_label(int $len = 12): string
{
    $alphabet = 'abcdefghjkmnpqrstuvwxyz23456789';
    $out = '';
    $max = strlen($alphabet) - 1;
    for ($i = 0; $i < $len; $i++) {
        $out .= $alphabet[random_int(0, $max)];
    }
    // Labels must start with a letter for maximum resolver/provider compatibility.
    if (ctype_digit($out[0])) {
        $out[0] = $alphabet[random_int(0, 22)];
    }
    return $out;
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/** @return array{ok: bool, detail: string} */
function provider_push(array $account, array $target, string $ip): array
{
    $cfg = decrypt_json($account['config_enc']);
    $tcfg = $target['target_config_enc'] !== '' ? decrypt_json($target['target_config_enc']) : [];
    $host = rtrim(strtolower($target['hostname']), '.');
    try {
        switch ($account['provider']) {
            case 'cloudflare': return cf_push($cfg, $host, $ip, (int)$target['ttl'], (bool)$target['proxied']);
            case 'powerdns':   return pdns_push($cfg, $host, $ip, (int)$target['ttl']);
            case 'dyndns2':    return dyndns2_push($cfg, $host, $ip);
            case 'duckdns':    return duckdns_push($cfg, $host, $ip);
            case 'freedns':    return freedns_push($tcfg, $host, $ip);
            case 'none':       return ['ok' => true, 'detail' => 'Tracking only (no DNS record)'];
        }
    } catch (Throwable $e) {
        return ['ok' => false, 'detail' => 'Internal error: ' . $e->getMessage()];
    }
    return ['ok' => false, 'detail' => 'Unknown provider'];
}

/**
 * What the provider currently publishes, for drift detection.
 * @return array{ip: ?string, detail: string, method: string}|null  null = can't verify
 */
function provider_lookup(array $account, array $target): ?array
{
    $cfg = decrypt_json($account['config_enc']);
    $host = rtrim(strtolower($target['hostname']), '.');
    try {
        switch ($account['provider']) {
            case 'cloudflare': return cf_lookup($cfg, $host);
            case 'powerdns':   return pdns_lookup($cfg, $host);
            case 'none':       return null;
            default:
                $recs = @dns_get_record($host, DNS_A);
                if ($recs === false) {
                    return ['ip' => null, 'detail' => 'resolver lookup failed', 'method' => 'resolver'];
                }
                $ips = array_column($recs, 'ip');
                return ['ip' => $ips[0] ?? null, 'detail' => $ips ? implode(', ', $ips) : 'no A record', 'method' => 'resolver'];
        }
    } catch (Throwable $e) {
        return ['ip' => null, 'detail' => $e->getMessage(), 'method' => 'error'];
    }
}

/** Non-destructive credential check for the account page. @return array{ok: bool, detail: string} */
function provider_test(string $provider, array $cfg): array
{
    switch ($provider) {
        case 'cloudflare':
            $r = http_json('GET', cf_base() . '/user/tokens/verify', cf_headers($cfg));
            if (($r['json']['success'] ?? false) && ($r['json']['result']['status'] ?? '') === 'active') {
                return ['ok' => true, 'detail' => 'Token is valid and active.'];
            }
            return ['ok' => false, 'detail' => cf_error($r)];
        case 'powerdns':
            $r = http_json('GET', pdns_base($cfg) . '/servers/' . rawurlencode($cfg['server_id'] ?: 'localhost'), pdns_headers($cfg));
            if ($r['status'] === 200) {
                return ['ok' => true, 'detail' => 'Connected: PowerDNS ' . ($r['json']['version'] ?? '') . ' (' . ($r['json']['daemon_type'] ?? '') . ')'];
            }
            return ['ok' => false, 'detail' => pdns_error($r)];
        case 'none':
            return ['ok' => true, 'detail' => 'Nothing to test.'];
        default:
            return ['ok' => true, 'detail' => 'This provider has no read-only test; the first push will confirm the credentials.'];
    }
}

// ---------------------------------------------------------------------------
// Cloudflare
// ---------------------------------------------------------------------------

function cf_base(): string
{
    return rtrim((string)(app_config('cloudflare_api_base') ?: 'https://api.cloudflare.com/client/v4'), '/');
}

function cf_headers(array $cfg): array
{
    return ['Authorization' => 'Bearer ' . ($cfg['api_token'] ?? '')];
}

function cf_error(array $r): string
{
    if ($r['error']) return 'Cloudflare unreachable: ' . $r['error'];
    $m = $r['json']['errors'][0]['message'] ?? null;
    return 'Cloudflare HTTP ' . $r['status'] . ($m ? ": $m" : '');
}

function cf_zone_id(array $cfg, string $host): ?string
{
    if (!empty($cfg['zone_id'])) {
        return $cfg['zone_id'];
    }
    $labels = explode('.', $host);
    for ($i = 0; $i < count($labels) - 1; $i++) {
        $candidate = implode('.', array_slice($labels, $i));
        $r = http_json('GET', cf_base() . '/zones?name=' . rawurlencode($candidate), cf_headers($cfg));
        if (!empty($r['json']['result'][0]['id'])) {
            return $r['json']['result'][0]['id'];
        }
    }
    return null;
}

function cf_records(array $cfg, string $zone, string $host): array
{
    $r = http_json('GET', cf_base() . "/zones/$zone/dns_records?type=A&name=" . rawurlencode($host), cf_headers($cfg));
    if (!($r['json']['success'] ?? false)) {
        throw new RuntimeException(cf_error($r));
    }
    return $r['json']['result'] ?? [];
}

function cf_push(array $cfg, string $host, string $ip, int $ttl, bool $proxied): array
{
    $zone = cf_zone_id($cfg, $host);
    if (!$zone) {
        return ['ok' => false, 'detail' => "No Cloudflare zone found for $host (check the token's zone access)"];
    }
    try {
        $records = cf_records($cfg, $zone, $host);
    } catch (RuntimeException $e) {
        return ['ok' => false, 'detail' => $e->getMessage()];
    }
    if (count($records) > 1) {
        // Two A records = round-robin between an old and new address. For an
        // allowlist that is never what anyone wants, and silently "fixing" it
        // could delete a record someone added on purpose.
        return ['ok' => false, 'detail' => count($records) . " A records exist for $host — remove the extras in Cloudflare"];
    }
    $body = ['type' => 'A', 'name' => $host, 'content' => $ip, 'ttl' => max(60, $ttl), 'proxied' => $proxied];
    if ($records) {
        $r = http_json('PATCH', cf_base() . "/zones/$zone/dns_records/" . $records[0]['id'], cf_headers($cfg), $body);
        $verb = 'Updated';
    } else {
        $r = http_json('POST', cf_base() . "/zones/$zone/dns_records", cf_headers($cfg), $body);
        $verb = 'Created';
    }
    if ($r['json']['success'] ?? false) {
        return ['ok' => true, 'detail' => "$verb A $host → $ip"];
    }
    return ['ok' => false, 'detail' => cf_error($r)];
}

function cf_lookup(array $cfg, string $host): array
{
    $zone = cf_zone_id($cfg, $host);
    if (!$zone) {
        return ['ip' => null, 'detail' => 'zone not found', 'method' => 'api'];
    }
    $records = cf_records($cfg, $zone, $host);
    return ['ip' => $records[0]['content'] ?? null, 'detail' => $records ? 'A ' . implode(', ', array_column($records, 'content')) : 'no A record', 'method' => 'api'];
}

// ---------------------------------------------------------------------------
// PowerDNS Authoritative HTTP API
// ---------------------------------------------------------------------------

function pdns_base(array $cfg): string
{
    $u = rtrim((string)($cfg['api_url'] ?? ''), '/');
    if (!preg_match('#/api/v1$#', $u)) {
        $u .= '/api/v1';
    }
    return $u;
}

function pdns_headers(array $cfg): array
{
    return ['X-API-Key' => (string)($cfg['api_key'] ?? '')];
}

function pdns_error(array $r): string
{
    if ($r['error']) return 'PowerDNS unreachable: ' . $r['error'];
    $m = $r['json']['error'] ?? trim(substr($r['body'], 0, 160));
    return 'PowerDNS HTTP ' . $r['status'] . ($m !== '' ? ": $m" : '');
}

/** @return array{0: ?string, 1: string}  [zone id for URLs, detail] */
function pdns_zone(array $cfg, string $host): array
{
    $sid = rawurlencode($cfg['server_id'] ?: 'localhost');
    if (!empty($cfg['zone'])) {
        $z = rtrim(strtolower($cfg['zone']), '.') . '.';
        if (substr($host . '.', -strlen($z)) !== $z) {
            return [null, "$host is not inside configured zone $z"];
        }
        return [$z, ''];
    }
    $r = http_json('GET', pdns_base($cfg) . "/servers/$sid/zones", pdns_headers($cfg));
    if ($r['status'] !== 200 || !is_array($r['json'])) {
        return [null, pdns_error($r)];
    }
    $best = null;
    $bestLen = -1;
    foreach ($r['json'] as $zone) {
        $name = strtolower((string)($zone['name'] ?? ''));
        if ($name !== '' && substr($host . '.', -strlen($name)) === $name
            && (strlen($host . '.') === strlen($name) || substr($host . '.', -strlen($name) - 1, 1) === '.')
            && strlen($name) > $bestLen) {
            $best = (string)($zone['id'] ?? $name);
            $bestLen = strlen($name);
        }
    }
    return $best ? [$best, ''] : [null, "No PowerDNS zone contains $host"];
}

function pdns_push(array $cfg, string $host, string $ip, int $ttl): array
{
    [$zone, $why] = pdns_zone($cfg, $host);
    if (!$zone) {
        return ['ok' => false, 'detail' => $why];
    }
    $sid = rawurlencode($cfg['server_id'] ?: 'localhost');
    $url = pdns_base($cfg) . "/servers/$sid/zones/" . rawurlencode($zone);
    // REPLACE sets the whole A rrset to exactly this one address, so an old
    // address can't linger next to the new one.
    $body = ['rrsets' => [[
        'name' => $host . '.', 'type' => 'A', 'ttl' => max(30, $ttl), 'changetype' => 'REPLACE',
        'records' => [['content' => $ip, 'disabled' => false]],
    ]]];
    $r = http_json('PATCH', $url, pdns_headers($cfg), $body);
    if ($r['status'] !== 204 && $r['status'] !== 200) {
        return ['ok' => false, 'detail' => pdns_error($r)];
    }
    $detail = "Set A $host → $ip (zone $zone)";
    if (!empty($cfg['notify'])) {
        $n = http_json('PUT', "$url/notify", pdns_headers($cfg));
        $detail .= $n['status'] === 200 ? '; NOTIFY sent' : '; NOTIFY failed (' . pdns_error($n) . ')';
    }
    return ['ok' => true, 'detail' => $detail];
}

function pdns_lookup(array $cfg, string $host): array
{
    [$zone, $why] = pdns_zone($cfg, $host);
    if (!$zone) {
        return ['ip' => null, 'detail' => $why, 'method' => 'api'];
    }
    $sid = rawurlencode($cfg['server_id'] ?: 'localhost');
    // rrset_name/rrset_type filter on newer PowerDNS; older versions ignore
    // them and return the whole zone, so filter again here either way.
    $r = http_json('GET', pdns_base($cfg) . "/servers/$sid/zones/" . rawurlencode($zone)
        . '?rrset_name=' . rawurlencode($host . '.') . '&rrset_type=A', pdns_headers($cfg));
    if ($r['status'] !== 200) {
        return ['ip' => null, 'detail' => pdns_error($r), 'method' => 'api'];
    }
    foreach ($r['json']['rrsets'] ?? [] as $rr) {
        if (strtolower($rr['name'] ?? '') === $host . '.' && ($rr['type'] ?? '') === 'A') {
            $ips = array_column(array_filter($rr['records'] ?? [], fn($x) => empty($x['disabled'])), 'content');
            return ['ip' => $ips[0] ?? null, 'detail' => $ips ? 'A ' . implode(', ', $ips) : 'no enabled A record', 'method' => 'api'];
        }
    }
    return ['ip' => null, 'detail' => 'no A record', 'method' => 'api'];
}

// ---------------------------------------------------------------------------
// dyndns2 family, DuckDNS, FreeDNS
// ---------------------------------------------------------------------------

function dyndns2_push(array $cfg, string $host, string $ip): array
{
    $preset = dyndns2_presets()[$cfg['preset'] ?? ''] ?? null;
    $tpl = ($cfg['preset'] ?? '') === 'custom' ? ($cfg['update_url'] ?? '') : ($preset['url'] ?? '');
    if ($tpl === '') {
        return ['ok' => false, 'detail' => 'No update URL configured for this account'];
    }
    $url = str_replace(['{hostname}', '{ip}'], [rawurlencode($host), rawurlencode($ip)], $tpl);
    $headers = [
        // No-IP requires an identifying agent with a contact address.
        'User-Agent' => 'ipfailover-control/' . APP_VERSION . ' ' . (setting('smtp_from') ?: 'admin@localhost'),
    ];
    if (($cfg['username'] ?? '') !== '') {
        $headers['Authorization'] = 'Basic ' . base64_encode($cfg['username'] . ':' . ($cfg['password'] ?? ''));
    }
    $r = http_request('GET', $url, $headers);
    if ($r['error']) {
        return ['ok' => false, 'detail' => 'Provider unreachable: ' . $r['error']];
    }
    $body = trim($r['body']);
    if ($r['status'] >= 200 && $r['status'] < 300 && preg_match('/^(good|nochg)\b/i', $body)) {
        return ['ok' => true, 'detail' => "Provider answered: $body"];
    }
    $why = [
        'badauth' => 'bad username/password', 'nohost' => 'hostname does not exist in this account',
        'notfqdn' => 'hostname is not a valid FQDN', 'abuse' => 'provider blocked the host for abuse',
        '!donator' => 'feature needs a paid account', '911' => 'provider-side outage', 'badagent' => 'provider rejected the client',
        'dnserr' => 'provider DNS error', 'numhost' => 'too many hosts in one request',
    ];
    $code = strtolower(strtok($body, " \n") ?: '');
    return ['ok' => false, 'detail' => 'Provider refused: ' . ($why[$code] ?? ("HTTP {$r['status']} " . substr($body, 0, 120)))];
}

function duckdns_push(array $cfg, string $host, string $ip): array
{
    $sub = preg_replace('/\.duckdns\.org$/i', '', $host);
    $base = rtrim((string)(app_config('duckdns_api_base') ?: 'https://www.duckdns.org'), '/');
    $r = http_request('GET', "$base/update?domains=" . rawurlencode($sub) . '&token=' . rawurlencode($cfg['token'] ?? '') . '&ip=' . rawurlencode($ip));
    if ($r['error']) {
        return ['ok' => false, 'detail' => 'DuckDNS unreachable: ' . $r['error']];
    }
    return trim($r['body']) === 'OK'
        ? ['ok' => true, 'detail' => "DuckDNS $sub → $ip"]
        : ['ok' => false, 'detail' => 'DuckDNS refused (check token and that the subdomain exists in this account)'];
}

function freedns_push(array $tcfg, string $host, string $ip): array
{
    $tok = (string)($tcfg['host_token'] ?? '');
    if ($tok === '' || !preg_match('/^[A-Za-z0-9]+$/', $tok)) {
        return ['ok' => false, 'detail' => 'Host update token missing or malformed'];
    }
    $r = http_request('GET', 'https://sync.afraid.org/u/' . $tok . '/?ip=' . rawurlencode($ip));
    if ($r['error']) {
        return ['ok' => false, 'detail' => 'FreeDNS unreachable: ' . $r['error']];
    }
    $body = trim($r['body']);
    return preg_match('/^(Updated|No IP change detected)/i', $body)
        ? ['ok' => true, 'detail' => "FreeDNS: $body"]
        : ['ok' => false, 'detail' => 'FreeDNS refused: ' . substr($body, 0, 120)];
}

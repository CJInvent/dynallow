<?php
declare(strict_types=1);
require dirname(__DIR__) . '/src/bootstrap.php';
$me = require_admin();

$editing = isset($_GET['edit']) ? db_one('SELECT * FROM dns_accounts WHERE id = ?', [(int)$_GET['edit']]) : null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    $action = (string)($_POST['action'] ?? '');
    $acc = isset($_POST['id']) ? db_one('SELECT * FROM dns_accounts WHERE id = ?', [(int)$_POST['id']]) : null;

    if ($action === 'save') {
        $provider = $acc ? $acc['provider'] : (string)($_POST['provider'] ?? '');
        if (!isset(providers()[$provider])) {
            flash('error', 'Pick a provider.');
            redirect('accounts.php');
        }
        $name = trim((string)($_POST['name'] ?? ''));
        $existing = $acc ? decrypt_json($acc['config_enc']) : [];
        [$cfg, $errors] = provider_account_from_input($provider, (array)($_POST['p'][$provider] ?? []) + ['domain' => $_POST['domain'] ?? ''], $existing);
        if ($name === '') $errors[] = 'Name is required.';
        elseif (db_one('SELECT id FROM dns_accounts WHERE name = ? AND id <> ?', [$name, $acc['id'] ?? 0])) $errors[] = "An account called \"$name\" already exists.";
        if ($errors) {
            foreach ($errors as $e) flash('error', $e);
            redirect('accounts.php' . ($acc ? '?edit=' . $acc['id'] : ''));
        }
        if ($acc) {
            db_update('dns_accounts', (int)$acc['id'], ['name' => $name, 'config_enc' => encrypt_json($cfg), 'updated_at' => time()]);
            // Credentials may now work: let failed targets on this account retry right away.
            db_exec("UPDATE dns_targets SET fail_count = 0 WHERE account_id = ? AND state = 'fault'", [$acc['id']]);
            log_event("DNS account \"$name\" updated", 'info');
        } else {
            db_exec('INSERT INTO dns_accounts(name, provider, config_enc, created_at, updated_at) VALUES(?,?,?,?,?)',
                [$name, $provider, encrypt_json($cfg), time(), time()]);
            log_event("DNS account \"$name\" ($provider) added", 'info');
        }
        flash('ok', 'Saved.');
        redirect('accounts.php');
    }
    if ($action === 'test' && $acc) {
        $r = provider_test($acc['provider'], decrypt_json($acc['config_enc']));
        flash($r['ok'] ? 'ok' : 'error', "{$acc['name']}: {$r['detail']}");
        redirect('accounts.php');
    }
    if ($action === 'delete' && $acc) {
        $n = (int)db_val('SELECT COUNT(*) FROM dns_targets WHERE account_id = ?', [$acc['id']]);
        if ($n > 0) {
            flash('error', "{$acc['name']} is used by $n DNS name(s). Move or remove those first.");
        } else {
            db_exec('DELETE FROM dns_accounts WHERE id = ?', [$acc['id']]);
            log_event("DNS account \"{$acc['name']}\" deleted", 'warn');
            flash('ok', 'Deleted.');
        }
        redirect('accounts.php');
    }
}

page_header('DNS accounts', 'accounts');
echo '<h1>DNS accounts</h1><p class="dim">Each account is one provider login, set up once here. Technicians just pick it from a list in the survey. '
    . 'Credentials are encrypted on this server, never shown again after saving, and never sent to agents.</p>';

$rows = db_all('SELECT a.*, (SELECT COUNT(*) FROM dns_targets t WHERE t.account_id = a.id) AS n FROM dns_accounts a ORDER BY a.name');
if ($rows) {
    echo '<div class="card tablewrap"><table><thead><tr><th>Name</th><th>Provider</th><th>Random names under</th><th>Names</th><th></th></tr></thead><tbody>';
    foreach ($rows as $r) {
        $meta = providers()[$r['provider']];
        $domain = dns_account_domain($r);
        echo '<tr><td><b>' . h($r['name']) . '</b></td><td>' . h($meta['label']) . '</td><td class="mono">'
            . ($meta['creates'] ? h($domain ?: '— (set a domain to enable)') : '<span class="dim">not supported</span>') . '</td><td>' . (int)$r['n'] . '</td><td class="nowrap">'
            . '<a class="btn small" href="?edit=' . (int)$r['id'] . '">Edit</a> '
            . action_button('test', 'Test', ['id' => $r['id']], 'small') . ' '
            . ((int)$r['n'] === 0 ? action_button('delete', 'Delete', ['id' => $r['id']], 'small danger', "Delete {$r['name']}?") : '')
            . '</td></tr>';
    }
    echo '</tbody></table></div>';
}

$cur = $editing ? decrypt_json($editing['config_enc']) : [];
echo '<div class="card"><h2>' . ($editing ? 'Edit ' . h($editing['name']) : 'Add an account') . '</h2><form method="post" autocomplete="off">' . csrf_field()
    . '<input type="hidden" name="action" value="save">' . ($editing ? '<input type="hidden" name="id" value="' . (int)$editing['id'] . '">' : '');
$opts = '';
foreach (providers() as $k => $p) {
    $sel = $editing ? $editing['provider'] === $k : $k === 'cloudflare';
    $opts .= '<option value="' . h($k) . '" data-creates="' . ($p['creates'] ? '1' : '0') . '"' . ($sel ? ' selected' : '') . '>' . h($p['label']) . '</option>';
}
echo '<div class="cols2">' . field('Provider', '<select name="provider" data-provider-select' . ($editing ? ' disabled' : '') . '>' . $opts . '</select>',
        $editing ? 'The provider of an existing account can\'t change; add a new account instead.' : '')
    . field('Name', input('name', $editing['name'] ?? '', 'text', ['required' => true, 'placeholder' => 'e.g. DP Solutions Cloudflare'])) . '</div>';
if ($editing) {
    // The disabled select above isn't submitted; keep the field groups keyed to the real provider.
    echo '<input type="hidden" name="provider" value="' . h($editing['provider']) . '">';
}
foreach (providers() as $k => $p) {
    echo '<div data-provider="' . h($k) . '">';
    foreach ($p['fields'] as $f) {
        $nameAttr = "p[$k][{$f['key']}]";
        $val = ($editing && $editing['provider'] === $k) ? ($cur[$f['key']] ?? '') : ($f['default'] ?? '');
        switch ($f['type']) {
            case 'secret':
                $isSet = $editing && $editing['provider'] === $k && ($cur[$f['key']] ?? '') !== '';
                $in = input($nameAttr, '', 'password', ['autocomplete' => 'new-password', 'placeholder' => $isSet ? '•••••••• (saved — leave blank to keep)' : '']);
                break;
            case 'bool':
                echo '<div class="field">' . checkbox($nameAttr, (bool)$val, $f['label']) . '</div>';
                continue 2;
            case 'select':
                $in = select($nameAttr, $f['options'], $val);
                break;
            default:
                $in = input($nameAttr, $val);
        }
        echo field($f['label'], $in, h($f['help'] ?? ''));
    }
    if (!$p['fields']) {
        echo '<p class="small dim">Nothing to configure here' . ($p['target_fields'] ? ' — each name\'s own update token is entered when the name is added.' : '.') . '</p>';
    }
    echo '</div>';
}
echo '<div data-creates-only>' . field('Domain for random names', input('domain', $cur['domain'] ?? '', 'text', ['placeholder' => 'dyn.example.com']),
    'Random site names are created under this domain (e.g. <code>k7m2qx9ad4pn.dyn.example.com</code>). Leave blank to always type names.') . '</div>';
echo '<button class="primary">Save</button>' . ($editing ? ' <a href="accounts.php">Cancel</a>' : '') . '</form></div>';

echo '<div class="card"><h2>Which provider?</h2><ul class="small">'
    . '<li><b>Cloudflare</b> and <b>PowerDNS</b> — one credential covers every name in the zone, can create new names, and can be read back to detect tampering. Best choice.</li>'
    . '<li><b>DynDNS-compatible</b> (No-IP, Dynu, Dyn, ChangeIP, OVH, custom) — one login, but each hostname must already exist at the provider.</li>'
    . '<li><b>DuckDNS</b> — one token; create the subdomain on duckdns.org first.</li>'
    . '<li><b>FreeDNS</b> — afraid.org gives each name its own update token, entered per name.</li>'
    . '<li><b>None</b> — no DNS; the site\'s IP is still tracked, alerted on, and published in allowlist feeds.</li></ul>'
    . '<p class="small">Cloudflare token: My Profile → API Tokens → Create Token → "Edit zone DNS", limited to the zone(s) you use. '
    . 'PowerDNS: enable <code>api=yes</code>, <code>api-key=…</code>, <code>webserver=yes</code> and allow this server in <code>webserver-allow-from</code>.</p></div>';
page_footer();

<?php
declare(strict_types=1);

/**
 * New-site survey for technicians. Six short steps; the last one creates the
 * site and lands on its page with the provisioning download. Works without
 * JavaScript too (all steps on one page).
 */
require dirname(__DIR__) . '/src/bootstrap.php';
$me = require_login();
$accounts = dns_accounts_all();

$v = [
    'customer' => '', 'name' => '', 'site_address' => '', 'site_contact' => '', 'platform' => 'windows', 'purpose' => [],
    'notes' => '', 'isp' => 'starlink', 'cgnat' => 'unknown', 'multiwan' => 'no', 'interval_sec' => setting('default_interval_sec'),
    'missed_threshold' => setting('default_missed'), 'alert_emails' => $me['email'], 'tags' => '', 'trust_mode' => 'agree',
    'targets' => $accounts ? [['account_id' => $accounts[0]['id'], 'name_mode' => 'random', 'ttl' => '120']] : [],
];
$errors = [];
$startStep = 0;

$isps = ['starlink' => 'Starlink', 'cable' => 'Cable', 'fiber' => 'Fiber', 'dsl' => 'DSL', 'wireless' => 'Fixed wireless', 'cellular' => 'Cellular / LTE / 5G', 'other' => 'Other'];
$purposes = ['pbx' => 'Phone system (PBX firewall allowlist)', 'vpn' => 'VPN / remote access', 'nvr' => 'Cameras / NVR', 'rdp' => 'Remote desktop allowlist', 'other' => 'Something else'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    foreach ($v as $k => $_) {
        if (isset($_POST[$k])) $v[$k] = is_array($_POST[$k]) ? $_POST[$k] : trim((string)$_POST[$k]);
    }
    $v['targets'] = array_values((array)($_POST['targets'] ?? []));
    $v['purpose'] = array_values(array_intersect((array)($_POST['purpose'] ?? []), array_keys($purposes)));

    $err = function (int $step, string $msg) use (&$errors, &$startStep) {
        if (!$errors) $startStep = $step;
        $errors[] = $msg;
    };
    if ($v['customer'] === '') $err(0, 'Customer is required.');
    if ($v['name'] === '' || strlen($v['name']) > 80) $err(0, 'Site name is required (80 characters max).');
    elseif (db_one('SELECT id FROM agents WHERE name = ?', [$v['name']])) $err(0, "A site called \"{$v['name']}\" already exists.");
    if (!in_array($v['platform'], ['windows', 'docker'], true)) $err(1, 'Pick where the agent will run.');
    if (!isset($isps[$v['isp']])) $err(2, 'Pick the internet type.');
    if (!isset(trust_modes()[$v['trust_mode']])) $err(4, 'Unknown trust mode.');
    $bad = array_diff(preg_split('/[\s,;]+/', (string)$v['alert_emails'], -1, PREG_SPLIT_NO_EMPTY), parse_emails((string)$v['alert_emails']));
    if ($bad) $err(4, 'Not a valid email: ' . implode(', ', $bad));

    $readyTargets = [];
    $seenHosts = [];
    foreach ($v['targets'] as $row) {
        [$f, $terr] = target_from_input((array)$row);
        foreach ($terr as $e) $err(3, $e);
        if ($f) {
            if (isset($seenHosts[$f['hostname']])) { $err(3, "{$f['hostname']} is listed twice."); continue; }
            $seenHosts[$f['hostname']] = true;
            $readyTargets[] = $f;
        }
    }

    if (!$errors) {
        db()->beginTransaction();
        try {
            db_exec('INSERT INTO agents(uid, name, customer, site_address, site_contact, tags, platform, purpose, isp, cgnat, notes,
                     interval_sec, missed_threshold, alert_emails, trust_mode, created_at, created_by)
                     VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)', [
                new_agent_uid(), $v['name'], $v['customer'], $v['site_address'], $v['site_contact'], implode(', ', parse_tags((string)$v['tags'])),
                $v['platform'], implode(', ', $v['purpose']), $isps[$v['isp']], $v['cgnat'], $v['notes'],
                max(60, (int)$v['interval_sec']), max(1, min(20, (int)$v['missed_threshold'])),
                implode(', ', parse_emails((string)$v['alert_emails'])), $v['trust_mode'], time(), $me['username'],
            ]);
            $agent = agent_get((int)db()->lastInsertId());
            log_event("Site created from the survey by {$me['username']} ({$isps[$v['isp']]}, CGNAT: {$v['cgnat']}, " . ($v['multiwan'] === 'yes' ? 'multi-WAN' : 'single WAN') . ')', 'info', $agent);
            foreach ($readyTargets as $f) {
                target_insert($agent, $f);
            }
            db()->commit();
        } catch (Throwable $e) {
            db()->rollBack();
            throw $e;
        }
        flash('ok', 'Site created. Download the provisioning profile or Docker installer below.');
        redirect('agent.php?id=' . (int)$agent['id'] . '&new=1');
    }
}

page_header('New site', 'survey');
echo '<h1>New site</h1>';
foreach ($errors as $e) echo '<div class="flash error">' . h($e) . '</div>';

$steps = ['Site', 'Machine', 'Internet', 'DNS name', 'Alerts', 'Review'];
echo '<div class="steps">';
foreach ($steps as $i => $s) echo '<span>' . ($i + 1) . '. ' . h($s) . '</span>';
echo '</div>';

echo '<form method="post" class="card" data-survey data-start="' . $startStep . '">' . csrf_field();

// 1. Site
echo '<section class="step"><h2>1. Which site is this?</h2>';
echo field('Customer', input('customer', $v['customer'], 'text', ['required' => true, 'autofocus' => true]), 'The business name, e.g. Smith Dental.');
echo field('Site name', input('name', $v['name'], 'text', ['required' => true, 'maxlength' => '80']), 'Short and unique, e.g. <code>SmithDental-Lufkin-PBX</code>. This is what alerts will say.');
echo '<div class="cols2">' . field('Site address (optional)', input('site_address', $v['site_address'])) . field('On-site contact (optional)', input('site_contact', $v['site_contact'], 'text', ['placeholder' => 'Name and phone'])) . '</div>';
echo '<div class="stepnav"><span></span><button class="primary" data-next>Next</button></div></section>';

// 2. Machine
echo '<section class="step"><h2>2. Where will the agent run?</h2><div class="choice">';
echo '<label><input type="radio" name="platform" value="windows"' . ($v['platform'] === 'windows' ? ' checked' : '') . '> <b>A Windows PC</b><span class="small dim">Any always-on PC at the site. Nothing to install first.</span></label>';
echo '<label><input type="radio" name="platform" value="docker"' . ($v['platform'] === 'docker' ? ' checked' : '') . '> <b>Docker (Linux / Proxmox LXC)</b><span class="small dim">A small container on the customer\'s server.</span></label>';
echo '</div><h3>What is it for?</h3>';
foreach ($purposes as $k => $label) {
    echo '<label class="check"><input type="checkbox" name="purpose[]" value="' . h($k) . '"' . (in_array($k, (array)$v['purpose'], true) ? ' checked' : '') . '> ' . h($label) . '</label>';
}
echo field('Notes (optional)', '<textarea name="notes">' . h($v['notes']) . '</textarea>');
echo '<div class="stepnav"><button data-back>Back</button><button class="primary" data-next>Next</button></div></section>';

// 3. Internet
echo '<section class="step"><h2>3. How is the site connected?</h2>';
echo field('Internet type', select('isp', $isps, $v['isp']));
echo field('Is it behind CGNAT?', select('cgnat', ['unknown' => 'Not sure', 'yes' => 'Yes', 'no' => 'No'], $v['cgnat']), 'Starlink residential and most cellular plans are. If unsure, leave "Not sure".');
echo '<div class="callout">With CGNAT, the site\'s public IPv4 is <b>shared with other customers</b> of that ISP. Allowlisting it also trusts everyone else behind it. '
    . 'Keep passwords/keys on the service even when an IP is allowlisted.</div>';
echo field('Does the site have more than one internet connection (failover or load balancing)?', select('multiwan', ['no' => 'No, just one', 'yes' => 'Yes, two or more'], $v['multiwan']),
    'If yes, the agent may see one address while the server sees the other. Choosing "Yes" sets the trust mode to Server-seen on the Alerts step.');
echo '<div class="stepnav"><button data-back>Back</button><button class="primary" data-next>Next</button></div></section>';

// 4. DNS
echo '<section class="step"><h2>4. Which DNS name should follow this site?</h2>';
if (!$accounts) {
    echo '<div class="callout info">No DNS accounts are set up yet' . ($me['role'] === 'admin' ? ' (<a href="accounts.php">add one</a>)' : ' — ask an admin to add one')
        . '. You can still continue: the site\'s IP will be tracked for alerts and allowlist feeds, and a name can be added later.</div>';
} else {
    echo '<p class="dim">The control server updates these records itself — the site never holds DNS passwords. Most sites need one name. Leave it empty to only track the IP.</p>';
    echo '<div data-targets>';
    foreach ($v['targets'] as $i => $row) echo target_row_html($accounts, "targets[$i]", (array)$row);
    echo '</div><template id="tpl-target">' . target_row_html($accounts, 'targets[0]') . '</template>';
    echo '<button type="button" data-add-target="tpl-target">+ Add another name</button>';
}
echo '<div class="stepnav"><button data-back>Back</button><button class="primary" data-next>Next</button></div></section>';

// 5. Alerts
$trust = $v['multiwan'] === 'yes' && $v['trust_mode'] === 'agree' ? 'server' : $v['trust_mode'];
echo '<section class="step"><h2>5. Alerts</h2>';
echo '<div class="cols2">' . field('Check in', select('interval_sec', interval_options(), $v['interval_sec']))
    . field('Email after this many missed check-ins', input('missed_threshold', $v['missed_threshold'], 'number', ['min' => '1', 'max' => '20'])) . '</div>';
echo field('Who else should get this site\'s alerts?', input('alert_emails', $v['alert_emails']), 'Comma-separated. The global alert list always gets them too.');
echo field('Tags (optional)', input('tags', $v['tags'], 'text', ['placeholder' => 'pbx, starlink']), 'Used to filter the dashboard and allowlist feeds.');
echo field('Trust mode', select('trust_mode', trust_modes(), $trust), 'Leave on Agree unless the site has two internet connections. Use Manual for sites whose IP opens something sensitive.');
echo '<div class="stepnav"><button data-back>Back</button><button class="primary" data-next>Review</button></div></section>';

// 6. Review
echo '<section class="step"><h2>6. Check and create</h2><table class="kv"><tbody data-review></tbody></table>';
echo '<p class="dim">After you create the site, download a Windows profile for the signed agent EXE, or a Docker installer. The enrollment credential works once and expires in ' . (int)setting('enroll_valid_days') . ' days.</p>';
echo '<div class="stepnav"><button data-back>Back</button><button class="primary">Create site</button></div></section>';
echo '</form>';
page_footer();

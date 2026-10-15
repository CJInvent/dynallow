<?php
declare(strict_types=1);

/**
 * Built-in SMTP client (STARTTLS / implicit TLS / plain, AUTH LOGIN) so alert
 * email works against Office 365, Gmail, SMTP2GO, your own relay, etc. with
 * no local MTA and no PHPMailer. Falls back to PHP mail() only when no SMTP
 * host is configured.
 */

/** @return array{ok: bool, error: ?string} */
function send_mail(array $to, string $subject, string $body): array
{
    $to = array_values(array_unique(array_filter($to, fn($e) => is_string($e) && filter_var($e, FILTER_VALIDATE_EMAIL))));
    if (!$to) {
        return ['ok' => false, 'error' => 'no recipients'];
    }
    $from = setting('smtp_from');
    $fromName = setting('smtp_from_name') ?: 'IP Failover';
    $host = setting('smtp_host');
    if ($from !== '' && !filter_var($from, FILTER_VALIDATE_EMAIL)) return ['ok' => false, 'error' => 'Invalid SMTP from address'];

    if ($host === '') {
        if ($from === '') {
            return ['ok' => false, 'error' => 'email not configured (Settings → Email)'];
        }
        $hdrs = 'From: ' . mail_encode_header($fromName) . " <$from>\r\nContent-Type: text/plain; charset=UTF-8";
        $ok = @mail(implode(', ', $to), mail_encode_header($subject), $body, $hdrs);
        return ['ok' => $ok, 'error' => $ok ? null : 'PHP mail() failed (no local MTA?)'];
    }
    if ($from === '') {
        return ['ok' => false, 'error' => 'Settings → Email: "From address" is empty'];
    }

    try {
        smtp_send($host, (int)setting('smtp_port'), setting('smtp_security'), setting('smtp_user'),
            setting('smtp_pass_enc') !== '' ? decrypt_str(setting('smtp_pass_enc')) : '',
            $from, $fromName, $to, $subject, $body);
        return ['ok' => true, 'error' => null];
    } catch (Throwable $e) {
        return ['ok' => false, 'error' => $e->getMessage()];
    }
}

function mail_encode_header(string $s): string
{
    return preg_match('/[^\x20-\x7e]/', $s) ? '=?UTF-8?B?' . base64_encode($s) . '?=' : $s;
}

function smtp_send(string $host, int $port, string $security, string $user, string $pass,
                   string $from, string $fromName, array $to, string $subject, string $body): void
{
    if (!filter_var($from, FILTER_VALIDATE_EMAIL)) throw new RuntimeException('Invalid SMTP from address');
    foreach ($to as $address) if (!filter_var($address, FILTER_VALIDATE_EMAIL)) throw new RuntimeException('Invalid SMTP recipient');
    $ctx = stream_context_create(['ssl' => ['verify_peer' => true, 'verify_peer_name' => true, 'peer_name' => $host]]);
    $remote = ($security === 'ssl' ? 'ssl://' : 'tcp://') . $host . ':' . $port;
    $fp = @stream_socket_client($remote, $errno, $errstr, 15, STREAM_CLIENT_CONNECT, $ctx);
    if (!$fp) {
        throw new RuntimeException("SMTP connect to $host:$port failed: $errstr");
    }
    stream_set_timeout($fp, 20);

    $read = function () use ($fp): array {
        $lines = '';
        while (($line = fgets($fp, 1024)) !== false) {
            $lines .= $line;
            if (strlen($line) < 4 || $line[3] === ' ') {
                break;
            }
        }
        if ($lines === '') {
            throw new RuntimeException('SMTP server closed the connection');
        }
        return [(int)substr($lines, 0, 3), trim($lines)];
    };
    $cmd = function (string $line, array $expect, bool $secret = false) use ($fp, $read): string {
        fwrite($fp, $line . "\r\n");
        [$code, $text] = $read();
        if (!in_array($code, $expect, true)) {
            $shown = $secret ? '[credentials]' : strtok($line, "\r\n");
            throw new RuntimeException("SMTP: '$shown' got $text");
        }
        return $text;
    };

    try {
        [$code, $text] = $read();
        if ($code !== 220) {
            throw new RuntimeException("SMTP greeting: $text");
        }
        $ehloName = gethostname() ?: 'localhost';
        $ehlo = $cmd("EHLO $ehloName", [250]);

        if ($security === 'starttls') {
            $cmd('STARTTLS', [220]);
            $methods = STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT | (defined('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT') ? STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT : 0);
            if (!stream_socket_enable_crypto($fp, true, $methods)) {
                throw new RuntimeException('SMTP STARTTLS negotiation failed');
            }
            $ehlo = $cmd("EHLO $ehloName", [250]);
        }

        if ($user !== '') {
            if ($security === 'none' && !(strtolower($host) === 'localhost' || $host === '::1' || (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) && ip_in_cidr($host, '127.0.0.0/8')))) {
                throw new RuntimeException('Refusing to send SMTP password over an unencrypted connection; use STARTTLS or SSL');
            }
            $cmd('AUTH LOGIN', [334]);
            $cmd(base64_encode($user), [334], true);
            $cmd(base64_encode($pass), [235], true);
        }

        $cmd('MAIL FROM:<' . $from . '>', [250]);
        foreach ($to as $rcpt) {
            $cmd('RCPT TO:<' . $rcpt . '>', [250, 251]);
        }
        $cmd('DATA', [354]);

        $msgId = '<' . random_token(12) . '@' . (substr(strrchr($from, '@'), 1) ?: 'localhost') . '>';
        $headers = [
            'Date: ' . date(DATE_RFC2822),
            'From: ' . mail_encode_header($fromName) . " <$from>",
            'To: ' . implode(', ', $to),
            'Subject: ' . mail_encode_header($subject),
            'Message-ID: ' . $msgId,
            'MIME-Version: 1.0',
            'Content-Type: text/plain; charset=UTF-8',
            'Content-Transfer-Encoding: 8bit',
            'Auto-Submitted: auto-generated',
        ];
        $norm = preg_replace("/\r\n|\r|\n/", "\r\n", $body);
        $norm = preg_replace('/^\./m', '..', $norm); // dot-stuffing
        $cmd(implode("\r\n", $headers) . "\r\n\r\n" . $norm . "\r\n.", [250], true);
        @fwrite($fp, "QUIT\r\n");
    } finally {
        fclose($fp);
    }
}

/** Everyone who should hear about a given agent: global list + the agent's own list. */
function alert_recipients(?array $agent = null): array
{
    $list = parse_emails(setting('alert_emails'));
    if ($agent) {
        $list = array_merge($list, parse_emails((string)$agent['alert_emails']));
    }
    return array_values(array_unique(array_map('strtolower', $list)));
}

function notify(string $subject, string $body, ?array $agent = null): void
{
    notify_webhook($subject, $body, $agent);
    $to = alert_recipients($agent);
    if (!$to) {
        log_event("Alert not emailed (no recipients configured): $subject", 'warn', $agent, 'system');
        return;
    }
    $url = rtrim(setting('public_url'), '/');
    if ($agent && $url !== '') {
        $body .= "\n\nAgent page: $url/agent.php?id=" . $agent['id'];
    }
    $body .= "\n\n-- \nIP Failover control server";
    $r = send_mail($to, '[IP Failover] ' . $subject, $body);
    if (!$r['ok']) {
        log_event("Alert email FAILED ($subject): " . $r['error'], 'error', $agent, 'system');
    }
}

/**
 * Optional generic webhook (Settings → Alerts). "text" makes it work as-is
 * with Slack, Teams workflows, Mattermost, Rocket.Chat, Discord (/slack) and
 * ntfy; the structured fields are there for n8n / custom receivers.
 */
function notify_webhook(string $subject, string $body, ?array $agent): void
{
    $url = setting('webhook_url');
    if ($url === '' || !preg_match('#^https?://#i', $url)) {
        return;
    }
    $payload = [
        'text'    => "[IP Failover] $subject\n\n$body",
        'subject' => $subject,
        'body'    => $body,
        'agent'   => $agent ? ['uid' => $agent['uid'], 'name' => $agent['name'], 'customer' => $agent['customer'],
                               'ipv4' => $agent['current_ipv4']] : null,
        'at'      => gmdate('c'),
    ];
    $r = http_json('POST', $url, [], $payload, 8);
    if ($r['error'] || $r['status'] >= 300) {
        log_event("Webhook delivery failed for '$subject': " . ($r['error'] ?: 'HTTP ' . $r['status']), 'error', $agent, 'system');
    }
}

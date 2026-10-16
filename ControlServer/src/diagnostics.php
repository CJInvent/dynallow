<?php
declare(strict_types=1);

/** Diagnostic text is untrusted; never accept raw request bodies or credentials here. */
function diagnostic_redact(string $s): string
{
    $s = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', $s);
    $s = preg_replace('~https?://[^\s<>"\']+~i', '[URL]', $s); // query/path credentials, including webhooks
    $s = preg_replace('/-----BEGIN .*PRIVATE KEY-----.*?-----END .*PRIVATE KEY-----/s', '[PRIVATE KEY REDACTED]', $s);
    $s = preg_replace('/\b(password|token|secret|authorization|enroll_token|private_pem)\s*[:=]\s*\S+/i', '$1=[REDACTED]', $s);
    return mb_substr_safe($s, 2000);
}

function server_diagnostic(string $level, string $message): void
{
    static $busy = false;
    if ($busy) return;
    $busy = true;
    $message = diagnostic_redact($message);
    error_log('[dynallow] ' . $level . ': ' . $message);
    try {
        // Coalesce repeats for a minute, while keeping the original visible warning.
        if (!db_val('SELECT id FROM diagnostics WHERE source = ? AND message = ? AND at > ? LIMIT 1', ['server', $message, time() - 60])) {
            db_exec('INSERT INTO diagnostics(source, entry_id, at, level, message) VALUES(?,?,?,?,?)',
                ['server', bin2hex(random_bytes(16)), time(), $level, $message]);
        }
    } catch (Throwable $e) {
        // Database failure must remain visible to the host's error-log collector.
        error_log('[dynallow] diagnostic database write failed; preceding message is not in web UI');
    } finally { $busy = false; }
}

function install_diagnostic_handlers(): void
{
    ini_set('display_errors', '0');
    set_error_handler(function (int $no, string $message, string $file, int $line): bool {
        if (!(error_reporting() & $no)) return false;
        server_diagnostic('warn', basename($file) . ':' . $line . ': ' . $message);
        return false;
    });
    set_exception_handler(function (Throwable $e): void {
        try { if (db()->inTransaction()) db()->rollBack(); } catch (Throwable) { /* Original failure still goes to the host log. */ }
        server_diagnostic('error', get_class($e) . ' at ' . basename($e->getFile()) . ':' . $e->getLine() . ': ' . $e->getMessage());
        if (PHP_SAPI !== 'cli') { http_response_code(500); header('Content-Type: text/plain'); }
        echo "Internal error. Check Logs in the control server and the host PHP error log.\n";
        exit(1);
    });
    register_shutdown_function(function (): void {
        $e = error_get_last();
        if ($e && in_array($e['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR], true)) {
            server_diagnostic('error', 'Fatal error at ' . basename($e['file']) . ':' . $e['line'] . ': ' . $e['message']);
        }
    });
}

/** Called only after identity signature + freshness checks. Bounded, deduplicated, acknowledged. */
function ingest_agent_logs(array $agent, $entries): array
{
    if (!is_array($entries) || count($entries) > 20) throw new WireError('bad_logs', 'at most 20 log entries per request');
    $ack = [];
    foreach ($entries as $e) {
        if (!is_array($e) || !preg_match('/^[a-f0-9]{32}$/D', (string)($e['id'] ?? ''))
            || !in_array($e['level'] ?? '', ['info', 'warn', 'error'], true)
            || !is_string($e['message'] ?? null) || strlen($e['message']) > 1600) {
            throw new WireError('bad_logs', 'invalid diagnostic entry');
        }
        // An authenticated compromised endpoint cannot grow the table without bound.
        if (!db_val('SELECT id FROM diagnostics WHERE source = ? AND agent_id = ? AND entry_id = ?', ['agent', $agent['id'], $e['id']])
            && (int)db_val('SELECT COUNT(*) FROM diagnostics WHERE source = ? AND agent_id = ? AND at > ?', ['agent', $agent['id'], time() - 3600]) >= 240) {
            break; // no ACK: retain on endpoint and retry later
        }
        db_exec('INSERT OR IGNORE INTO diagnostics(source, agent_id, agent_name, entry_id, at, client_at, level, message) VALUES(?,?,?,?,?,?,?,?)',
            ['agent', $agent['id'], $agent['name'], $e['id'], time(), max(0, (int)($e['at'] ?? 0)), $e['level'], diagnostic_redact($e['message'])]);
        $ack[] = $e['id'];
    }
    return $ack;
}

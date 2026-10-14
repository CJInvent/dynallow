<?php
declare(strict_types=1);

/**
 * Minimal outbound HTTP client on PHP streams — no curl extension needed.
 * Returns ['status' => int, 'body' => string, 'error' => ?string].
 */
function http_request(string $method, string $url, array $headers = [], ?string $body = null, int $timeout = 12): array
{
    $hdr = [];
    $hasUa = false;
    foreach ($headers as $k => $v) {
        $hdr[] = "$k: $v";
        if (strcasecmp((string)$k, 'User-Agent') === 0) {
            $hasUa = true;
        }
    }
    if (!$hasUa) {
        $hdr[] = 'User-Agent: ipfailover-control/' . APP_VERSION;
    }
    $opts = [
        'http' => [
            'method'          => $method,
            'header'          => implode("\r\n", $hdr),
            'timeout'         => $timeout,
            'ignore_errors'   => true,   // still return the body on 4xx/5xx
            'follow_location' => 0,
            'protocol_version' => 1.1,
        ],
        'ssl' => [
            'verify_peer'      => true,
            'verify_peer_name' => true,
        ],
    ];
    if ($body !== null) {
        $opts['http']['content'] = $body;
    }
    // Connection: close keeps HTTP/1.1 from waiting on keep-alive.
    $opts['http']['header'] .= "\r\nConnection: close";

    $errMsg = null;
    set_error_handler(function ($no, $str) use (&$errMsg) {
        $errMsg = preg_replace('/^file_get_contents\([^)]*\): /', '', $str);
        return true;
    });
    try {
        $resp = file_get_contents($url, false, stream_context_create($opts));
    } finally {
        restore_error_handler();
    }

    $status = 0;
    // $http_response_header is populated by the stream wrapper in this scope.
    $respHeaders = $http_response_header ?? [];
    foreach ($respHeaders as $line) {
        if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m)) {
            $status = (int)$m[1]; // last one wins (after any 1xx)
        }
    }
    if ($resp === false) {
        return ['status' => $status, 'body' => '', 'error' => $errMsg ?: 'request failed'];
    }
    return ['status' => $status, 'body' => (string)$resp, 'error' => null];
}

function http_json(string $method, string $url, array $headers = [], $payload = null, int $timeout = 12): array
{
    $headers['Accept'] = 'application/json';
    $body = null;
    if ($payload !== null) {
        $headers['Content-Type'] = 'application/json';
        $body = json_encode($payload, JSON_UNESCAPED_SLASHES);
    }
    $r = http_request($method, $url, $headers, $body, $timeout);
    $r['json'] = $r['body'] !== '' ? json_decode($r['body'], true) : null;
    return $r;
}

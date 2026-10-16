<?php
declare(strict_types=1);

/**
 * The single agent endpoint. Everything an agent says arrives inside an IPF1
 * envelope (see src/wire.php) and everything we say back leaves inside one.
 *
 * Note what is NOT here: no Authorization header. Identity is the agent's
 * signature inside the envelope, independent of Authorization header forwarding.
 */

require dirname(__DIR__, 2) . '/src/bootstrap.php';

header('Content-Type: application/json');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'method_not_allowed']);
    exit;
}

$body = (string)file_get_contents('php://input', false, null, 0, WIRE_MAX_BODY + 1);

try {
    [$plain, $ctx] = wire_open_request($body);
} catch (WireError $e) {
    // We could not even derive the response key, so this answer is
    // unauthenticated. Agents treat it as a transport failure, never as an
    // instruction.
    http_response_code(400);
    echo json_encode(['error' => $e->codeStr, 'message' => $e->getMessage()]);
    exit;
} catch (Throwable $e) {
    server_diagnostic('error', 'Envelope failure: ' . get_class($e) . ': ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'server_error']);
    exit;
}

try {
    $resp = api_dispatch($plain, $ctx);
} catch (WireError $e) {
    $resp = ['ok' => false, 'error' => $e->codeStr, 'message' => $e->getMessage()];
} catch (Throwable $e) {
    if (db()->inTransaction()) db()->rollBack();
    server_diagnostic('error', 'API failure: ' . get_class($e) . ': ' . $e->getMessage() . ' @ ' . basename($e->getFile()) . ':' . $e->getLine());
    $resp = ['ok' => false, 'error' => 'server_error', 'message' => 'internal server error (see server log)'];
}
echo wire_seal_response($ctx, $resp);

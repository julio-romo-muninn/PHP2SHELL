<?php
/**
 * LAB ONLY — LFI sink used by the Chain A demo
 * (session file injection via session.upload_progress -> RCE).
 *
 * This file does not exist in any real environment. The include is restricted
 * to the container's session directory so that this endpoint cannot be used to
 * include arbitrary files.
 *
 * Technical context: ext/session/session.c stores the uploaded file name
 * verbatim (unsanitised) in the session file
 * (add_assoc_string_ex(&progress->current_file, "name", ..., *data->filename)).
 * With an include() sink in the application, those bytes are executed.
 */

header('Content-Type: text/plain; charset=utf-8');

$f = (string)($_GET['f'] ?? '');
if ($f === '') {
    echo "usage: ?f=/tmp/sessions/sess_<sid>\n";
    exit;
}

if (!preg_match('#^/tmp/sessions/sess_[A-Za-z0-9,-]+$#', $f)) {
    http_response_code(400);
    echo "only files from the lab session directory are allowed\n";
    exit;
}

include($f);

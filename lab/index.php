<?php
/**
 * Minimal victim endpoint of the lab.
 * Opens the session (needed to seed the session file that the in-flight upload
 * re-reads via php_session_initialize on every progress update).
 */
session_start();

if (!isset($_SESSION['seed'])) {
    $_SESSION['seed'] = bin2hex(random_bytes(8));
}

header('Content-Type: text/plain; charset=utf-8');
echo "ok sid=" . session_id() . " seed=" . $_SESSION['seed'] . "\n";

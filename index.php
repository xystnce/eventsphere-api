<?php
// index.php — entry point
// CORS headers are handled entirely by api/api.php — do NOT add them here.

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

require_once __DIR__ . '/api/api.php';

<?php
// index.php — entry point
// CORS headers MUST be set here, before the OPTIONS early-exit.
// If they were only in api/api.php, preflight OPTIONS requests would exit
// before api.php is ever included, returning a 200 with no CORS headers → blocked.
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
 
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}
 
require_once __DIR__ . '/api/api.php';

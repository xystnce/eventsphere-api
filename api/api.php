<?php
// ══════════════════════════════════════
//  EventSphere — API
//  Save to: C:/xampp/htdocs/api/api.php
// ══════════════════════════════════════
 
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, Authorization");
header("Content-Type: application/json");
 
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(200); exit(); }
 
// ══════════════════════════════════════
//  DATABASE CONFIG
// ══════════════════════════════════════
define('DB_HOST',   'localhost');
define('DB_NAME',   'eventsphere_db');  // your database name
define('DB_USER',   'root');
define('DB_PASS',   '');                // XAMPP default is blank
define('DB_PORT',   '3306');
define('JWT_SECRET','eventsphere_local_secret');
 
// ══════════════════════════════════════
//  DATABASE CONNECTION
// ══════════════════════════════════════
function db() {
    static $pdo = null;
    if ($pdo === null) {
        $dsn = "mysql:host=" . DB_HOST . ";port=" . DB_PORT . ";dbname=" . DB_NAME . ";charset=utf8mb4";
        try {
            $pdo = new PDO($dsn, DB_USER, DB_PASS, [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC
            ]);
        } catch (PDOException $e) {
            respond_error("Database connection failed: " . $e->getMessage(), 500);
        }
    }
    return $pdo;
}
 
// ══════════════════════════════════════
//  HELPERS
// ══════════════════════════════════════
function respond($data, $code = 200) {
    http_response_code($code);
    echo json_encode($data);
    exit();
}
 
function respond_error($msg, $code = 400) {
    http_response_code($code);
    echo json_encode(["error" => $msg]);
    exit();
}
 
function get_body() {
    return json_decode(file_get_contents("php://input"), true) ?? [];
}
 
function make_token($user_id) {
    $payload   = base64_encode(json_encode(["user_id" => $user_id, "exp" => time() + 86400 * 7]));
    $signature = base64_encode(hash_hmac('sha256', $payload, JWT_SECRET, true));
    return $payload . '.' . $signature;
}
 
function require_auth() {
    $headers = getallheaders();
    $auth    = $headers['Authorization'] ?? $headers['authorization'] ?? '';
    if (!$auth) respond_error("Unauthorized", 401);
 
    $token = str_replace('Bearer ', '', trim($auth));
    $parts = explode('.', $token);
    if (count($parts) !== 2) respond_error("Unauthorized", 401);
 
    [$payload, $signature] = $parts;
    $expected = base64_encode(hash_hmac('sha256', $payload, JWT_SECRET, true));
    if (!hash_equals($expected, $signature)) respond_error("Unauthorized", 401);
 
    $data = json_decode(base64_decode($payload), true);
    if (!$data || $data['exp'] < time()) respond_error("Unauthorized", 401);
 
    return (int) $data['user_id'];
}
 
// Get client row from user_id (creates one if missing)
function get_or_create_client($user_id) {
    $pdo  = db();
    $stmt = $pdo->prepare("SELECT * FROM clients WHERE user_id = ?");
    $stmt->execute([$user_id]);
    $client = $stmt->fetch();
    if (!$client) {
        $ins = $pdo->prepare("INSERT INTO clients (user_id, phone, created_at) VALUES (?, '', NOW())");
        $ins->execute([$user_id]);
        $stmt->execute([$user_id]);
        $client = $stmt->fetch();
    }
    return $client;
}
 
// ══════════════════════════════════════
//  ROUTER
// ══════════════════════════════════════
$route  = $_GET['route'] ?? '';
$method = $_SERVER['REQUEST_METHOD'];
 
switch ($route) {
 
    // ────────────────────────────────
    //  REGISTER
    //  POST ?route=register
    //  Body: { first_name, last_name, email, phone, password }
    //  Returns: { client_id, token }
    // ────────────────────────────────
    case 'register':
        if ($method !== 'POST') respond_error("Method not allowed", 405);
 
        $b        = get_body();
        $first    = trim($b['first_name'] ?? '');
        $last     = trim($b['last_name']  ?? '');
        $email    = trim($b['email']      ?? '');
        $phone    = trim($b['phone']      ?? '');
        $password = $b['password']        ?? '';
 
        if (!$first || !$last || !$email || !$password)
            respond_error("first_name, last_name, email, and password are required.");
 
        $pdo = db();
 
        // Check if email already exists in users
        $check = $pdo->prepare("SELECT id FROM users WHERE email = ?");
        $check->execute([$email]);
        if ($check->fetch()) respond_error("Email is already registered.");
 
        // Get the client role_id (role named 'client')
        $role_stmt = $pdo->prepare("SELECT id FROM roles WHERE LOWER(name) = 'client' LIMIT 1");
        $role_stmt->execute();
        $role = $role_stmt->fetch();
        $role_id = $role ? $role['id'] : 1; // fallback to 1 if no roles table match
 
        // Insert into users
        $hash = password_hash($password, PASSWORD_DEFAULT);
        $stmt = $pdo->prepare("INSERT INTO users (first_name, last_name, email, password_hash, role_id, is_active, created_at) VALUES (?, ?, ?, ?, ?, 1, NOW())");
        $stmt->execute([$first, $last, $email, $hash, $role_id]);
        $user_id = (int) $pdo->lastInsertId();
 
        // Insert into clients
        $ins = $pdo->prepare("INSERT INTO clients (user_id, phone, created_at) VALUES (?, ?, NOW())");
        $ins->execute([$user_id, $phone]);
        $client_id = (int) $pdo->lastInsertId();
 
        $token = make_token($user_id);
 
        respond(["client_id" => $client_id, "token" => $token], 201);
 
    // ────────────────────────────────
    //  LOGIN
    //  POST ?route=login
    //  Body: { email, password }
    //  Returns: { client_id, first_name, last_name, email, phone, token }
    // ────────────────────────────────
    case 'login':
        if ($method !== 'POST') respond_error("Method not allowed", 405);
 
        $b        = get_body();
        $email    = trim($b['email']    ?? '');
        $password = $b['password']      ?? '';
 
        if (!$email || !$password) respond_error("Email and password are required.");
 
        $pdo  = db();
        $stmt = $pdo->prepare("SELECT * FROM users WHERE email = ?");
        $stmt->execute([$email]);
        $user = $stmt->fetch();
 
        if (!$user || !password_verify($password, $user['password_hash']))
            respond_error("Invalid email or password.", 401);
 
        if (!$user['is_active'])
            respond_error("Account is inactive. Please contact support.", 403);
 
        // Get client profile
        $client = get_or_create_client($user['id']);
 
        $token = make_token($user['id']);
 
        respond([
            "client_id"  => (int) $client['id'],
            "first_name" => $user['first_name'],
            "last_name"  => $user['last_name'],
            "email"      => $user['email'],
            "phone"      => $client['phone'] ?? '',
            "token"      => $token
        ]);
 
    // ────────────────────────────────
    //  ME
    //  GET ?route=me
    //  Header: Authorization: Bearer <token>
    //  Returns: { client_id, first_name, last_name, email, phone }
    // ────────────────────────────────
    case 'me':
        if ($method !== 'GET') respond_error("Method not allowed", 405);
 
        $user_id = require_auth();
        $pdo     = db();
 
        $stmt = $pdo->prepare("SELECT * FROM users WHERE id = ?");
        $stmt->execute([$user_id]);
        $user = $stmt->fetch();
        if (!$user) respond_error("User not found.", 404);
 
        $client = get_or_create_client($user_id);
 
        respond([
            "client_id"  => (int) $client['id'],
            "first_name" => $user['first_name'],
            "last_name"  => $user['last_name'],
            "email"      => $user['email'],
            "phone"      => $client['phone'] ?? ''
        ]);
 
    // ────────────────────────────────
    //  BOOKINGS (maps to your "events" table)
    //  GET  ?route=bookings  — fetch all events for this client
    //  POST ?route=bookings  — create a new event
    //  Header: Authorization: Bearer <token>
    // ────────────────────────────────
    case 'bookings':
        $user_id = require_auth();
        $pdo     = db();
        $client  = get_or_create_client($user_id);
        $client_id = (int) $client['id'];
 
        if ($method === 'GET') {
            $stmt = $pdo->prepare("SELECT * FROM events WHERE client_id = ? ORDER BY created_at DESC");
            $stmt->execute([$client_id]);
            $rows = $stmt->fetchAll();
 
            // Map events columns to what the frontend expects
            $mapped = array_map(function($r) {
                return [
                    "booking_id"      => $r['id'],
                    "client_id"       => $r['client_id'],
                    "event_name"      => $r['title'],
                    "event_type"      => $r['event_type'],
                    "event_date"      => $r['event_date'],
                    "venue"           => $r['venue'],
                    "guest_count"     => $r['guest_count'],
                    "budget"          => $r['budget_php'],
                    "status"          => $r['status'],
                    "cover_photo_url" => '',
                    "services"        => [],
                    "special_requests"=> '',
                    "package_name"    => '',
                    "created_at"      => $r['created_at']
                ];
            }, $rows);
 
            respond($mapped);
        }
 
        if ($method === 'POST') {
            $b = get_body();
 
            $stmt = $pdo->prepare("
                INSERT INTO events (
                    client_id, title, event_type, event_date,
                    venue, guest_count, budget_php, status, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'Inquiry', NOW())
            ");
            $stmt->execute([
                $client_id,
                $b['event_name']  ?? $b['event_type'] ?? 'New Event',
                $b['event_type']  ?? '',
                $b['event_date']  ?? null,
                $b['venue']       ?? '',
                isset($b['guest_count']) ? (int)$b['guest_count']  : 0,
                isset($b['budget'])      ? (float)$b['budget']     : 0.00
            ]);
 
            respond(["booking_id" => (int) $pdo->lastInsertId(), "status" => "Inquiry"], 201);
        }
 
        respond_error("Method not allowed", 405);
 
    // ────────────────────────────────
    //  INVOICES
    //  GET ?route=invoices — fetch all invoices for this client
    //  Header: Authorization: Bearer <token>
    // ────────────────────────────────
    case 'invoices':
        $user_id = require_auth();
        $pdo     = db();
        $client  = get_or_create_client($user_id);
        $client_id = (int) $client['id'];
 
        if ($method === 'GET') {
            // Join invoices with events to get event name
            $stmt = $pdo->prepare("
                SELECT
                    i.id            AS invoice_id,
                    i.event_id,
                    e.title         AS event_name,
                    i.amount,
                    i.due_date,
                    i.status,
                    i.created_at
                FROM invoices i
                JOIN events e ON e.id = i.event_id
                WHERE e.client_id = ?
                ORDER BY i.created_at DESC
            ");
            $stmt->execute([$client_id]);
 
            $rows = $stmt->fetchAll();
            $mapped = array_map(function($r) {
                return [
                    "invoice_id"     => $r['invoice_id'],
                    "client_id"      => null,
                    "invoice_number" => 'INV-' . str_pad($r['invoice_id'], 4, '0', STR_PAD_LEFT),
                    "event_name"     => $r['event_name'],
                    "total"          => $r['amount'],
                    "due_date"       => $r['due_date'],
                    "status"         => $r['status'],
                    "created_at"     => $r['created_at']
                ];
            }, $rows);
 
            respond($mapped);
        }
 
        respond_error("Method not allowed", 405);
 
    // ────────────────────────────────
    //  404
    // ────────────────────────────────
    default:
        respond_error("Route '$route' not found.", 404);
}

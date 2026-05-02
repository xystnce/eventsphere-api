<?php
/**
 * EventSphere Unified API — Aiven MySQL backend
 * Upload to InfinityFree: htdocs/api/api.php
 */

$DB_HOST = 'switchyard.proxy.rlwy.net';
$DB_PORT = 45462;
$DB_USER = 'root';
$DB_PASS = 'EEvLcaHtQYjyearjqgygaGYFMjZcXExz';
$DB_NAME = 'railway';

header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
header('Content-Type: application/json');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(200); exit; }

function getDB() {
    global $DB_HOST,$DB_PORT,$DB_USER,$DB_PASS,$DB_NAME;
    static $conn=null;
    if($conn===null){
        $conn=new mysqli($DB_HOST,$DB_USER,$DB_PASS,$DB_NAME,$DB_PORT);
        if($conn->connect_error) respond(['error'=>'DB: '.$conn->connect_error],500);
        $conn->set_charset('utf8mb4');
    }
    return $conn;
}
function getInput(){return json_decode(file_get_contents('php://input'),true)??[];}
function respond($d,$c=200){http_response_code($c);echo json_encode($d);exit;}
function b64e($d){return rtrim(strtr(base64_encode($d),'+/','-_'),'=');}
function b64d($d){return base64_decode(strtr($d,'-_','+/'));}
function createToken($p){
    $s='eventsphere-jwt-2024';
    $h=b64e(json_encode(['alg'=>'HS256','typ'=>'JWT']));
    $p['exp']=time()+86400;
    $pl=b64e(json_encode($p));
    $sig=b64e(hash_hmac('sha256',"$h.$pl",$s,true));
    return "$h.$pl.$sig";
}
function decodeToken($t){
    $s='eventsphere-jwt-2024';
    $p=explode('.',$t);
    if(count($p)!==3)return null;
    if(b64e(hash_hmac('sha256',"$p[0].$p[1]",$s,true))!==$p[2])return null;
    $pl=json_decode(b64d($p[1]),true);
    if(!$pl||($pl['exp']??0)<time())return null;
    return $pl;
}
function getAuthUser(){
    $a=$_SERVER['HTTP_AUTHORIZATION']??'';
    if(strpos($a,'Bearer ')!==0)return null;
    return decodeToken(substr($a,7));
}
function requireAuth(){$u=getAuthUser();if(!$u)respond(['error'=>'Unauthorized'],401);return $u;}
function requireStaff(){$u=requireAuth();if(($u['type']??''!=='staff'))respond(['error'=>'Staff only'],403);return $u;}

$route=$_GET['route']??'';
$method=$_SERVER['REQUEST_METHOD'];

// PING
if($route===''||$route==='ping'){
    $db=getDB();
    respond(['status'=>'ok','db'=>'aiven','tables'=>$db->query("SHOW TABLES")->num_rows,'time'=>date('Y-m-d H:i:s')]);
}

// CLIENT REGISTER
if($route==='register'&&$method==='POST'){
    $d=getInput();
    if(empty($d['email'])||empty($d['password']))respond(['error'=>'Missing fields'],400);
    $db=getDB();
    $st=$db->prepare("SELECT id FROM users WHERE email=?");$st->bind_param('s',$d['email']);$st->execute();
    if($st->get_result()->num_rows>0)respond(['error'=>'Email already registered'],409);
    $hash=password_hash($d['password'],PASSWORD_BCRYPT);
    $res=$db->query("SELECT id FROM roles WHERE LOWER(name)='client' LIMIT 1");
    $row=$res->fetch_assoc();$roleId=$row?$row['id']:0;
    $fn=$d['first_name']??'';$ln=$d['last_name']??'';
    $st=$db->prepare("INSERT INTO users(first_name,last_name,email,password_hash,role_id,is_active)VALUES(?,?,?,?,?,1)");
    $st->bind_param('ssssi',$fn,$ln,$d['email'],$hash,$roleId);$st->execute();
    $uid=$db->insert_id;
    $db->query("INSERT INTO clients(user_id)VALUES($uid)");
    $cid=$db->insert_id;
    $tok=createToken(['type'=>'client','client_id'=>$cid,'user_id'=>$uid,'email'=>$d['email'],'first_name'=>$fn,'last_name'=>$ln]);
    respond(['token'=>$tok,'client_id'=>$cid,'message'=>'Account created'],201);
}

// CLIENT LOGIN
if($route==='login'&&$method==='POST'){
    $d=getInput();
    if(empty($d['email'])||empty($d['password']))respond(['error'=>'Missing fields'],400);
    $db=getDB();
    $st=$db->prepare("SELECT u.*,r.name AS role_name,c.id AS client_id FROM users u
        JOIN roles r ON u.role_id=r.id LEFT JOIN clients c ON c.user_id=u.id
        WHERE u.email=? AND u.is_active=1 AND LOWER(r.name)='client'");
    $st->bind_param('s',$d['email']);$st->execute();
    $u=$st->get_result()->fetch_assoc();
    if(!$u)respond(['error'=>'Invalid email or password'],401);
    $ok=password_verify($d['password'],$u['password_hash'])||$u['password_hash']===$d['password'];
    if(!$ok)respond(['error'=>'Invalid email or password'],401);
    $tok=createToken(['type'=>'client','client_id'=>$u['client_id'],'user_id'=>$u['id'],
        'email'=>$u['email'],'first_name'=>$u['first_name'],'last_name'=>$u['last_name']]);
    respond(['token'=>$tok,'client_id'=>$u['client_id'],'first_name'=>$u['first_name'],'last_name'=>$u['last_name'],'email'=>$u['email']]);
}

// STAFF LOGIN
if($route==='staff-login'&&$method==='POST'){
    $d=getInput();
    if(empty($d['email'])||empty($d['password']))respond(['error'=>'Missing fields'],400);
    $db=getDB();
    $st=$db->prepare("SELECT u.*,r.name AS role_name FROM users u JOIN roles r ON u.role_id=r.id
        WHERE u.email=? AND u.is_active=1 AND LOWER(r.name)!='client'");
    $st->bind_param('s',$d['email']);$st->execute();
    $s=$st->get_result()->fetch_assoc();
    if(!$s)respond(['error'=>'Invalid credentials'],401);
    $ok=password_verify($d['password'],$s['password_hash'])||$s['password_hash']===$d['password'];
    if(!$ok)respond(['error'=>'Invalid credentials'],401);
    $tok=createToken(['type'=>'staff','staff_id'=>$s['id'],'role_id'=>$s['role_id'],
        'role'=>$s['role_name'],'email'=>$s['email'],'first_name'=>$s['first_name'],'last_name'=>$s['last_name']]);
    respond(['token'=>$tok,'staff_id'=>$s['id'],'role'=>$s['role_name'],'first_name'=>$s['first_name'],'last_name'=>$s['last_name']]);
}

// ME
if($route==='me'&&$method==='GET'){
    $u=requireAuth();$db=getDB();
    $id=$u['type']==='client'?$u['user_id']:$u['staff_id'];
    $st=$db->prepare("SELECT u.id,u.first_name,u.last_name,u.email,r.name AS role_name
        FROM users u JOIN roles r ON u.role_id=r.id WHERE u.id=?");
    $st->bind_param('i',$id);$st->execute();
    respond($st->get_result()->fetch_assoc()??['error'=>'Not found']);
}

// BOOKINGS GET
if($route==='bookings'&&$method==='GET'){
    $u=requireAuth();$db=getDB();
    if($u['type']==='client'){
        $st=$db->prepare("SELECT e.id AS booking_id,e.client_id,e.title AS event_name,
            e.event_type,e.event_date,e.venue,e.guest_count,e.budget_php AS budget,
            e.status,e.created_at,p.name AS package_name
            FROM events e LEFT JOIN packages p ON e.package_id=p.id
            WHERE e.client_id=? ORDER BY e.created_at DESC");
        $st->bind_param('i',$u['client_id']);
    }else{
        $st=$db->prepare("SELECT e.id AS booking_id,e.client_id,e.title AS event_name,
            e.event_type,e.event_date,e.venue,e.guest_count,e.budget_php AS budget,
            e.status,e.created_at,p.name AS package_name,
            u.first_name AS client_first,u.last_name AS client_last
            FROM events e LEFT JOIN packages p ON e.package_id=p.id
            LEFT JOIN clients c ON e.client_id=c.id LEFT JOIN users u ON c.user_id=u.id
            ORDER BY e.created_at DESC");
    }
    $st->execute();respond($st->get_result()->fetch_all(MYSQLI_ASSOC));
}

// BOOKINGS POST
if($route==='bookings'&&$method==='POST'){
    $u=requireAuth();$d=getInput();
    if(empty($d['event_name'])||empty($d['event_date']))respond(['error'=>'event_name and event_date required'],400);
    $db=getDB();
    $cid=$u['client_id']??0;$pid=!empty($d['package_id'])?intval($d['package_id']):null;
    $et=$d['event_type']??'General';$v=$d['venue']??'';$gc=intval($d['guest_count']??0);$b=floatval($d['budget']??0);
    $st=$db->prepare("INSERT INTO events(client_id,package_id,title,event_type,event_date,venue,guest_count,budget_php,status)VALUES(?,?,?,?,?,?,?,?,'Inquiry')");
    $st->bind_param('iissssid',$cid,$pid,$d['event_name'],$et,$d['event_date'],$v,$gc,$b);
    $st->execute();respond(['booking_id'=>$db->insert_id,'message'=>'Booking submitted'],201);
}

// BOOKINGS PUT
if($route==='bookings'&&$method==='PUT'){
    requireStaff();$d=getInput();
    $id=intval($_GET['id']??$d['booking_id']??0);
    if(!$id)respond(['error'=>'id required'],400);
    $db=getDB();$sets=[];$vals=[];$types='';
    foreach(['status','venue','event_date','event_type'] as $k){
        if(isset($d[$k])){$sets[]="$k=?";$vals[]=$d[$k];$types.='s';}
    }
    if(empty($sets))respond(['error'=>'Nothing to update'],400);
    $vals[]=$id;$types.='i';
    $st=$db->prepare("UPDATE events SET ".implode(',',$sets)." WHERE id=?");
    $st->bind_param($types,...$vals);$st->execute();
    respond(['message'=>'Booking updated']);
}

// INVOICES GET
if($route==='invoices'&&$method==='GET'){
    $u=requireAuth();$db=getDB();
    if($u['type']==='client'){
        $st=$db->prepare("SELECT i.id AS invoice_id,i.invoice_number,i.event_id AS booking_id,
            i.status,i.due_date,i.total_amount AS total,i.created_at,e.title AS event_name
            FROM invoices i JOIN events e ON i.event_id=e.id
            WHERE e.client_id=? ORDER BY i.created_at DESC");
        $st->bind_param('i',$u['client_id']);
    }else{
        $st=$db->prepare("SELECT i.id AS invoice_id,i.invoice_number,i.event_id AS booking_id,
            i.status,i.due_date,i.total_amount AS total,i.created_at,e.title AS event_name,
            u.first_name AS client_first,u.last_name AS client_last
            FROM invoices i JOIN events e ON i.event_id=e.id
            LEFT JOIN clients c ON e.client_id=c.id LEFT JOIN users u ON c.user_id=u.id
            ORDER BY i.created_at DESC");
    }
    $st->execute();respond($st->get_result()->fetch_all(MYSQLI_ASSOC));
}

// INVOICES POST
if($route==='invoices'&&$method==='POST'){
    requireStaff();$d=getInput();$db=getDB();
    $cnt=$db->query("SELECT COUNT(*) AS c FROM invoices")->fetch_assoc()['c'];
    $inv='INV-'.(2400+$cnt+1);$total=$d['total']??$d['total_amount']??0;
    $st=$db->prepare("INSERT INTO invoices(invoice_number,event_id,total_amount,due_date)VALUES(?,?,?,?)");
    $st->bind_param('sids',$inv,$d['booking_id'],$total,$d['due_date']);$st->execute();
    respond(['invoice_id'=>$db->insert_id,'invoice_number'=>$inv],201);
}

// INVOICES PUT
if($route==='invoices'&&$method==='PUT'){
    requireStaff();$d=getInput();
    $id=intval($_GET['id']??$d['invoice_id']??0);
    if(!$id)respond(['error'=>'id required'],400);
    $db=getDB();
    if(!empty($d['status'])){
        $st=$db->prepare("UPDATE invoices SET status=? WHERE id=?");
        $st->bind_param('si',$d['status'],$id);$st->execute();
    }
    respond(['message'=>'Invoice updated']);
}

// MESSAGES GET
if($route==='messages'&&$method==='GET'){
    $u=requireAuth();$db=getDB();
    if($u['type']==='client'){
        $st=$db->prepare("SELECT id AS message_id,subject AS content,description,
            status,priority,resolution_notes,created_at,'client' AS sender_type
            FROM support_tickets WHERE client_id=? ORDER BY created_at DESC");
        $st->bind_param('i',$u['client_id']);
    }elseif(!empty($_GET['client_id'])){
        $cid=intval($_GET['client_id']);
        $st=$db->prepare("SELECT st.*,st.subject AS content,u.first_name AS client_first,u.last_name AS client_last
            FROM support_tickets st JOIN clients c ON st.client_id=c.id JOIN users u ON c.user_id=u.id
            WHERE st.client_id=? ORDER BY st.created_at ASC");
        $st->bind_param('i',$cid);
    }else{
        $st=$db->prepare("SELECT st.id,st.client_id,st.subject AS content,st.status,st.priority,st.created_at,
            u.first_name AS client_first,u.last_name AS client_last
            FROM support_tickets st JOIN clients c ON st.client_id=c.id JOIN users u ON c.user_id=u.id
            ORDER BY st.created_at DESC LIMIT 100");
    }
    $st->execute();respond($st->get_result()->fetch_all(MYSQLI_ASSOC));
}

// MESSAGES POST
if($route==='messages'&&$method==='POST'){
    $u=requireAuth();$d=getInput();$db=getDB();
    if($u['type']==='client'){
        $sub=$d['content']??$d['subject']??'Inquiry';$desc=$d['description']??'';
        $cid=$u['client_id'];$eid=$d['booking_id']??null;
        $st=$db->prepare("INSERT INTO support_tickets(client_id,event_id,subject,description,priority)VALUES(?,?,?,?,'medium')");
        $st->bind_param('iiss',$cid,$eid,$sub,$desc);
    }else{
        if(empty($d['client_id']))respond(['error'=>'client_id required'],400);
        $content=$d['content']??'';
        $st=$db->prepare("UPDATE support_tickets SET resolution_notes=?,status='in_progress' WHERE client_id=? ORDER BY created_at DESC LIMIT 1");
        $st->bind_param('si',$content,$d['client_id']);
    }
    $st->execute();respond(['message_id'=>$db->insert_id],201);
}

// PACKAGES
if($route==='packages'&&$method==='GET'){
    $db=getDB();
    $r=$db->query("SELECT id AS package_id,name,description,price AS base_price FROM packages ORDER BY price ASC");
    respond($r->fetch_all(MYSQLI_ASSOC));
}

// STAFF GET
if($route==='staff'&&$method==='GET'){
    requireStaff();$db=getDB();
    $st=$db->prepare("SELECT u.id AS staff_id,u.role_id,u.first_name,u.last_name,u.email,u.is_active,r.name AS role_name
        FROM users u JOIN roles r ON u.role_id=r.id WHERE LOWER(r.name)!='client' ORDER BY u.first_name");
    $st->execute();respond($st->get_result()->fetch_all(MYSQLI_ASSOC));
}

// STAFF POST
if($route==='staff'&&$method==='POST'){
    requireStaff();$d=getInput();$db=getDB();
    $hash=password_hash($d['password'],PASSWORD_BCRYPT);
    $st=$db->prepare("INSERT INTO users(role_id,first_name,last_name,email,password_hash,is_active)VALUES(?,?,?,?,?,1)");
    $st->bind_param('issss',$d['role_id'],$d['first_name'],$d['last_name'],$d['email'],$hash);
    $st->execute();respond(['staff_id'=>$db->insert_id,'message'=>'Staff created'],201);
}

// STAFF PUT
if($route==='staff'&&$method==='PUT'){
    requireStaff();$d=getInput();
    $id=intval($_GET['id']??0);if(!$id)respond(['error'=>'id required'],400);
    $db=getDB();$active=intval($d['is_active']??1);
    $st=$db->prepare("UPDATE users SET is_active=? WHERE id=?");
    $st->bind_param('ii',$active,$id);$st->execute();
    respond(['message'=>'Staff updated']);
}

// ROLES
if($route==='roles'&&$method==='GET'){
    $db=getDB();
    respond($db->query("SELECT id AS role_id,name AS role_name FROM roles ORDER BY id")->fetch_all(MYSQLI_ASSOC));
}

// NOTIFICATIONS (stub)
if($route==='notifications'){respond($method==='GET'?[]:['message'=>'ok']);}

// CALENDAR (stub)
if($route==='calendar-events'||$route==='calendar-blocks'){respond([]);}

respond(['error'=>'Route not found: '.$route],404);

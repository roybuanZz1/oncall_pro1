<?php
header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type');
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') exit;
ob_start();

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

function debug_log($msg) {
    file_put_contents(__DIR__.'/debug.log', print_r($msg, true)."\n", FILE_APPEND);
}


$conn = @new mysqli("localhost", "root", "", "", 3307);

if ($conn->connect_error) {
    debug_log("DB_CONNECT_ERROR: " . $conn->connect_error);
    if (ob_get_length()) ob_clean();
    http_response_code(500);
    die(json_encode([
        "success" => false,
        "error" => "Database connection failed",
        "details" => $conn->connect_error
    ]));
}


$dbName = "oncall_pro";
if (!$conn->select_db($dbName)) {
    debug_log("DB_SELECT_DB_ERROR: ".$conn->error);
    if (ob_get_length()) ob_clean();
    die(json_encode([
        "success" => false,
        "error" => "Database 'oncall_pro' not found",
        "details" => $conn->error
    ]));
}


$inputStr = file_get_contents("php://input");
$input = json_decode($inputStr, true);
$jsonError = json_last_error();
// Always log incoming request for debugging
debug_log("REQUEST raw_len=" . strlen($inputStr) . " json_error=" . $jsonError . " body=" . substr($inputStr, 0, 400));

if ($jsonError !== JSON_ERROR_NONE) {
    if (ob_get_length()) ob_clean();
    echo json_encode([
        "success" => false,
        "error" => "Invalid JSON body",
        "details" => json_last_error_msg(),
        "raw_preview" => substr($inputStr, 0, 200)
    ]);
    exit;
}
if (!is_array($input)) {
    debug_log("INPUT_NOT_ARRAY: " . print_r($input, true));
    if (ob_get_length()) ob_clean();
    echo json_encode([
        "success" => false,
        "error" => "Request body must be a JSON object",
        "raw_preview" => substr($inputStr, 0, 200)
    ]);
    exit;
}
if (!isset($input['action']) || (is_string($input['action']) && trim((string)$input['action']) === '')) {
    debug_log("INPUT_ERROR no action: " . print_r($inputStr, true));
    if (ob_get_length()) ob_clean();
    echo json_encode([
        "success" => false,
        "error" => "No action provided",
        "reason" => "Your request JSON must include a non-empty 'action' key, e.g. {\"action\":\"signup\", ...}.",
        "received_keys" => array_keys($input)
    ]);
    exit;
}
$action = strtolower(trim((string) $input['action']));
debug_log("ACTION parsed: " . var_export($action, true) . " len=" . strlen($action));

// ===== HELPER FUNCTIONS =====
function ok($data = []) {
    if (ob_get_length()) ob_clean();
    echo json_encode(array_merge(["success" => true], $data));
    exit;
}

function err($msg, $details = null) {
    debug_log("ERROR: $msg".($details ? " | $details" : ""));
    if (ob_get_length()) ob_clean();
    $out = ["success" => false, "error" => $msg];
    if ($details !== null) {
        $out["details"] = $details;
    }
    echo json_encode($out);
    exit;
}

function get_email($input) {
    if (!empty($input['email'])) return trim($input['email']);
    if (isset($input['user']) && isset($input['user']['email'])) return trim($input['user']['email']);
    return '';
}

// Get user id from email using the oncall_pro.users table
function get_user_id_by_email($conn, $email) {
    $stmt = $conn->prepare("SELECT id FROM users WHERE email=?");
    if (!$stmt) {
        err("User lookup failed", $conn->error);
    }
    $stmt->bind_param("s", $email);
    $stmt->execute();
    // Initialize to avoid "unassigned variable" warnings in static analysis
    $userId = null;
    $stmt->bind_result($userId);
    if (!$stmt->fetch()) {
        $stmt->close();
        err("User not found for given email");
    }
    $stmt->close();
    return $userId;
}


if ($action === "signup") {

    $name = trim($input['name'] ?? "");
    $email = trim($input['email'] ?? "");
    $pass = $input['pass'] ?? "";

    if (!$name || !$email || strlen($pass) < 6) {
        err("Fill all fields (min 6 chars password)");
    }

    $check = $conn->prepare("SELECT id FROM users WHERE email=?");
    if (!$check) err("Failed to prepare user check", $conn->error);
    $check->bind_param("s", $email);
    $check->execute();
    $check->store_result();

    if ($check->num_rows > 0) err("Email already exists");
    $check->close();

    $hash = password_hash($pass, PASSWORD_DEFAULT);

    $stmt = $conn->prepare("INSERT INTO users(name,email,password) VALUES(?,?,?)");
    if (!$stmt) err("Could not create user (prepare failed)", $conn->error);
    $stmt->bind_param("sss", $name, $email, $hash);

    if (!$stmt->execute()) err("Could not create user", $stmt->error);
    $stmt->close();

    ok();
}


if ($action === "login") {

    $email = trim($input['email'] ?? "");
    $pass = $input['pass'] ?? "";

    if (empty($email)) err("Email required");

    $stmt = $conn->prepare("SELECT id,name,password FROM users WHERE email=?");
    if (!$stmt) err("Login failed (prepare error)", $conn->error);
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->bind_result($id, $name, $hash);

    $fetch_result = $stmt->fetch();
    if (!$fetch_result || $hash === null) {
        $stmt->close();
        err("Account not found");
    }

    if (!password_verify($pass, (string)$hash)) {
        $stmt->close();
        err("Wrong password");
    }
    $stmt->close();

    ok([
        "user" => [
            "id" => $id,
            "name" => $name,
            "email" => $email
        ]
    ]);
}


// Support both "delete_account" (frontend) and "delete_user" (e.g. external clients)
if ($action === "delete_account" || $action === "delete_user") {
    $email = get_email($input);
    $pass = trim((string)($input['pass'] ?? $input['password'] ?? ""));

    if (empty($email)) err("Email required");
    if (empty($pass)) err("Password required to confirm account deletion");

    // Verify user exists and password matches
    $stmt = $conn->prepare("SELECT id, password FROM users WHERE email=?");
    if (!$stmt) err("Account check prepare failed", $conn->error);
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->bind_result($userId, $hash);
    $found = $stmt->fetch();

    $stmt->close();

    if (!$found) err("Account not found");
    if (!password_verify($pass, (string)$hash)) err("Wrong password");

    // In oncall_pro the schema uses foreign keys with ON DELETE CASCADE
    // and a trigger to log deleted users, so deleting the user row is enough.
    $stmtDel = $conn->prepare("DELETE FROM users WHERE id=?");
    if (!$stmtDel) {
        err("Delete user prepare failed", $conn->error);
    }
    $stmtDel->bind_param("i", $userId);
    if (!$stmtDel->execute()) {
        $errMsg = $stmtDel->error;
        $stmtDel->close();
        err("Could not delete account", $errMsg);
    }
    $stmtDel->close();

    ok(["message" => "Account deleted."]);
}


if ($action === "create_room" || $action === "auto_create_room") {
    // For backward compatibility: "create_room" and "auto_create_room" both support automatic room id creation.
    $email = get_email($input);
    if (empty($email)) err("Email required");

    // Map email to user_id in oncall_pro.users
    $userId = get_user_id_by_email($conn, $email);

    // In oncall_pro the rooms table has a BEFORE INSERT trigger that auto-generates room_code
    $stmt = $conn->prepare("INSERT INTO rooms(room_code,created_by) VALUES(NULL, ?)");
    if (!$stmt) err("Could not create room (prepare failed)", $conn->error);
    $stmt->bind_param("i", $userId);
    if (!$stmt->execute()) err("Could not create room", $stmt->error);

    $roomId = $stmt->insert_id;
    $stmt->close();

    // Fetch the generated room_code
    $stmtCode = $conn->prepare("SELECT room_code FROM rooms WHERE id=?");
    if (!$stmtCode) err("Could not fetch room code", $conn->error);
    $stmtCode->bind_param("i", $roomId);
    $stmtCode->execute();
    $stmtCode->bind_result($roomCode);
    if (!$stmtCode->fetch()) {
        $stmtCode->close();
        err("Room created but could not read code");
    }
    $stmtCode->close();

    // Add creator as participant (active join)
    $stmtPart = $conn->prepare("INSERT INTO room_participants(room_id,user_id) VALUES(?,?)");
    if (!$stmtPart) err("Could not add creator to room participants", $conn->error);
    $stmtPart->bind_param("ii", $roomId, $userId);
    if (!$stmtPart->execute()) {
        $errMsg = $stmtPart->error;
        $stmtPart->close();
        err("Room was created but could not add participant", $errMsg);
    }
    $stmtPart->close();

    ok(["room_code" => $roomCode, "room_id" => $roomId]);
}


if ($action === "auto_create_room") {
    // Already handled above together with 'create_room'
    exit; // Prevent double handling
}


if ($action === "join_room") {
    $roomCode = trim($input['room_code'] ?? "");
    $email = get_email($input);

    if (empty($roomCode) || empty($email)) err("Room code and email required");

    // Resolve room by either room_code or numeric room id
    $roomIdNumeric = ctype_digit($roomCode) ? (int)$roomCode : 0;
    $stmt = $conn->prepare("SELECT id FROM rooms WHERE room_code=? OR id=?");
    if (!$stmt) err("Check room existence prepare failed", $conn->error);
    $stmt->bind_param("si", $roomCode, $roomIdNumeric);
    $stmt->execute();
    $stmt->bind_result($roomId);

    if (!$stmt->fetch()) {
        $stmt->close();
        err("Room not found");
    }
    $stmt->close();

    // Use room_participants with user_id (oncall_pro schema)
    $userId = get_user_id_by_email($conn, $email);

    $stmt = $conn->prepare("SELECT id FROM room_participants WHERE room_id=? AND user_id=? AND left_at IS NULL");
    if (!$stmt) err("Check membership prepare failed", $conn->error);
    $stmt->bind_param("ii", $roomId, $userId);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows == 0) {
        $stmtInsert = $conn->prepare("INSERT INTO room_participants(room_id,user_id) VALUES(?,?)");
        if (!$stmtInsert) {
            err("Could not join room (prepare failed)", $conn->error);
        }
        $stmtInsert->bind_param("ii", $roomId, $userId);
        if (!$stmtInsert->execute()) {
            $errMsg = $stmtInsert->error;
            $stmtInsert->close();
            err("Could not join room", $errMsg);
        }
        $stmtInsert->close();
    }
    $stmt->close();

    ok();
}


if ($action === "leave_room") {
    $roomRef = trim($input['room_id'] ?? "");
    $email   = get_email($input);

    if (empty($roomRef) || empty($email)) err("Room id and email required");

    // Resolve room id from either room_code or numeric id
    $roomIdNumeric = ctype_digit($roomRef) ? (int)$roomRef : 0;
    $stmt = $conn->prepare("SELECT id FROM rooms WHERE room_code=? OR id=?");
    if (!$stmt) err("Leave room failed (room lookup)", $conn->error);
    $stmt->bind_param("si", $roomRef, $roomIdNumeric);
    $stmt->execute();
    $stmt->bind_result($roomId);
    if (!$stmt->fetch()) {
        $stmt->close();
        err("Room not found");
    }
    $stmt->close();

    // Map email to user id and mark the participant as left (set left_at)
    $userId = get_user_id_by_email($conn, $email);

    $stmtDel = $conn->prepare("UPDATE room_participants SET left_at = CURRENT_TIMESTAMP WHERE room_id=? AND user_id=? AND left_at IS NULL");
    if (!$stmtDel) err("Leave room failed (prepare)", $conn->error);
    $stmtDel->bind_param("ii", $roomId, $userId);
    $stmtDel->execute();
    $stmtDel->close();

    ok();
}


if ($action === "delete_room") {
    $roomRef = trim($input['room_id'] ?? "");
    if (empty($roomRef)) err("Room id required");

    // Resolve room id from either room_code or numeric id
    $roomIdNumeric = ctype_digit($roomRef) ? (int)$roomRef : 0;
    $stmt = $conn->prepare("SELECT id FROM rooms WHERE room_code=? OR id=?");
    if (!$stmt) err("Delete room failed (room lookup)", $conn->error);
    $stmt->bind_param("si", $roomRef, $roomIdNumeric);
    $stmt->execute();
    $stmt->bind_result($roomId);
    if (!$stmt->fetch()) {
        $stmt->close();
        err("Room not found");
    }
    $stmt->close();

    // In oncall_pro, room_participants (and the messages table we add)
    // should use ON DELETE CASCADE on room_id, so deleting the room
    // row will cascade deletions.
    $stmtDel = $conn->prepare("DELETE FROM rooms WHERE id=?");
    if (!$stmtDel) err("Could not delete room (prepare failed)", $conn->error);
    $stmtDel->bind_param("i", $roomId);
    if (!$stmtDel->execute()) {
        $errMsg = $stmtDel->error;
        $stmtDel->close();
        err("Could not delete room", $errMsg);
    }
    $stmtDel->close();

    ok();
}


if ($action === "send_message") {
    $roomCode = trim($input['room_code'] ?? "");
    $message = trim($input['message'] ?? "");
    $email = get_email($input);
    if (empty($roomCode) || empty($email) || empty($message)) err("Missing data");

    $stmt = $conn->prepare("SELECT id FROM rooms WHERE room_code=?");
    if (!$stmt) err("Room check prepare failed", $conn->error);
    $stmt->bind_param("s", $roomCode);
    $stmt->execute();
    $stmt->bind_result($roomId);
    if (!$stmt->fetch()) {
        $stmt->close();
        err("Room not found");
    }
    $stmt->close();

    // Store sender email in messages; room_id is FK to rooms.id in oncall_pro
    $stmtMsg = $conn->prepare("INSERT INTO messages(room_id,sender_email,message) VALUES(?,?,?)");
    if (!$stmtMsg) err("Could not send message (prepare failed)", $conn->error);
    $stmtMsg->bind_param("iss", $roomId, $email, $message);
    if (!$stmtMsg->execute()) {
        $stmtMsg->close();
        err("Could not send message", $stmtMsg->error);
    }
    $stmtMsg->close();

    ok();
}


if ($action === "start_call") {
    // Frontend only needs a success response; you can
    // extend this later to track active calls in DB.
    ok();
}

if ($action === "end_call") {
    ok();
}


if ($action === "fetch_messages") {
    $roomCode = trim($input['room_code'] ?? "");
    if (empty($roomCode)) err("Room code required");

    $stmt = $conn->prepare("SELECT id FROM rooms WHERE room_code=?");
    if (!$stmt) err("Room check prepare failed", $conn->error);
    $stmt->bind_param("s", $roomCode);
    $stmt->execute();
    $stmt->bind_result($roomId);
    if (!$stmt->fetch()) {
        $stmt->close();
        err("Room not found");
    }
    $stmt->close();

    $stmtMessages = $conn->prepare("SELECT sender_email AS sender,message,created_at FROM messages WHERE room_id=? ORDER BY id ASC");
    if (!$stmtMessages) err("Could not fetch messages (prepare failed)", $conn->error);
    $stmtMessages->bind_param("i", $roomId);
    $stmtMessages->execute();
    $result = $stmtMessages->get_result();

    $messages = [];
    if ($result) {
        while ($row = $result->fetch_assoc()) {
            $messages[] = $row;
        }
    }
    $stmtMessages->close();

    ok(["messages" => $messages]);
}

// If no matching action, log and return helpful error:
debug_log("INVALID_ACTION: " . $action . " | raw_action_type=" . gettype($input['action'] ?? null));
if (ob_get_length()) ob_clean();
echo json_encode([
    "success" => false,
    "error" => "Invalid action",
    "action_provided" => $action,
    "action_length" => strlen($action),
    "expected_actions" => [
        "signup",
        "login",
        "delete_account",
        "delete_user",
        "create_room",
        "auto_create_room",
        "join_room",
        "leave_room",
        "delete_room",
        "start_call",
        "end_call",
        "send_message",
        "fetch_messages"
    ],
    "tip" => "Action must be exactly one of the expected_actions (case-insensitive). Check Network tab for the request body.",
    "debug_request_preview" => substr($inputStr, 0, 300)
]);
exit;
?>
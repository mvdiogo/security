<?php
header('Content-Type: application/json');

try {
    // Testar MySQL
    $mysql = new PDO('mysql:host=mysql;dbname=appdb', 'appuser', 'userpass123');
    $mysql_tables = $mysql->query("SHOW TABLES")->fetchAll(PDO::FETCH_COLUMN);
    
    // Testar SQLite
    $sqlite = new PDO('sqlite:/tmp/test.db');
    $sqlite_tables = $sqlite->query("SELECT name FROM sqlite_master WHERE type='table'")->fetchAll(PDO::FETCH_COLUMN);
    
    echo json_encode([
        'mysql_connected' => true,
        'mysql_tables' => $mysql_tables,
        'sqlite_connected' => true,
        'sqlite_tables' => $sqlite_tables,
        'status' => 'OK'
    ], JSON_PRETTY_PRINT);
    
} catch (Exception $e) {
    echo json_encode([
        'error' => $e->getMessage(),
        'status' => 'ERROR'
    ], JSON_PRETTY_PRINT);
}
?>
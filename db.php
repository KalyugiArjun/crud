<?php
/**
 * Database Connection using PDO (Secure & Prepared Statements)
 */

$host     = '127.0.0.1';
$db       = 'crud_db';
$user     = 'root';
$password = ''; // Set your MySQL password if any
$charset  = 'utf8mb4';

$dsn = "mysql:host={$host};dbname={$db};charset={$charset}";
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
];

try {
    $pdo = new PDO($dsn, $user, $password, $options);
} catch (\PDOException $e) {
    // In production, log error instead of exposing raw database messages
    error_log("Database connection failed: " . $e->getMessage());
    $pdo = null;
}

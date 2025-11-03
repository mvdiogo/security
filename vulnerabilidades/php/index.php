<?php
header('Content-Type: application/json');

// Log para debugging
function log_attempt($vulnerability, $payload, $success) {
    $log_entry = sprintf(
        "[%s] %s: %s | Payload: %s\n",
        date('Y-m-d H:i:s'),
        $vulnerability,
        $success ? 'EXPLORADA' : 'FALHOU',
        substr(json_encode($payload), 0, 100)
    );
    file_put_contents('/tmp/exploit_attempts.log', $log_entry, FILE_APPEND);
}

function initSqliteDatabase() {
    try {
        $db = new PDO('sqlite:/tmp/test.db');
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $db->exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, bio TEXT)");
        
        // Verifica se a tabela está vazia
        $count = $db->query("SELECT COUNT(*) FROM users")->fetchColumn();
        if ($count == 0) {
            $db->exec("INSERT INTO users (id, username, bio) VALUES 
                      (1, 'admin', 'Administrator account'), 
                      (2, 'guest', 'Guest account'),
                      (3, 'test', 'Test account')");
        }
        return $db;
    } catch (PDOException $e) {
        return ['error' => 'SQLite: ' . $e->getMessage()];
    }
}

function initMysqlDatabase() {
    $host = 'mysql';
    $port = 3306;
    $dbname = 'appdb';
    $user = 'appuser';
    $pass = 'userpass123';

    $dsn = "mysql:host=$host;port=$port;dbname=$dbname;charset=utf8mb4";
    try {
        $pdo = new PDO($dsn, $user, $pass, [
            PDO::ATTR_TIMEOUT => 5,
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION
        ]);

        // Verifica se as tabelas existem
        $tables = $pdo->query("SHOW TABLES LIKE 'customers'")->rowCount();
        if ($tables == 0) {
            return ['error' => 'Tabela customers não existe. Execute o script de inicialização em mysql-init/init.sql'];
        }

        return $pdo;
    } catch (PDOException $e) {
        return ['error' => 'MySQL: ' . $e->getMessage()];
    }
}

$sqlite = initSqliteDatabase();
$mysql = initMysqlDatabase();

$action = $_GET['action'] ?? 'info';

// Header para mostrar versão da aplicação
header('X-Vulnerable-App: CVE-Test-Suite-1.0');

switch($action) {
    case 'soap':
        $xml = file_get_contents('php://input');
        $has_xxe = stripos($xml, '<!ENTITY') !== false || stripos($xml, '<!DOCTYPE') !== false;
        
        $response = [
            'vulnerability' => 'CVE-2025-6491 (XXE)',
            'status' => 'XML_PROCESSED',
            'xml_size' => strlen($xml),
            'xxe_detected' => $has_xxe,
            'evidence' => $has_xxe ? 'ENTITY ou DOCTYPE detectado no XML' : 'XML simples aceito',
            'processed_xml' => substr($xml, 0, 500)
        ];
        
        log_attempt('CVE-2025-6491', $xml, $has_xxe);
        echo json_encode($response, JSON_PRETTY_PRINT);
        break;

    case 'redirect':
        $url = $_GET['url'] ?? '';
        if (empty($url)) {
            echo json_encode(['error' => 'Parâmetro url é obrigatório']);
            break;
        }
        
        $is_external = filter_var($url, FILTER_VALIDATE_URL) && 
                      !preg_match('/^(http|https):\/\/(localhost|127\.0\.0\.1)/', $url);
        
        if ($is_external) {
            log_attempt('CVE-2025-1861', $url, true);
            header("Location: $url", true, 302);
            exit;
        } else {
            echo json_encode([
                'vulnerability' => 'CVE-2025-1861 (Open Redirect)',
                'status' => 'REDIRECT_BLOCKED',
                'evidence' => 'Redirecionamento apenas permitido para URLs internas',
                'provided_url' => $url
            ]);
        }
        break;

    case 'custom_request':
        $ua = $_GET['user_agent'] ?? '';
        $crlf_detected = preg_match('/[\r\n]/', $ua);
        $injected_headers = [];
        
        if ($crlf_detected) {
            $lines = preg_split('/\r\n|\r|\n/', $ua);
            foreach ($lines as $line) {
                if (preg_match('/^([^:]+):\s*(.+)$/', $line, $matches)) {
                    $injected_headers[$matches[1]] = $matches[2];
                }
            }
        }
        
        $response = [
            'vulnerability' => 'CVE-2025-1736 (CRLF Injection)',
            'crlf_detected' => $crlf_detected,
            'injected_headers' => $injected_headers,
            'evidence' => $crlf_detected ? 
                'CRLF detectado e headers injetados: ' . json_encode($injected_headers) :
                'Nenhum caractere CRLF detectado',
            'user_agent_received' => $ua
        ];
        
        log_attempt('CVE-2025-1736', $ua, $crlf_detected);
        echo json_encode($response, JSON_PRETTY_PRINT);
        break;

    case 'connect':
        $host = $_GET['hostname'] ?? '';
        $null_byte_detected = strpos($host, "\0") !== false;
        
        // Lista de hosts permitidos
        $allowed = ['trusted.com', 'api.trusted.com'];
        
        // Simular vulnerabilidade real: o null byte faz o parse_url parar de processar
        $parsed_host = parse_url("http://" . $host, PHP_URL_HOST);
        
        // A vulnerabilidade real: sistemas antigos param no null byte
        $parts = explode("\0", $host);
        $host_before_null = $parts[0];
        $parsed_before_null = parse_url("http://" . $host_before_null, PHP_URL_HOST);
        
        $bypass_successful = $null_byte_detected && in_array($parsed_before_null, $allowed);
        
        echo json_encode([
            'vulnerability' => 'CVE-2025-1220 (Null Byte Bypass)',
            'null_byte_detected' => $null_byte_detected,
            'bypass_successful' => $bypass_successful,
            'evidence' => $bypass_successful ? 
                "Bypass bem-sucedido! Sistema validou apenas: $parsed_before_null" :
                ($null_byte_detected ? "Null byte detectado mas validação falhou" : "Null byte não detectado"),
            'original_input' => bin2hex($host),
            'host_before_null' => $host_before_null,
            'parsed_host' => $parsed_host,
            'parsed_before_null' => $parsed_before_null
        ]);
        
        log_attempt('CVE-2025-1220', $host, $bypass_successful);
        break;

    case 'search_user':
        $user = $_GET['username'] ?? '';
        
        if (is_array($sqlite) && isset($sqlite['error'])) {
            echo json_encode(['error' => $sqlite['error']]);
            break;
        }
        
        // SIMULAR VULNERABILIDADE REAL DE TRUNCAMENTO
        // Em versões antigas do SQLite ou em aplicações com limites customizados
        $max_length = 1000; // Limite artificial para simular truncamento
        
        // Se a string for muito longa, simular truncamento
        $original_user = $user;
        if (strlen($user) > $max_length) {
            $user = substr($user, 0, $max_length);
        }
        
        $truncated = (strlen($original_user) > $max_length);
        
        // Vulnerabilidade: usar quote() que pode ter comportamento inconsistente com strings longas
        $quoted = $sqlite->quote($user);
        
        // Verificar se o quote removeu caracteres (simulando comportamento antigo do SQLite)
        $quote_worked_correctly = (strlen($quoted) === strlen($user) + 2); // +2 para as aspas
        
        // Query vulnerável - concatenação direta
        $query = "SELECT * FROM users WHERE username = $quoted";
        $results = [];
        $injection_success = false;
        
        try {
            $stmt = $sqlite->query($query);
            $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            // Injeção bem-sucedida se:
            // 1. Houve truncamento E retornou resultados
            // 2. OU a query retornou mais resultados que o esperado
            $expected_normal_results = ($original_user === 'admin' || $original_user === 'guest' || $original_user === 'test') ? 1 : 0;
            $injection_success = $truncated && count($results) > 0;
            
            // Se não houve truncamento mas ainda assim retornou muitos resultados, é injeção
            if (!$injection_success && count($results) > $expected_normal_results) {
                $injection_success = true;
            }
            
        } catch (Exception $e) {
            $results = ['error' => $e->getMessage()];
        }
        
        $response = [
            'vulnerability' => 'CVE-2022-31631 (SQLite Truncation)',
            'quote_truncated' => $truncated,
            'sql_injection_successful' => $injection_success,
            'evidence' => $injection_success ? 
                "Vulnerabilidade explorada! Query retornou " . count($results) . " registros" :
                ($truncated ? "Truncamento detectado mas injeção não funcionou" : "Sem truncamento detectado"),
            'original_length' => strlen($original_user),
            'truncated_length' => strlen($user),
            'quoted_length' => strlen($quoted),
            'executed_query' => $query,
            'results_count' => count($results),
            'sample_results' => array_slice($results, 0, 2)
        ];
        
        log_attempt('CVE-2022-31631', $original_user, $injection_success);
        echo json_encode($response, JSON_PRETTY_PRINT);
        break;

    case 'parse_header':
        $header = $_GET['header'] ?? '';
        $has_colon = strpos($header, ':') !== false;
        $exploitable = !$has_colon && !empty($header);
        
        $response = [
            'vulnerability' => 'CVE-2025-1734 (Header Parsing)',
            'exploitable' => $exploitable ? 'YES' : 'NO',
            'evidence' => $exploitable ? 
                'Header malformado aceito sem validação' :
                ($has_colon ? 'Header válido com :' : 'Header vazio'),
            'header_received' => $header
        ];
        
        log_attempt('CVE-2025-1734', $header, $exploitable);
        echo json_encode($response, JSON_PRETTY_PRINT);
        break;

    case 'folded_header':
        $val = file_get_contents('php://input');
        $fold_detected = preg_match('/\r\n[ \t]/', $val);
        
        $response = [
            'vulnerability' => 'CVE-2025-1217 (Header Folding)',
            'exploitable' => $fold_detected ? 'YES' : 'NO',
            'evidence' => $fold_detected ? 
                'Header folding detectado e explorado' :
                'Nenhum header folding detectado',
            'input_received' => substr($val, 0, 200)
        ];
        
        log_attempt('CVE-2025-1217', $val, $fold_detected);
        echo json_encode($response, JSON_PRETTY_PRINT);
        break;

    case 'mysql_search':
        if (is_array($mysql) && isset($mysql['error'])) {
            // Tentar criar a tabela se não existir
            try {
                $test_mysql = new PDO('mysql:host=mysql;dbname=appdb', 'appuser', 'userpass123');
                $test_mysql->exec("CREATE TABLE IF NOT EXISTS customers (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(100),
                    email VARCHAR(100)
                )");
                $test_mysql->exec("INSERT IGNORE INTO customers (name, email) VALUES 
                    ('Alice', 'alice@example.com'), 
                    ('Bob', 'bob@example.com')");
                $mysql = $test_mysql;
            } catch (Exception $e) {
                $response = [
                    'error' => 'MySQL connection failed', 
                    'details' => $mysql['error'],
                    'evidence' => 'FALHA NA CONEXÃO MYSQL - Verifique se o banco foi inicializado corretamente'
                ];
                echo json_encode($response, JSON_PRETTY_PRINT);
                break;
            }
        }
        
        $name = $_GET['name'] ?? '';
        
        // VULNERABILIDADE INTENCIONAL: concatenação direta
        $query = "SELECT * FROM customers WHERE name = '$name'";
        $results = [];
        $injection_success = false;
        
        try {
            $stmt = $mysql->query($query);
            $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
            
            // Detectar injeção baseado no comportamento
            $normal_behavior = (strlen($name) > 0 && count($results) <= 1);
            $injection_behavior = (count($results) > 1) || 
                                (strpos($name, "' OR") !== false && count($results) > 0) ||
                                (strpos($name, "' --") !== false && count($results) > 0);
            
            $injection_success = $injection_behavior;
            
        } catch (Exception $e) {
            // Em caso de erro de syntax, pode ser injeção malformada
            if (strpos($e->getMessage(), 'SQLSTATE') !== false) {
                $injection_success = true;
                $results = ['error' => 'SQL Syntax Error - Possible SQL Injection'];
            } else {
                $results = ['error' => $e->getMessage()];
            }
        }
        
        $response = [
            'vulnerability' => 'SQLI_MYSQL_CLASSIC',
            'sql_injection_successful' => $injection_success,
            'evidence' => $injection_success ? 
                "SQL Injection detectada! Retornados " . count($results) . " registros" :
                (count($results) > 0 ? "Consulta normal retornou " . count($results) . " registros" : "Nenhum registro retornado"),
            'executed_query' => $query,
            'results_count' => count($results),
            'sample_data' => array_slice($results, 0, 3)
        ];
        
        log_attempt('SQLI_MYSQL_CLASSIC', $name, $injection_success);
        echo json_encode($response, JSON_PRETTY_PRINT);
        break;

    case 'info':
    default:
        $mysql_status = is_array($mysql) ? 'ERROR: ' . $mysql['error'] : 'CONNECTED';
        $sqlite_status = is_array($sqlite) ? 'ERROR: ' . $sqlite['error'] : 'CONNECTED';
        
        echo json_encode([
            'service' => 'CVE-Test-Suite-v1.0',
            'status' => 'operational',
            'database_status' => [
                'mysql' => $mysql_status,
                'sqlite' => $sqlite_status
            ],
            'endpoints' => [
                'soap' => 'POST /?action=soap (XXE)',
                'redirect' => 'GET /?action=redirect&url=URL (Open Redirect)',
                'custom_request' => 'GET /?action=custom_request&user_agent=UA (CRLF)',
                'connect' => 'GET /?action=connect&hostname=HOST (Null Byte)',
                'search_user' => 'GET /?action=search_user&username=USER (SQLite SQLi)',
                'parse_header' => 'GET /?action=parse_header&header=HEADER (Header Parsing)',
                'folded_header' => 'POST /?action=folded_header (Header Folding)',
                'mysql_search' => 'GET /?action=mysql_search&name=NAME (MySQL SQLi)'
            ],
            'log_file' => '/tmp/exploit_attempts.log'
        ], JSON_PRETTY_PRINT);
}
?>
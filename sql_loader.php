<?php


// ------------------------ CONFIGURATION  ------------------------
$localLicenseKey = '7f9a2b3c4d5e6f7081a2b3c4d5e6f7089a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4
d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7081a2b3c4d5e6f708
a1b2c3d4e5f60718293a4b5c6d7e8f9012a3b4c5d6e7f8091a2b3c4d5e6f70
9f8e7d6c5b4a39281706f5e4d3c2b1a0f9e8d7c6b5a4f3e2d1c0b9a8f7e6d5
0123456789abcdefABCDEF0123456789abcdefABCDEF0123456789abcdefAB
fedcba9876543210FEDCBA9876543210fedcba9876543210FEDCBA9876543210
6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f7081a2b3c4d5e6f7089a0b1c
C1D2E3F405162738495A6B7C8D9E0F1A2B3C4D5E6F708192A3B4C5D6E7F809';   // <-- Dont change (if not empty = valid license)
$adminKey        = 'PUT_A_STRONG_ADMIN_KEY_HERE';      // <-- Choose a admin password so the script cant be started by randoms via webb

$db = (object)[
    'host' => '127.0.0.1',
    'user' => 'dbuser',
    'pass' => 'dbpass',
    'name' => 'dbname',
    'port' => 3306
];

$allow_dangerous = false; -- // Change to true if you want the script to run possible dangerous patterns such as 'SET PASSWORD','SHUTDOWN', or 'drop table' and etc!
$excludedDirs = ['.git','node_modules','quarantine','logs','vendor','storage']; 
$logFile = __DIR__ . '/logs/sync_sql.log'; // loggfil

$licenseUrl = 'https://licensingsystem.xo.je/wille/license/encrypt/key.txt';

function fetch_remote_license($url) {
    // cURL-first
    if (function_exists('curl_init')) {
        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 6);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_MAXREDIRS, 3);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        $res = curl_exec($ch);
        $http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err = curl_error($ch);
        curl_close($ch);
        if ($res !== false && $http >= 200 && $http < 300) return trim($res);
    }
    // fallback file_get_contents
    if (ini_get('allow_url_fopen')) {
        $ctx = stream_context_create(['http'=>['timeout'=>6],'ssl'=>['verify_peer'=>true,'verify_peer_name'=>true]]);
        $res = @file_get_contents($url, false, $ctx);
        if ($res !== false) return trim($res);
    }
    return false;
}

function append_log($msg) {
    global $logFile;
    $line = "[".gmdate('c')."] ".$msg.PHP_EOL;
    @mkdir(dirname($logFile), 0750, true);
    file_put_contents($logFile, $line, FILE_APPEND | LOCK_EX);
}

function is_cli() {
    return php_sapi_name() === 'cli';
}

$remoteKey = fetch_remote_license($licenseUrl);
if ($remoteKey === false) {
    $m = "License verification failed: could not fetch remote license key from {$licenseUrl}";
    append_log($m);
    if (is_cli()) { fwrite(STDERR, $m . PHP_EOL); exit(1); }
    header('HTTP/1.1 403 Forbidden'); echo $m; exit;
}
if (!is_string($localLicenseKey) || $localLicenseKey === '') {
    $m = "Local license key not set in script. Set \$localLicenseKey at top of file.";
    append_log($m);
    if (is_cli()) { fwrite(STDERR, $m . PHP_EOL); exit(1); }
    header('HTTP/1.1 403 Forbidden'); echo $m; exit;
}
if (!hash_equals($remoteKey, $localLicenseKey)) {
    $m = "License verification failed: local license key does not match remote.";
    append_log($m);
    if (is_cli()) { fwrite(STDERR, $m . PHP_EOL); exit(1); }
    header('HTTP/1.1 403 Forbidden'); echo $m; exit;
}
// license ok
append_log("License verified successfully.");

$cli = is_cli();
$dryRun = false;
$providedBase = null;

if ($cli) {
    $argv = $_SERVER['argv'] ?? [];
    $dryRun = in_array('--dry-run', $argv) || in_array('-n', $argv);
    foreach ($argv as $arg) {
        if (strpos($arg, '--base=') === 0) $providedBase = substr($arg, 7);
    }
} else {
    // extra admin key check for web-run
    $providedAdmin = $_GET['key'] ?? $_POST['key'] ?? null;
    if (!$providedAdmin || !hash_equals($adminKey, $providedAdmin)) {
        header('HTTP/1.1 403 Forbidden');
        echo "Forbidden: admin key required to run this script via web.";
        exit;
    }
    $dryRun = isset($_GET['dry']) || isset($_POST['dry']);
    if (!empty($_GET['base'])) $providedBase = $_GET['base'];
}

$scriptDir = realpath(__DIR__);
$baseDir = $scriptDir;
if ($providedBase) {
    $try = $providedBase;
    if (!preg_match('#^(/|[A-Za-z]:\\\\)#', $try)) $try = $scriptDir . DIRECTORY_SEPARATOR . $try;
    $real = realpath($try);
    if ($real && is_dir($real)) $baseDir = $real;
    else {
        $msg = "Provided base not valid or not found: $providedBase";
        append_log($msg);
        if ($cli) { fwrite(STDERR, $msg.PHP_EOL); exit(1); } else { header('Content-Type:text/plain'); echo $msg; exit; }
    }
}

$mysqli = new mysqli($db->host, $db->user, $db->pass, $db->name, $db->port ?? 3306);
if ($mysqli->connect_error) {
    $m = "DB connect error: " . $mysqli->connect_error;
    append_log($m);
    if ($cli) { fwrite(STDERR, $m.PHP_EOL); exit(1);} else { header('Content-Type:text/plain'); echo $m; exit; }
}
$mysqli->set_charset('utf8mb4');

$createMigrations = "
CREATE TABLE IF NOT EXISTS `applied_sql_files` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `relpath` VARCHAR(1024) NOT NULL,
  `filename` VARCHAR(255) NOT NULL,
  `sha256` CHAR(64) NOT NULL,
  `applied_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY(relpath)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
";
if (!$mysqli->query($createMigrations)) {
    $m = "Could not create migrations table: " . $mysqli->error;
    append_log($m);
    die($m);
}

// ---------- collect sql files ----------
function collect_sql_files($dir, $baseDir, $excludedDirs) {
    $files = [];
    $it = @scandir($dir);
    if ($it === false) return $files;
    foreach ($it as $name) {
        if ($name === '.' || $name === '..') continue;
        $full = $dir . DIRECTORY_SEPARATOR . $name;
        if (is_dir($full)) {
            if (in_array($name, $excludedDirs)) continue;
            $files = array_merge($files, collect_sql_files($full, $baseDir, $excludedDirs));
        } else {
            if (preg_match('/\.sql$/i', $name)) {
                $rel = ltrim(str_replace($baseDir, '', $full), DIRECTORY_SEPARATOR);
                $files[] = ['rel'=>$rel, 'full'=>$full, 'name'=>$name];
            }
        }
    }
    return $files;
}

$found = collect_sql_files($baseDir, $baseDir, $excludedDirs);
usort($found, function($a,$b){ return strnatcasecmp($a['rel'],$b['rel']); });

if (!$found) {
    $msg = "No .sql files found under: $baseDir";
    append_log($msg);
    if ($cli) { echo $msg . PHP_EOL; } else { header('Content-Type:text/plain'); echo $msg; }
    exit;
}

$dangerousPatterns = ['DROP DATABASE','DROP TABLE','GRANT','REVOKE','SET PASSWORD','SHUTDOWN','ALTER USER','CREATE USER','DELETE FROM `mysql`','FLUSH PRIVILEGES'];

$results = [];
foreach ($found as $f) {
    $rel = $f['rel'];
    $full = $f['full'];
    $name = $f['name'];
    $content = @file_get_contents($full);
    if ($content === false) {
        $results[] = "ERROR reading: $rel";
        append_log("ERROR reading: $full");
        continue;
    }
    $sha = hash('sha256', $content);

    $stmt = $mysqli->prepare("SELECT sha256 FROM applied_sql_files WHERE relpath = ?");
    $stmt->bind_param('s', $rel);
    $stmt->execute();
    $stmt->store_result();
    if ($stmt->num_rows > 0) {
        $stmt->close();
        $results[] = "SKIP already applied: $rel";
        continue;
    }
    $stmt->close();

    $upper = strtoupper($content);
    $foundDanger = false;
    foreach ($dangerousPatterns as $pat) {
        if (strpos($upper, $pat) !== false) { $foundDanger = true; break; }
    }
    if ($foundDanger && !$allow_dangerous) {
        $results[] = "BLOCKED dangerous statements in: $rel";
        append_log("BLOCKED dangerous in $rel");
        continue;
    }


    if ($dryRun) {
        $results[] = "DRY-RUN would apply: $rel (sha256:$sha) bytes:".strlen($content);
        append_log("DRY-RUN: $rel");
        continue;
    }

    $applied = false;
    if ($mysqli->begin_transaction()) {
        if ($mysqli->multi_query($content)) {
         
            do {
                if ($res = $mysqli->store_result()) { $res->free(); }
            } while ($mysqli->more_results() && $mysqli->next_result());
            if ($mysqli->commit()) {
                // record applied
                $ins = $mysqli->prepare("INSERT INTO applied_sql_files (relpath, filename, sha256) VALUES (?, ?, ?)");
                $ins->bind_param('sss', $rel, $name, $sha);
                if ($ins->execute()) {
                    $applied = true;
                    $ins->close();
                    $results[] = "APPLIED: $rel";
                    append_log("APPLIED: $rel sha:$sha");
                } else {
                    $results[] = "ERROR recording migration for $rel: " . $ins->error;
                    append_log("Applied but record failed for $rel: " . $ins->error);
                    $mysqli->rollback();
                }
            } else {
                $results[] = "ERROR commit failed for $rel: " . $mysqli->error;
                append_log("Commit failed for $rel: " . $mysqli->error);
                $mysqli->rollback();
            }
        } else {
            $results[] = "ERROR executing (multi_query) $rel: " . $mysqli->error;
            append_log("multi_query failed for $rel: " . $mysqli->error);
            $mysqli->rollback();
        }
    } else {
        // no transaction support -> best-effort
        if ($mysqli->multi_query($content)) {
            do {
                if ($res = $mysqli->store_result()) { $res->free(); }
            } while ($mysqli->more_results() && $mysqli->next_result());
            $ins = $mysqli->prepare("INSERT INTO applied_sql_files (relpath, filename, sha256) VALUES (?, ?, ?)");
            $ins->bind_param('sss', $rel, $name, $sha);
            if ($ins->execute()) {
                $applied = true;
                $ins->close();
                $results[] = "APPLIED (no tx): $rel";
                append_log("APPLIED (no tx): $rel sha:$sha");
            } else {
                $results[] = "ERROR recording migration for $rel: " . $ins->error;
                append_log("Executed but record failed for $rel: " . $ins->error);
            }
        } else {
            $results[] = "ERROR executing (no tx) $rel: " . $mysqli->error;
            append_log("multi_query failed (no tx) for $rel: " . $mysqli->error);
        }
    }
}

if ($cli) {
    foreach ($results as $r) echo $r . PHP_EOL;
} else {
    header('Content-Type: text/plain; charset=utf-8');
    foreach ($results as $r) echo $r . PHP_EOL;
}

$mysqli->close();
exit;

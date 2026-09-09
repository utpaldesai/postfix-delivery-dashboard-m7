<?php
/**
 * Mail Size JSON Host Helper
 * Native dashboard backend helper for Postfix message-size management.
 *
 * Security model:
 * - Loopback only (dashboard uses network_mode: host)
 * - Shared API key stored outside web root
 * - Dashboard session/ACL/CSRF remain enforced by FastAPI
 * - Privileged Postfix deployment remains delegated to the restricted
 *   /usr/local/bin/deploy_postfix.sh sudo helper
 */

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');

$remote = $_SERVER['REMOTE_ADDR'] ?? '';
if (!in_array($remote, ['127.0.0.1', '::1'], true)) {
    http_response_code(403);
    echo json_encode(['ok' => false, 'error' => 'Loopback access required']);
    exit();
}

$keyFile = '/etc/postfix-web/mail-size-api.key';
$expectedKey = is_file($keyFile) ? trim((string)file_get_contents($keyFile)) : '';
$providedKey = trim((string)($_SERVER['HTTP_X_MAIL_SIZE_KEY'] ?? ''));

if ($expectedKey === '' || $providedKey === '' || !hash_equals($expectedKey, $providedKey)) {
    http_response_code(403);
    echo json_encode(['ok' => false, 'error' => 'Invalid API key']);
    exit();
}

// Audit identity is supplied by the authenticated dashboard backend.
// Trust these headers only because this helper has already enforced loopback-only access
// and the shared API key above.
$dashboardClientIp = trim((string)($_SERVER['HTTP_X_DASHBOARD_CLIENT_IP'] ?? ''));
$dashboardUsername = trim((string)($_SERVER['HTTP_X_DASHBOARD_USERNAME'] ?? ''));
if ($dashboardClientIp === '' || strlen($dashboardClientIp) > 64 || !preg_match('/^[0-9A-Fa-f:.]+$/', $dashboardClientIp)) {
    $dashboardClientIp = $remote;
}
if ($dashboardUsername === '' || strlen($dashboardUsername) > 128 || !preg_match('/^[A-Za-z0-9_.@-]+$/', $dashboardUsername)) {
    $dashboardUsername = 'unknown';
}

$liveFile = '/etc/postfix/master.cf';
$stagingFile = '/tmp/master.cf.new';
$backupDir = '/var/lib/postfix-web/backups/';
$auditLog = '/var/lib/postfix-web/audit.log';
$cooldownFile = '/tmp/postfix_admin_cooldown';
$filter = '-o message_size_limit';
$hiddenLines = [62, 86];

$profiles = [
    'outlook' => [
        'label' => 'Outlook / Submission',
        'pattern' => '/192\.168\.20\.252:submission\s+inet/',
    ],
    'webmail' => [
        'label' => 'Webmail / SMTPS',
        'pattern' => '/192\.168\.20\.252:465\s+inet/',
    ],
];

function json_fail($status, $message) {
    http_response_code($status);
    echo json_encode(['ok' => false, 'error' => $message], JSON_UNESCAPED_SLASHES);
    exit();
}

function json_ok($payload = []) {
    echo json_encode(array_merge(['ok' => true], $payload), JSON_UNESCAPED_SLASHES);
    exit();
}

function service_status($displayName, $processName) {
    $execName = ($displayName === 'Postfix') ? 'master' : $processName;
    $pids = [];
    exec('pgrep -f ' . escapeshellarg($execName), $pids);
    return [
        'name' => $displayName,
        'status' => !empty($pids) ? 'WORKING' : 'STOPPED',
    ];
}

function cooldown_remaining($cooldownFile) {
    $lastUpdate = is_file($cooldownFile) ? (int)file_get_contents($cooldownFile) : 0;
    return max(0, 30 - (time() - $lastUpdate));
}

function profile_state($lines, $pattern, $filter, $hiddenLines) {
    $parentIndex = null;

    foreach ($lines as $index => $line) {
        if ($parentIndex === null && preg_match($pattern, $line)) {
            $parentIndex = $index;
            continue;
        }

        if ($parentIndex !== null && $index > $parentIndex) {
            if (preg_match('/^[^\s#]+/', $line) && $index > ($parentIndex + 1)) {
                break;
            }

            if (strpos($line, $filter) !== false && !in_array($index + 1, $hiddenLines, true)) {
                $parts = explode('=', $line, 2);
                $bytes = (float)trim($parts[1] ?? 0);
                return [
                    'custom' => true,
                    'mb' => (int)round($bytes / 1048576),
                    'line' => $index + 1,
                ];
            }
        }
    }

    return [
        'custom' => false,
        'mb' => 25,
        'line' => null,
    ];
}

function collect_status($liveFile, $backupDir, $auditLog, $cooldownFile, $filter, $hiddenLines, $profiles) {
    if (!is_readable($liveFile)) {
        json_fail(500, 'Unable to read Postfix master.cf');
    }

    $lines = file($liveFile);
    if ($lines === false) {
        json_fail(500, 'Unable to read Postfix master.cf');
    }

    $servicesToTrack = [
        ['display' => 'Postfix',   'name' => 'postfix'],
        ['display' => 'Dovecot',   'name' => 'dovecot'],
        ['display' => 'Amavis',    'name' => 'amavisd'],
        ['display' => 'OpenDKIM',  'name' => 'opendkim'],
        ['display' => 'OpenDMARC', 'name' => 'opendmarc'],
        ['display' => 'Apache',    'name' => 'apache2'],
        ['display' => 'MariaDB',   'name' => 'mariadbd'],
    ];

    $services = [];
    foreach ($servicesToTrack as $service) {
        $services[] = service_status($service['display'], $service['name']);
    }

    $profileData = [];
    foreach ($profiles as $key => $profile) {
        $profileData[$key] = profile_state(
            $lines,
            $profile['pattern'],
            $filter,
            $hiddenLines
        );
    }

    $backups = glob($backupDir . '*.bak');
    if ($backups) {
        rsort($backups);
    } else {
        $backups = [];
    }

    $backupRows = [];
    foreach (array_slice($backups, 0, 4) as $backup) {
        $file = basename($backup);
        $display = date('M j, H:i', filemtime($backup));
        if (preg_match('/(\d{8})_(\d{6})/', $file, $match)) {
            $parsed = strtotime($match[1] . ' ' . $match[2]);
            if ($parsed !== false) {
                $display = date('M j, H:i', $parsed);
            }
        }
        $backupRows[] = [
            'file' => $file,
            'display_time' => $display,
        ];
    }

    $audit = [];
    if (is_file($auditLog)) {
        $entries = file($auditLog, FILE_IGNORE_NEW_LINES);
        if ($entries !== false) {
            $audit = array_reverse(array_slice($entries, -10));
        }
    }

    return [
        'services' => $services,
        'profiles' => $profileData,
        'cooldown_remaining' => cooldown_remaining($cooldownFile),
        'backups' => $backupRows,
        'audit' => $audit,
    ];
}

function append_audit($auditLog, $message, $clientIp, $username) {
    $line = '[' . date('Y-m-d H:i:s') . '] [USER:' . $username . '] [IP:' . $clientIp . '] ' . $message . PHP_EOL;
    file_put_contents($auditLog, $line, FILE_APPEND | LOCK_EX);
}

if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    json_ok(collect_status(
        $liveFile,
        $backupDir,
        $auditLog,
        $cooldownFile,
        $filter,
        $hiddenLines,
        $profiles
    ));
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_fail(405, 'Method not allowed');
}

$raw = file_get_contents('php://input');
$payload = json_decode((string)$raw, true);
if (!is_array($payload)) {
    json_fail(400, 'Invalid JSON request');
}

$action = strtolower(trim((string)($payload['action'] ?? '')));

if ($action === 'save') {
    $remaining = cooldown_remaining($cooldownFile);
    if ($remaining > 0) {
        json_fail(409, 'Cooldown active for ' . $remaining . ' seconds');
    }

    $profileKey = strtolower(trim((string)($payload['profile'] ?? '')));
    if (!isset($profiles[$profileKey])) {
        json_fail(400, 'Invalid Mail Size profile');
    }

    $mb = filter_var($payload['mb'] ?? null, FILTER_VALIDATE_INT);
    if ($mb === false || $mb < 1 || $mb > 99) {
        json_fail(400, 'Mail Size must be between 1 and 99 MB');
    }

    $lines = file($liveFile);
    if ($lines === false) {
        json_fail(500, 'Unable to read Postfix master.cf');
    }

    $parentIndex = null;
    $foundIndex = null;
    $pattern = $profiles[$profileKey]['pattern'];

    foreach ($lines as $index => $line) {
        if ($parentIndex === null && preg_match($pattern, $line)) {
            $parentIndex = $index;
            continue;
        }

        if ($parentIndex !== null && $index > $parentIndex) {
            if (preg_match('/^[^\s#]+/', $line) && $index > ($parentIndex + 1)) {
                break;
            }

            if (strpos($line, $filter) !== false && !in_array($index + 1, $hiddenLines, true)) {
                $foundIndex = $index;
                break;
            }
        }
    }

    $byteValue = $mb * 1048576;
    if ($foundIndex !== null) {
        $parts = explode('=', $lines[$foundIndex], 2);
        $lines[$foundIndex] = $parts[0] . '=' . $byteValue . "\n";
    } elseif ($parentIndex !== null) {
        $newLine = "    -o message_size_limit=" . $byteValue . "\n";
        array_splice($lines, $parentIndex + 1, 0, $newLine);
        $foundIndex = $parentIndex + 1;
    } else {
        json_fail(409, 'Could not locate the Postfix profile in master.cf');
    }

    if (file_put_contents($stagingFile, implode('', $lines), LOCK_EX) === false) {
        json_fail(500, 'Unable to create staged Postfix configuration');
    }

    $output = [];
    $retval = 0;
    exec('sudo /usr/local/bin/deploy_postfix.sh', $output, $retval);

    if ($retval !== 0) {
        json_fail(500, 'Postfix deployment helper failed');
    }

    file_put_contents($cooldownFile, (string)time(), LOCK_EX);
    append_audit(
        $auditLog,
        'SET ' . strtoupper($profileKey) . ' L' . ($foundIndex + 1) . ' TO ' . $mb . ' MB',
        $dashboardClientIp,
        $dashboardUsername
    );

    json_ok([
        'message' => 'Applied ' . $mb . ' MB limit to ' . $profiles[$profileKey]['label'],
        'cooldown_remaining' => 30,
    ]);
}

if ($action === 'revert') {
    $filename = basename(trim((string)($payload['backup_file'] ?? '')));
    if ($filename === '') {
        json_fail(400, 'Backup file is required');
    }

    $restoreFile = $backupDir . $filename;
    $realBackupDir = realpath($backupDir);
    $realRestoreFile = realpath($restoreFile);

    if (
        !$realRestoreFile
        || !$realBackupDir
        || strpos($realRestoreFile, $realBackupDir . DIRECTORY_SEPARATOR) !== 0
        || !is_file($realRestoreFile)
    ) {
        json_fail(400, 'Invalid backup file');
    }

    $output = [];
    $retval = 0;
    exec(
        'sudo /usr/local/bin/deploy_postfix.sh restore ' . escapeshellarg($realRestoreFile),
        $output,
        $retval
    );

    if ($retval !== 0) {
        json_fail(500, 'Postfix restore helper failed');
    }

    append_audit($auditLog, 'RESTORE ' . $filename, $dashboardClientIp, $dashboardUsername);

    json_ok([
        'message' => 'Restored backup ' . $filename,
    ]);
}

json_fail(400, 'Invalid action');

<?php
declare(strict_types=1);

/**
 * /api/lead.php — обробник заявок з лендингу crm.papirinvest.com.ua
 *
 * - Honeypot захист (поле "website")
 * - Rate-limit: 3 заявки/година з одного IP
 * - INSERT у `leads`
 * - Telegram-нотифай в @prostircrm-чи-який-там бот (Papir bot reused)
 * - JSON-відповідь
 *
 * Конфіг: /var/www/prostir-crm-landing/.env (DB_*, TELEGRAM_BOT_TOKEN, TELEGRAM_LEAD_CHAT_ID)
 */

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

function reply(int $code, array $data): void {
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    reply(405, ['success' => false, 'error' => 'method_not_allowed']);
}

// .env у /var/www/prostir-crm-landing/.env (parent of public/api/)
$envPath = dirname(__DIR__, 2) . '/.env';
$env = is_readable($envPath) ? (parse_ini_file($envPath) ?: []) : [];

// Honeypot — мовчки відкидаємо ботів (повертаємо ok=true щоб не сигналізувати)
if (!empty($_POST['website'])) {
    reply(200, ['success' => true, 'lead_id' => 0]);
}

// User-Agent guard
$ua = (string)($_SERVER['HTTP_USER_AGENT'] ?? '');
if ($ua === '' || strlen($ua) < 10) {
    reply(400, ['success' => false, 'error' => 'bad_user_agent']);
}

// Validate fields
$name    = trim((string)($_POST['name'] ?? ''));
$contact = trim((string)($_POST['contact'] ?? ''));
$email   = trim((string)($_POST['email'] ?? ''));
$message = trim((string)($_POST['message'] ?? ''));
$source  = trim((string)($_POST['source'] ?? 'landing'));

if ($name === '' || $contact === '' || $email === '') {
    reply(400, ['success' => false, 'error' => 'missing_fields']);
}
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    reply(400, ['success' => false, 'error' => 'bad_email']);
}
if (mb_strlen($name) > 200 || mb_strlen($contact) > 200 || mb_strlen($email) > 200) {
    reply(400, ['success' => false, 'error' => 'field_too_long']);
}
if (mb_strlen($message) > 2000) {
    $message = mb_substr($message, 0, 2000);
}
if (mb_strlen($source) > 64) {
    $source = mb_substr($source, 0, 64);
}

$ip = (string)($_SERVER['REMOTE_ADDR'] ?? '');

// DB
try {
    $pdo = new PDO(
        'mysql:host=' . ($env['DB_HOST'] ?? 'localhost')
            . ';dbname=' . ($env['DB_NAME'] ?? '')
            . ';charset=utf8mb4',
        (string)($env['DB_USER'] ?? ''),
        (string)($env['DB_PASS'] ?? ''),
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]
    );
} catch (Throwable $e) {
    error_log('lead.php DB connect: ' . $e->getMessage());
    reply(500, ['success' => false, 'error' => 'db_unavailable']);
}

// Rate limit: 3/hour per IP
try {
    $stmt = $pdo->prepare('SELECT COUNT(*) FROM leads WHERE ip = ? AND created_at > NOW() - INTERVAL 1 HOUR');
    $stmt->execute([$ip]);
    if ((int)$stmt->fetchColumn() >= 3) {
        reply(429, ['success' => false, 'error' => 'rate_limited']);
    }
} catch (Throwable $e) {
    error_log('lead.php rate-limit query: ' . $e->getMessage());
    // не блокуємо, просто продовжуємо — DB lock на rate-limit не повинен ламати потік
}

// Insert
try {
    $stmt = $pdo->prepare(
        'INSERT INTO leads (name, contact, email, message, source, ip, user_agent)
         VALUES (?, ?, ?, ?, ?, ?, ?)'
    );
    $stmt->execute([$name, $contact, $email, $message, $source, $ip, $ua]);
    $leadId = (int)$pdo->lastInsertId();
} catch (Throwable $e) {
    error_log('lead.php INSERT: ' . $e->getMessage());
    reply(500, ['success' => false, 'error' => 'db_write_failed']);
}

// Telegram notify (best-effort; не валимо запит якщо TG не вiдповiв)
$tgToken = (string)($env['TELEGRAM_BOT_TOKEN'] ?? '');
$tgChat  = (string)($env['TELEGRAM_LEAD_CHAT_ID'] ?? '');
if ($tgToken !== '' && $tgChat !== '') {
    $esc = static fn(string $s): string => htmlspecialchars($s, ENT_QUOTES | ENT_HTML5, 'UTF-8');

    $lines = [
        '🔔 <b>Нова заявка з лендинга</b> #' . $leadId,
        '',
        '<b>Імʼя:</b> ' . $esc($name),
        '<b>Контакт:</b> ' . $esc($contact),
        '<b>Email:</b> ' . $esc($email),
    ];
    if ($message !== '') {
        $lines[] = '';
        $lines[] = '<b>Про бізнес:</b>';
        $lines[] = $esc($message);
    }
    $lines[] = '';
    $lines[] = '<i>Джерело: ' . $esc($source) . ' · IP: ' . $esc($ip) . '</i>';
    $tgText = implode("\n", $lines);

    $payload = json_encode([
        'chat_id'                  => $tgChat,
        'text'                     => $tgText,
        'parse_mode'               => 'HTML',
        'disable_web_page_preview' => true,
    ], JSON_UNESCAPED_UNICODE);

    $ch = curl_init('https://api.telegram.org/bot' . $tgToken . '/sendMessage');
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => $payload,
        CURLOPT_HTTPHEADER     => ['Content-Type: application/json'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 5,
    ]);
    $resp = curl_exec($ch);
    if ($resp === false) {
        error_log('lead.php TG notify failed: ' . curl_error($ch));
    }
    curl_close($ch);
}

reply(200, ['success' => true, 'lead_id' => $leadId]);

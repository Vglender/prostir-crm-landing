<?php
declare(strict_types=1);

/**
 * /api/lead.php — обробник заявок з лендингу prostircrm.com
 *
 * - Honeypot захист (поле "website")
 * - Spam-detection (SEO-scam, video-pitch, foreign cold-pitch)
 * - Rate-limit: 3 заявки/година з одного IP
 * - INSERT у `leads`
 * - Telegram-нотифай в Papir bot
 * - JSON-відповідь
 *
 * Конфіг: /var/www/prostir-crm-landing/.env
 */

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

function reply(int $code, array $data): void {
    http_response_code($code);
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

/**
 * Spam-detection. Повертає reason-код або null якщо чисто.
 * Перевіряємо ДО rate-limit і ДО TG-нотифая щоб не палити бюджет/чат.
 */
function detect_spam(string $name, string $contact, string $email, string $message): ?string {
    $blob = $name . ' ' . $email . ' ' . $message;

    // SEO-index scam (searchregister.live/org, GoogleSearchIndex)
    if (preg_match('~google\s*search\s*index|searchregister\.|\bsearch\s+register\b|web\s+search\s+results~i', $blob)) {
        return 'seo_scam';
    }

    // Video service cold-pitch ("engaging video", "video samples", "prices start from $N")
    if (preg_match('~\b(engaging|explainer|promotional|animated|corporate|product)\s+video|video\s+(samples?|prices?|production|service)|prices?\s+start\s+from~i', $blob)) {
        return 'video_pitch';
    }

    // Generic USD-pitch ("$195 USD", "price $500")
    if (preg_match('~\$\s*\d{2,5}\s*\(?\s*USD~i', $blob)) {
        return 'usd_pitch';
    }

    // Spam email patterns
    if (preg_match('~^domains@search-|^[a-z]+video\d+@|videos?\d+@gmail~i', $email)) {
        return 'spam_email';
    }

    // No Cyrillic anywhere AND contact is not a UA phone (380… or 0XXXXXXXXX)
    $textBlob = $name . ' ' . $message;
    $digits = preg_replace('/\D/', '', $contact);
    $isUaPhone = (strlen($digits) === 12 && substr($digits, 0, 3) === '380')
              || (strlen($digits) === 10 && $digits[0] === '0');
    if ($textBlob !== '' && !preg_match('~[\p{Cyrillic}]~u', $textBlob) && !$isUaPhone) {
        return 'foreign_non_ua';
    }

    // Bulgarian/Macedonian/Serbian cyrillic cold-pitch (RobertTam-style botnet).
    // "Здравейте", "исках", "знам", "цената" — common fillers; UA/RU would say
    // "ціну"/"цену". Also catches generic "искам да знам" phrasings.
    if (preg_match('~\b(здравейте|исках|искам|знам|цената|получих|бихте|бих\s+искал|изпратете|може\s+ли)\b~iu', $blob)) {
        return 'bg_bot';
    }

    // gmail with random-suffix pattern used by sign-up botnets:
    // first-name-ish letters + 3-7 random alphanum (gregoryj8tl2g, michaelk4b1n6, ...).
    if (preg_match('~^[a-z]{3,10}[a-z]?\d{1,3}[a-z]{1,3}\d{0,2}[a-z]*@gmail\.com$~i', $email)) {
        return 'gmail_random_suffix';
    }

    // Name == single CamelCase word 6-15 chars without space (RobertTam, LindaWilliams).
    // Real submissions almost always have first + last name separated.
    if (preg_match('~^[A-Z][a-z]+[A-Z][a-z]+$~', $name)) {
        return 'camelcase_name';
    }

    return null;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') {
    reply(405, ['success' => false, 'error' => 'method_not_allowed']);
}

$envPath = dirname(__DIR__, 2) . '/.env';
$env = is_readable($envPath) ? (parse_ini_file($envPath) ?: []) : [];

// Honeypot — мовчки відкидаємо ботів
if (!empty($_POST['website'])) {
    reply(200, ['success' => true, 'lead_id' => 0]);
}

// User-Agent guard
$ua = (string)($_SERVER['HTTP_USER_AGENT'] ?? '');
if ($ua === '' || strlen($ua) < 10) {
    reply(400, ['success' => false, 'error' => 'bad_user_agent']);
}

// Real client IP — behind Cloudflare REMOTE_ADDR is a CF edge, CF-Connecting-IP is
// the visitor. Used for rate-limit, storage and Turnstile remoteip.
$ip = (string)($_SERVER['HTTP_CF_CONNECTING_IP'] ?? $_SERVER['REMOTE_ADDR'] ?? '');

// Cloudflare Turnstile — enforced only when TURNSTILE_SECRET is set in .env
// (graceful rollout: deploying the code without a key keeps the form working).
$tsSecret = (string)($env['TURNSTILE_SECRET'] ?? '');
if ($tsSecret !== '') {
    $tsToken = (string)($_POST['cf-turnstile-response'] ?? '');
    if ($tsToken === '') {
        reply(400, ['success' => false, 'error' => 'captcha_required']);
    }
    $tsOk = false;
    $ch = curl_init('https://challenges.cloudflare.com/turnstile/v0/siteverify');
    curl_setopt_array($ch, [
        CURLOPT_POST           => true,
        CURLOPT_POSTFIELDS     => http_build_query([
            'secret'   => $tsSecret,
            'response' => $tsToken,
            'remoteip' => $ip,
        ]),
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT        => 6,
    ]);
    $tsResp = curl_exec($ch);
    if ($tsResp === false) {
        error_log('lead.php turnstile curl: ' . curl_error($ch));
    }
    curl_close($ch);
    if ($tsResp !== false) {
        $tsData = json_decode((string)$tsResp, true);
        $tsOk = is_array($tsData) && !empty($tsData['success']);
    }
    if (!$tsOk) {
        reply(403, ['success' => false, 'error' => 'captcha_failed']);
    }
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

// Spam-detection — silent success (бот думає що пройшло), запис у БД з is_spam=1, без TG
$spamReason = detect_spam($name, $contact, $email, $message);
if ($spamReason !== null) {
    try {
        $stmt = $pdo->prepare(
            'INSERT INTO leads (name, contact, email, message, source, ip, user_agent, is_spam, spam_reason)
             VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)'
        );
        $stmt->execute([$name, $contact, $email, $message, $source, $ip, $ua, $spamReason]);
    } catch (Throwable $e) {
        error_log('lead.php SPAM insert: ' . $e->getMessage());
    }
    reply(200, ['success' => true, 'lead_id' => 0]);
}

// Rate limit: 3/hour per IP (вважаємо тільки чисті заявки)
try {
    $stmt = $pdo->prepare('SELECT COUNT(*) FROM leads WHERE ip = ? AND is_spam = 0 AND created_at > NOW() - INTERVAL 1 HOUR');
    $stmt->execute([$ip]);
    if ((int)$stmt->fetchColumn() >= 3) {
        reply(429, ['success' => false, 'error' => 'rate_limited']);
    }
} catch (Throwable $e) {
    error_log('lead.php rate-limit query: ' . $e->getMessage());
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

// Telegram notify (best-effort)
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

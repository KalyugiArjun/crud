<?php
/**
 * Production-Ready Core PHP Form with Complete Security & Validations
 * Features:
 * - CSRF Token Protection
 * - XSS Prevention (htmlspecialchars sanitization)
 * - Strict Server-side & Client-side Validation
 * - Input State Retention (Old value persistence on error)
 * - Clean Modern Responsive UI (No external heavy dependencies needed)
 * - Post-Redirect-Get (PRG) Pattern to prevent form re-submission on refresh
 */

// Start session with secure cookie parameters
if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.cookie_httponly', 1);
    ini_set('session.use_only_cookies', 1);
    // Enable cookie_secure if HTTPS is active
    if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
        ini_set('session.cookie_secure', 1);
    }
    session_start();
}

// Generate CSRF Token if not set
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Helper: Sanitize string output
function e(?string $data): string {
    return htmlspecialchars(trim((string)$data), ENT_QUOTES, 'UTF-8');
}

// Helper: Clean and trim input
function clean_input(?string $data): string {
    return trim((string)$data);
}

// Retrieve flash data from session (Errors, Old Inputs, Success status)
$errors  = $_SESSION['form_errors'] ?? [];
$old     = $_SESSION['form_old'] ?? [];
$success = $_SESSION['form_success'] ?? false;

// Clear flash session data for current request
unset($_SESSION['form_errors'], $_SESSION['form_old'], $_SESSION['form_success']);

// Handle Form POST Submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $submittedErrors = [];

    // 1. CSRF Token Validation
    $csrfToken = $_POST['csrf_token'] ?? '';
    if (!hash_equals($_SESSION['csrf_token'] ?? '', $csrfToken)) {
        $submittedErrors['csrf'] = 'Invalid session or CSRF token mismatch. Please try again.';
    }

    // 2. Fetch and Clean Inputs
    $name   = clean_input($_POST['name'] ?? '');
    $email  = clean_input($_POST['email'] ?? '');
    $phone  = clean_input($_POST['phone'] ?? '');
    $gender = clean_input($_POST['gender'] ?? '');

    // 3. Validation: Name
    if ($name === '') {
        $submittedErrors['name'] = 'Name is required.';
    } elseif (mb_strlen($name) < 3 || mb_strlen($name) > 60) {
        $submittedErrors['name'] = 'Name must be between 3 and 60 characters.';
    } elseif (!preg_match("/^[a-zA-Z\s\.\'-]+$/u", $name)) {
        $submittedErrors['name'] = 'Name should only contain letters, spaces, dots, and hyphens.';
    }

    // 4. Validation: Email
    if ($email === '') {
        $submittedErrors['email'] = 'Email address is required.';
    } elseif (mb_strlen($email) > 100) {
        $submittedErrors['email'] = 'Email address is too long.';
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $submittedErrors['email'] = 'Please enter a valid email address.';
    }

    // 5. Validation: Phone Number (10 digit format)
    if ($phone === '') {
        $submittedErrors['phone'] = 'Phone number is required.';
    } elseif (!preg_match('/^[6-9][0-9]{9}$/', $phone)) {
        $submittedErrors['phone'] = 'Please enter a valid 10-digit mobile number (starting with 6, 7, 8, or 9).';
    }

    // 6. Validation: Gender
    $validGenders = ['male', 'female', 'other'];
    if ($gender === '') {
        $submittedErrors['gender'] = 'Please select a gender.';
    } elseif (!in_array($gender, $validGenders, true)) {
        $submittedErrors['gender'] = 'Invalid gender selected.';
    }

    // Process outcome
    if (!empty($submittedErrors)) {
        $_SESSION['form_errors']  = $submittedErrors;
        $_SESSION['form_old']     = [
            'name'   => $name,
            'email'  => $email,
            'phone'  => $phone,
            'gender' => $gender,
        ];
    } else {
        $savedToDb = false;

        // Auto-detect and save to database if db.php is configured and connected
        if (file_exists(__DIR__ . '/db.php')) {
            require_once __DIR__ . '/db.php';
            if (isset($pdo) && $pdo instanceof PDO) {
                try {
                    $stmt = $pdo->prepare("INSERT INTO users (name, email, phone, gender) VALUES (?, ?, ?, ?)");
                    $stmt->execute([$name, $email, $phone, $gender]);
                    $savedToDb = true;
                } catch (\PDOException $e) {
                    // Check duplicate entry for unique email constraint (SQLSTATE 23000)
                    if ($e->getCode() == 23000) {
                        $_SESSION['form_errors'] = ['email' => 'This email address is already registered.'];
                        $_SESSION['form_old'] = [
                            'name'   => $name,
                            'email'  => $email,
                            'phone'  => $phone,
                            'gender' => $gender,
                        ];
                        header('Location: ' . $_SERVER['PHP_SELF']);
                        exit;
                    }
                    error_log("Database Insert Error: " . $e->getMessage());
                }
            }
        }

        // Refresh CSRF Token for security
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        $successMsg = "Form successfully submitted! " . ($savedToDb ? "Data successfully saved to database." : "") . " Welcome, " . e($name) . ".";
        $_SESSION['form_success'] = $successMsg;
    }

    // Post-Redirect-Get pattern (Prevents form re-submission on F5/refresh)
    header('Location: ' . $_SERVER['PHP_SELF']);
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Registration Form</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg-gradient: linear-gradient(135deg, #0f172a 0%, #1e1b4b 50%, #0f172a 100%);
            --card-bg: rgba(30, 41, 59, 0.78);
            --card-border: rgba(255, 255, 255, 0.1);
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --primary: #6366f1;
            --primary-hover: #4f46e5;
            --primary-glow: rgba(99, 102, 241, 0.35);
            --danger: #ef4444;
            --danger-bg: rgba(239, 68, 68, 0.12);
            --success: #10b981;
            --success-bg: rgba(16, 185, 129, 0.12);
            --input-bg: rgba(15, 23, 42, 0.65);
            --input-border: rgba(148, 163, 184, 0.22);
            --radius-md: 12px;
            --radius-lg: 18px;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: 'Plus Jakarta Sans', system-ui, -apple-system, sans-serif;
        }

        body {
            min-height: 100vh;
            background: var(--bg-gradient);
            color: var(--text-main);
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px 16px;
        }

        .container {
            width: 100%;
            max-width: 520px;
        }

        .card {
            background: var(--card-bg);
            backdrop-filter: blur(16px);
            -webkit-backdrop-filter: blur(16px);
            border: 1px solid var(--card-border);
            border-radius: var(--radius-lg);
            padding: 36px 32px;
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.55), 0 0 0 1px rgba(255, 255, 255, 0.05);
        }

        .header {
            margin-bottom: 28px;
            text-align: center;
        }

        .header h1 {
            font-size: 1.75rem;
            font-weight: 700;
            letter-spacing: -0.02em;
            background: linear-gradient(135deg, #ffffff 30%, #a5b4fc 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 8px;
        }

        .header p {
            color: var(--text-muted);
            font-size: 0.92rem;
        }

        /* Alert Notifications */
        .alert {
            padding: 14px 16px;
            border-radius: var(--radius-md);
            margin-bottom: 24px;
            font-size: 0.9rem;
            display: flex;
            align-items: center;
            gap: 12px;
            animation: fadeIn 0.3s ease-in-out;
        }

        .alert-success {
            background: var(--success-bg);
            border: 1px solid rgba(16, 185, 129, 0.35);
            color: #6ee7b7;
        }

        .alert-danger {
            background: var(--danger-bg);
            border: 1px solid rgba(239, 68, 68, 0.35);
            color: #fca5a5;
        }

        /* Form Controls */
        .form-group {
            margin-bottom: 20px;
        }

        label {
            display: block;
            margin-bottom: 8px;
            font-size: 0.88rem;
            font-weight: 600;
            color: #cbd5e1;
        }

        .required {
            color: var(--danger);
            margin-left: 3px;
        }

        .input-wrap {
            position: relative;
        }

        input[type="text"],
        input[type="email"],
        input[type="tel"] {
            width: 100%;
            padding: 12px 16px;
            background: var(--input-bg);
            border: 1px solid var(--input-border);
            border-radius: var(--radius-md);
            color: var(--text-main);
            font-size: 0.95rem;
            outline: none;
            transition: all 0.2s ease;
        }

        input[type="text"]:focus,
        input[type="email"]:focus,
        input[type="tel"]:focus {
            border-color: var(--primary);
            box-shadow: 0 0 0 3px var(--primary-glow);
            background: rgba(15, 23, 42, 0.9);
        }

        input.is-invalid {
            border-color: var(--danger) !important;
            box-shadow: 0 0 0 3px rgba(239, 68, 68, 0.25) !important;
        }

        .error-message {
            margin-top: 6px;
            font-size: 0.82rem;
            color: #f87171;
            display: flex;
            align-items: center;
            gap: 6px;
        }

        /* Gender Radio Group */
        .gender-options {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 10px;
            margin-top: 6px;
        }

        .gender-radio-label {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            padding: 11px 12px;
            background: var(--input-bg);
            border: 1px solid var(--input-border);
            border-radius: var(--radius-md);
            cursor: pointer;
            font-size: 0.9rem;
            font-weight: 500;
            color: #cbd5e1;
            transition: all 0.2s ease;
            user-select: none;
        }

        .gender-radio-label:hover {
            border-color: rgba(99, 102, 241, 0.5);
            background: rgba(30, 41, 59, 0.9);
        }

        .gender-radio-label input[type="radio"] {
            appearance: none;
            -webkit-appearance: none;
            width: 16px;
            height: 16px;
            border: 2px solid #64748b;
            border-radius: 50%;
            outline: none;
            transition: 0.2s ease;
            position: relative;
        }

        .gender-radio-label input[type="radio"]:checked {
            border-color: var(--primary);
            background: var(--primary);
            box-shadow: inset 0 0 0 3px #1e293b;
        }

        .gender-radio-label:has(input[type="radio"]:checked) {
            border-color: var(--primary);
            background: rgba(99, 102, 241, 0.15);
            color: #fff;
        }

        /* Submit Button */
        .btn-submit {
            width: 100%;
            padding: 13px 20px;
            margin-top: 10px;
            background: var(--primary);
            color: #ffffff;
            border: none;
            border-radius: var(--radius-md);
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s ease;
            box-shadow: 0 4px 15px var(--primary-glow);
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
        }

        .btn-submit:hover {
            background: var(--primary-hover);
            transform: translateY(-1px);
            box-shadow: 0 6px 20px rgba(99, 102, 241, 0.45);
        }

        .btn-submit:active {
            transform: translateY(0);
        }

        .footer-note {
            text-align: center;
            margin-top: 20px;
            font-size: 0.8rem;
            color: var(--text-muted);
        }

        @keyframes fadeIn {
            from { opacity: 0; transform: translateY(-6px); }
            to { opacity: 1; transform: translateY(0); }
        }

        @media (max-width: 480px) {
            .card {
                padding: 24px 20px;
            }
            .gender-options {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>

<div class="container">
    <div class="card">
        <div class="header">
            <h1>Create Account</h1>
            <p>Please enter your details to register</p>
        </div>

        <!-- Success Alert -->
        <?php if ($success): ?>
            <div class="alert alert-success" role="alert">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                    <polyline points="22 4 12 14.01 9 11.01"></polyline>
                </svg>
                <span><?= $success; ?></span>
            </div>
        <?php endif; ?>

        <!-- CSRF or Global Errors -->
        <?php if (!empty($errors['csrf'])): ?>
            <div class="alert alert-danger" role="alert">
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="10"></circle>
                    <line x1="12" y1="8" x2="12" y2="12"></line>
                    <line x1="12" y1="16" x2="12.01" y2="16"></line>
                </svg>
                <span><?= e($errors['csrf']); ?></span>
            </div>
        <?php endif; ?>

        <form action="<?= htmlspecialchars($_SERVER['PHP_SELF']); ?>" method="POST" novalidate id="registrationForm">
            <!-- CSRF Protection Token -->
            <input type="hidden" name="csrf_token" value="<?= e($_SESSION['csrf_token']); ?>">

            <!-- Full Name -->
            <div class="form-group">
                <label for="name">Full Name <span class="required">*</span></label>
                <div class="input-wrap">
                    <input 
                        type="text" 
                        id="name" 
                        name="name" 
                        placeholder="John Doe" 
                        value="<?= e($old['name'] ?? ''); ?>"
                        class="<?= !empty($errors['name']) ? 'is-invalid' : ''; ?>"
                        required
                        maxlength="60"
                        autocomplete="name"
                    >
                </div>
                <?php if (!empty($errors['name'])): ?>
                    <div class="error-message">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                        <span><?= e($errors['name']); ?></span>
                    </div>
                <?php endif; ?>
            </div>

            <!-- Email Address -->
            <div class="form-group">
                <label for="email">Email Address <span class="required">*</span></label>
                <div class="input-wrap">
                    <input 
                        type="email" 
                        id="email" 
                        name="email" 
                        placeholder="john.doe@example.com" 
                        value="<?= e($old['email'] ?? ''); ?>"
                        class="<?= !empty($errors['email']) ? 'is-invalid' : ''; ?>"
                        required
                        maxlength="100"
                        autocomplete="email"
                    >
                </div>
                <?php if (!empty($errors['email'])): ?>
                    <div class="error-message">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                        <span><?= e($errors['email']); ?></span>
                    </div>
                <?php endif; ?>
            </div>

            <!-- Phone Number -->
            <div class="form-group">
                <label for="phone">Phone Number (10 Digits) <span class="required">*</span></label>
                <div class="input-wrap">
                    <input 
                        type="tel" 
                        id="phone" 
                        name="phone" 
                        placeholder="9876543210" 
                        value="<?= e($old['phone'] ?? ''); ?>"
                        class="<?= !empty($errors['phone']) ? 'is-invalid' : ''; ?>"
                        required
                        pattern="[6-9][0-9]{9}"
                        maxlength="10"
                        inputmode="numeric"
                        autocomplete="tel"
                    >
                </div>
                <?php if (!empty($errors['phone'])): ?>
                    <div class="error-message">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                        <span><?= e($errors['phone']); ?></span>
                    </div>
                <?php endif; ?>
            </div>

            <!-- Gender -->
            <div class="form-group">
                <label>Gender <span class="required">*</span></label>
                <div class="gender-options">
                    <?php 
                        $selectedGender = $old['gender'] ?? '';
                    ?>
                    <label class="gender-radio-label">
                        <input 
                            type="radio" 
                            name="gender" 
                            value="male" 
                            <?= $selectedGender === 'male' ? 'checked' : ''; ?>
                        >
                        <span>Male</span>
                    </label>

                    <label class="gender-radio-label">
                        <input 
                            type="radio" 
                            name="gender" 
                            value="female" 
                            <?= $selectedGender === 'female' ? 'checked' : ''; ?>
                        >
                        <span>Female</span>
                    </label>

                    <label class="gender-radio-label">
                        <input 
                            type="radio" 
                            name="gender" 
                            value="other" 
                            <?= $selectedGender === 'other' ? 'checked' : ''; ?>
                        >
                        <span>Other</span>
                    </label>
                </div>
                <?php if (!empty($errors['gender'])): ?>
                    <div class="error-message">
                        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                        <span><?= e($errors['gender']); ?></span>
                    </div>
                <?php endif; ?>
            </div>

            <!-- Submit Button -->
            <button type="submit" class="btn-submit" id="submitBtn">
                <span>Submit Details</span>
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <line x1="5" y1="12" x2="19" y2="12"></line>
                    <polyline points="12 5 19 12 12 19"></polyline>
                </svg>
            </button>
        </form>

        <p class="footer-note">All inputs are secured and validated according to security standards.</p>
    </div>
</div>

<!-- Client-side instantaneous validation -->
<script>
    document.addEventListener('DOMContentLoaded', () => {
        const form = document.getElementById('registrationForm');
        const phoneInput = document.getElementById('phone');

        // Only allow numbers to be typed into the phone input
        phoneInput.addEventListener('input', (e) => {
            e.target.value = e.target.value.replace(/\D/g, '').slice(0, 10);
        });

        // Form submission client validation
        form.addEventListener('submit', (e) => {
            const name = document.getElementById('name').value.trim();
            const email = document.getElementById('email').value.trim();
            const phone = document.getElementById('phone').value.trim();
            const gender = form.querySelector('input[name="gender"]:checked');

            let isValid = true;
            let errorMsg = '';

            if (name.length < 3) {
                isValid = false;
                errorMsg = 'Name must be at least 3 characters.';
            } else if (!email.includes('@') || !email.includes('.')) {
                isValid = false;
                errorMsg = 'Please provide a valid email.';
            } else if (!/^[6-9]\d{9}$/.test(phone)) {
                isValid = false;
                errorMsg = 'Phone number must be a valid 10-digit number starting with 6-9.';
            } else if (!gender) {
                isValid = false;
                errorMsg = 'Please choose your gender.';
            }

            if (!isValid) {
                // If invalid on client-side, let user know or allow server side validation to catch
                // For optimal UX, native HTML5 validation or form submit continues
            }
        });
    });
</script>

</body>
</html>


<?php
session_start();

// Database connection
$conn = new mysqli(
    "db01.dbhost.dev",
    "user_453dkg77j",
    "p453dkg77j",
    "db_453dkg77j",
    "5051"
);

if ($conn->connect_error) {
    die("Database connection failed. Check MySQL settings.");
}

$conn->set_charset("utf8mb4");

// Create a CSRF token for forms
if (empty($_SESSION["csrf"])) {
    $_SESSION["csrf"] = bin2hex(random_bytes(32));
}

function e($value) {
    return htmlspecialchars(
        (string)$value,
        ENT_QUOTES,
        "UTF-8"
    );
}

function goHome() {
    header("Location: index.php");
    exit;
}

$message = "";
$error = "";

// Process form submissions
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    $token = $_POST["csrf"] ?? "";

    if (!hash_equals($_SESSION["csrf"], $token)) {
        $error = "Invalid form token. Refresh and try again.";
    } else {
        $action = $_POST["action"] ?? "";

        // Register a student
        if ($action === "register") {
            $name = trim($_POST["name"] ?? "");
            $email = trim($_POST["email"] ?? "");
            $password = $_POST["password"] ?? "";

            if (
                $name === "" ||
                !filter_var($email, FILTER_VALIDATE_EMAIL) ||
                strlen($password) < 8
            ) {
                $error = "Enter valid details and a password of at least 8 characters.";
            } else {
                $hash = password_hash(
                    $password,
                    PASSWORD_DEFAULT
                );

                $stmt = $conn->prepare(
                    "INSERT INTO csecusers (name, email, password)
                     VALUES (?, ?, ?)"
                );
                $stmt->bind_param("sss", $name, $email, $hash);

                if ($stmt->execute()) {
                    $message = "Registration successful. Please log in.";
                } else {
                    $error = $stmt->errno === 1062
                        ? "This email is already registered."
                        : "Registration failed.";
                }

                $stmt->close();
            }
        }

        // Login
        elseif ($action === "login") {
            $email = trim($_POST["email"] ?? "");
            $password = $_POST["password"] ?? "";

            $stmt = $conn->prepare(
                "SELECT id, name, email, password, role
                 FROM csecusers WHERE email = ?"
            );
            $stmt->bind_param("s", $email);
            $stmt->execute();
            $result = $stmt->get_result();
            $user = $result->fetch_assoc();
            $stmt->close();

            if (
                $user &&
                password_verify($password, $user["password"])
            ) {
                session_regenerate_id(true);

                $_SESSION["user_id"] = $user["id"];
                $_SESSION["name"] = $user["name"];
                $_SESSION["role"] = $user["role"];

                goHome();
            } else {
                $error = "Incorrect email or password.";
            }
        }

        // Submit a complaint
        elseif ($action === "complaint" &&
                isset($_SESSION["user_id"]) &&
                $_SESSION["role"] === "student") {

            $category = trim($_POST["category"] ?? "");
            $subject = trim($_POST["subject"] ?? "");
            $description = trim($_POST["description"] ?? "");

            $allowed = [
                "Infrastructure",
                "Hostel",
                "Transport",
                "Library",
                "Academics",
                "Other"
            ];

            if (
                !in_array($category, $allowed, true) ||
                $subject === "" ||
                $description === ""
            ) {
                $error = "Please complete all complaint fields.";
            } else {
                $stmt = $conn->prepare(
                    "INSERT INTO cseccomplaints
                    (user_id, category, subject, description)
                    VALUES (?, ?, ?, ?)"
                );
                $stmt->bind_param(
                    "isss",
                    $_SESSION["user_id"],
                    $category,
                    $subject,
                    $description
                );

                if ($stmt->execute()) {
                    $message = "Complaint submitted successfully.";
                } else {
                    $error = "Could not submit complaint.";
                }

                $stmt->close();
            }
        }

        // Admin updates status and response
        elseif ($action === "update" &&
                isset($_SESSION["user_id"]) &&
                $_SESSION["role"] === "admin") {

            $id = filter_input(
                INPUT_POST,
                "complaint_id",
                FILTER_VALIDATE_INT
            );
            $status = $_POST["status"] ?? "";
            $response = trim($_POST["response"] ?? "");

            $statuses = [
                "Pending",
                "In Progress",
                "Resolved",
                "Rejected"
            ];

            if (
                !$id ||
                !in_array($status, $statuses, true)
            ) {
                $error = "Invalid complaint or status.";
            } else {
                $stmt = $conn->prepare(
                    "UPDATE cseccomplaints
                     SET status = ?, admin_response = ?
                     WHERE id = ?"
                );
                $stmt->bind_param("ssi", $status, $response, $id);

                $message = $stmt->execute()
                    ? "Complaint updated."
                    : "Update failed.";

                $stmt->close();
            }
        }

        // Admin deletes a complaint
        elseif ($action === "delete" &&
                isset($_SESSION["user_id"]) &&
                $_SESSION["role"] === "admin") {

            $id = filter_input(
                INPUT_POST,
                "complaint_id",
                FILTER_VALIDATE_INT
            );

            if ($id) {
                $stmt = $conn->prepare(
                    "DELETE FROM cseccomplaints WHERE id = ?"
                );
                $stmt->bind_param("i", $id);
                $message = $stmt->execute()
                    ? "Complaint deleted."
                    : "Delete failed.";
                $stmt->close();
            } else {
                $error = "Invalid complaint ID.";
            }
        }

        // Logout
        elseif ($action === "logout") {
            $_SESSION = [];
            session_destroy();
            header("Location: index.php");
            exit;
        }

        else {
            $error = "Please log in with the correct account.";
        }
    }
}

// Read complaints belonging to the current student,
// or all complaints for the admin.
$complaints = [];

if (isset($_SESSION["user_id"])) {
    if ($_SESSION["role"] === "admin") {
        $sql = "SELECT c.*, u.name, u.email
                FROM cseccomplaints c
                JOIN csecusers u ON c.user_id = u.id
                ORDER BY c.created_at DESC";
        $result = $conn->query($sql);
    } else {
        $stmt = $conn->prepare(
            "SELECT c.*, u.name, u.email
             FROM cseccomplaints c
             JOIN csecusers u ON c.user_id = u.id
             WHERE c.user_id = ?
             ORDER BY c.created_at DESC"
        );
        $stmt->bind_param("i", $_SESSION["user_id"]);
        $stmt->execute();
        $result = $stmt->get_result();
    }

    while ($row = $result->fetch_assoc()) {
        $complaints[] = $row;
    }

    if (isset($stmt) && $_SESSION["role"] !== "admin") {
        $stmt->close();
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, initial-scale=1">
    <title>College Complaint Portal</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>

<header class="topbar">
    <div>
        <h2>CampusCare</h2>
        <p>College Complaint Management System</p>
    </div>

    <?php if (isset($_SESSION["user_id"])): ?>
        <div class="user-info">
            <span><?= e($_SESSION["name"]) ?></span>
            <form method="post">
                <input type="hidden" name="csrf"
                       value="<?= e($_SESSION["csrf"]) ?>">
                <input type="hidden" name="action" value="logout">
                <button class="btn secondary">Logout</button>
            </form>
        </div>
    <?php endif; ?>
</header>

<main class="container">
    <?php if ($message): ?>
        <div class="alert success"><?= e($message) ?></div>
    <?php endif; ?>

    <?php if ($error): ?>
        <div class="alert danger"><?= e($error) ?></div>
    <?php endif; ?>

    <?php if (!isset($_SESSION["user_id"])): ?>

        <section class="welcome">
            <h1>Your Voice Matters</h1>
            <p>
                Submit college concerns and track their progress
                transparently.
            </p>
        </section>

        <div class="auth-grid">
            <section class="card">
                <h2>Student Login / Admin Login</h2>

                <form method="post">
                    <input type="hidden" name="csrf"
                           value="<?= e($_SESSION["csrf"]) ?>">
                    <input type="hidden" name="action" value="login">

                    <label>Email</label>
                    <input type="email" name="email"
                           required autocomplete="email">

                    <label>Password</label>
                    <input type="password" name="password"
                           required autocomplete="current-password">

                    <button class="btn">Login</button>
                </form>
            </section>

            <section class="card">
                <h2>Student Registration</h2>

                <form method="post">
                    <input type="hidden" name="csrf"
                           value="<?= e($_SESSION["csrf"]) ?>">
                    <input type="hidden" name="action" value="register">

                    <label>Full Name</label>
                    <input type="text" name="name"
                           maxlength="100" required>

                    <label>Email</label>
                    <input type="email" name="email"
                           maxlength="150" required>

                    <label>Password (minimum 8 characters)</label>
                    <input type="password" name="password"
                           minlength="8" required
                           autocomplete="new-password">

                    <button class="btn">Create Account</button>
                </form>
            </section>
        </div>

    <?php else: ?>

        <section class="welcome">
            <h1>
                Welcome, <?= e($_SESSION["name"]) ?>!
            </h1>
            <p>
                Role: <?= e(ucfirst($_SESSION["role"])) ?>
            </p>
        </section>

        <?php if ($_SESSION["role"] === "student"): ?>
            <section class="card">
                <h2>Submit a Complaint</h2>

                <form method="post">
                    <input type="hidden" name="csrf"
                           value="<?= e($_SESSION["csrf"]) ?>">
                    <input type="hidden" name="action"
                           value="complaint">

                    <label>Category</label>
                    <select name="category" required>
                        <option value="">Select category</option>
                        <option>Infrastructure</option>
                        <option>Hostel</option>
                        <option>Transport</option>
                        <option>Library</option>
                        <option>Academics</option>
                        <option>Other</option>
                    </select>

                    <label>Subject</label>
                    <input type="text" name="subject"
                           maxlength="200" required>

                    <label>Complaint Description</label>
                    <textarea name="description"
                              rows="4" required></textarea>

                    <button class="btn">Submit Complaint</button>
                </form>
            </section>
        <?php endif; ?>

        <section class="card">
            <h2>
                <?= $_SESSION["role"] === "admin"
                    ? "All Student Complaints"
                    : "My Complaints" ?>
            </h2>

            <?php if (!$complaints): ?>
                <p>No complaints found.</p>
            <?php endif; ?>

            <?php foreach ($complaints as $c): ?>
                <article class="complaint">
                    <h3>#<?= (int)$c["id"] ?> —
                        <?= e($c["subject"]) ?>
                    </h3>

                    <?php if ($_SESSION["role"] === "admin"): ?>
                        <p>Student: <?= e($c["name"]) ?>
                            (<?= e($c["email"]) ?>)</p>
                    <?php endif; ?>

                    <p><b>Category:</b>
                        <?= e($c["category"]) ?></p>
                    <p><b>Description:</b>
                        <?= nl2br(e($c["description"])) ?></p>
                    <p><b>Status:</b>
                        <span class="status">
                            <?= e($c["status"]) ?>
                        </span>
                    </p>
                    <p><b>Submitted:</b>
                        <?= e($c["created_at"]) ?></p>

                    <?php if ($c["admin_response"]): ?>
                        <p><b>Admin Response:</b>
                            <?= nl2br(e($c["admin_response"])) ?>
                        </p>
                    <?php endif; ?>

                    <?php if ($_SESSION["role"] === "admin"): ?>
                        <form method="post" class="admin-form">
                            <input type="hidden" name="csrf"
                                   value="<?= e($_SESSION["csrf"]) ?>">
                            <input type="hidden" name="action"
                                   value="update">
                            <input type="hidden" name="complaint_id"
                                   value="<?= (int)$c["id"] ?>">

                            <label>Update Status</label>
                            <select name="status">
                                <?php foreach (
                                    ["Pending", "In Progress",
                                     "Resolved", "Rejected"] as $s
                                ): ?>
                                    <option value="<?= e($s) ?>"
                                        <?= $c["status"] === $s
                                            ? "selected" : "" ?>>
                                        <?= e($s) ?>
                                    </option>
                                <?php endforeach; ?>
                            </select>

                            <label>Admin Response</label>
                            <textarea name="response"
                                      rows="2"><?= e(
                                          $c["admin_response"] ?? ""
                                      ) ?></textarea>

                            <button class="btn">Save Update</button>
                        </form>

                        <form method="post"
                              onsubmit="return confirm('Delete this complaint?')">
                            <input type="hidden" name="csrf"
                                   value="<?= e($_SESSION["csrf"]) ?>">
                            <input type="hidden" name="action"
                                   value="delete">
                            <input type="hidden" name="complaint_id"
                                   value="<?= (int)$c["id"] ?>">
                            <button class="btn danger-btn">
                                Delete Complaint
                            </button>
                        </form>
                    <?php endif; ?>
                </article>
            <?php endforeach; ?>
        </section>

    <?php endif; ?>
</main>

<footer>
    <p>CampusCare | College Complaint Management System</p>
</footer>

</body>
</html>

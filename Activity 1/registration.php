<?php
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "regform"; 


if ($_SERVER["REQUEST_METHOD"] == "POST") {

    $conn = new mysqli($servername, $username, $password, $dbname);


    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }


    $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $password = $_POST['password']; 
    

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        echo "<script>alert('Invalid email format'); window.location.href='registration.php';</script>";
        exit;
    }


    $checkQuery = "SELECT id FROM users WHERE email = ?";
    $stmt = $conn->prepare($checkQuery);
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        echo "<script>alert('This email is already registered. Please use a different email.'); window.location.href='registration.php';</script>";
    } else {

        $hashed_password = password_hash($password, PASSWORD_DEFAULT);
        

        $insertQuery = "INSERT INTO users (email, password) VALUES (?, ?)";
        $stmt = $conn->prepare($insertQuery);
        if ($stmt) {
            $stmt->bind_param("ss", $email, $hashed_password);
            $result = $stmt->execute();
            
            if ($result) {
                echo "<script>alert('Registration successful!'); window.location.href='registration.php';</script>";
            } else {
                echo "<script>alert('Error during registration: " . $stmt->error . "'); window.location.href='registration.php';</script>";
            }
            $stmt->close();
        } else {
            echo "<script>alert('Error preparing statement: " . $conn->error . "'); window.location.href='registration.php';</script>";
        }
    }

    $conn->close();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Registration</title>
    <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <h2>Register Here!</h2>
        <form action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post" onsubmit="return validateForm()">
            
            <div class="input-container">
                <input type="email" name="email" required placeholder=" ">
                <label>Email</label>
            </div>

            <div class="input-container">
                <input type="password" id="password" name="password" required placeholder=" " minlength="8">
                <label>Password</label>
            </div>

            <div class="input-container">
                <input type="password" id="confirm_password" name="confirm_password" required placeholder=" " minlength="8">
                <label>Confirm Password</label>
            </div>

            <button type="submit">Register</button>
        </form>
    </div>

    <script>
        function validateForm() {
            var password = document.getElementById("password").value;
            var confirmPassword = document.getElementById("confirm_password").value;
            
            if (password != confirmPassword) {
                alert("Passwords do not match!");
                return false;
            }
            return true;
        }
    </script>
</body>
</html>
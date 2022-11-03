<?php
    if (empty($_FILES)) {
?>

        <h3>Upload new file:</h3>
        <form action="upload.php" method="POST"  enctype="multipart/form-data">
        <p>
        <input type="file" name="file" required>
        </p>
        <input type="submit" value="Upload">
        </form>

<?php
} else {
    $file_dir = "./files/";

    $host = "localhost";
    $db_name = "mysql";
    $db_username = "root";
    $db_password = "";

    $conn = new mysqli($host, $db_username, $db_password, $db_name);
    if ($conn->connect_error) {
        die("Connection failed: " . $conn->connect_error);
    }


    if ($_FILES["file"]["size"] > 500000) {
        echo "Sorry, your file is too large.";
    } else {
        $file_name = basename($_FILES["file"]["name"]);
        $file_path = $file_dir . $file_name;
        if (move_uploaded_file($_FILES["file"]["tmp_name"], $file_path)) {
            $sql = "INSERT INTO files (filename, filepath) VALUES ('$file_name', '$file_path')";
            if ($conn->query($sql) === TRUE) {
                echo "
                    <h1>File successfully uploaded!</h1>
                    <p><a href='/www/html'>Back</a></p>
                    ";
            } else {
                echo "Error: " . $sql . "<br>" . $conn->error;
            }
        } else {
            echo "Sorry, there was an error uploading your file.";
        }
    }
    $conn->close();
}
?>

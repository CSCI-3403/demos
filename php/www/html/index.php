<!DOCTYPE html>
<html>
<body>

<h1>Docz</h1>
<a href="/www/html/upload.php">Upload new file</a>

<h3>Files</h3>
<form>
  <label for="search">Search</label>
  <input type="text" name="search" value="<?php echo $_GET["search"] ?? ""; ?>">
</form>
<?php

$host = "localhost";
$db_name = "mysql";
$db_username = "root";
$db_password = "";

$conn = new mysqli($host, $db_username, $db_password, $db_name);
if ($conn->connect_error) {
  die("Connection failed: " . $conn->connect_error);
} 

$conn->query("CREATE TABLE IF NOT EXISTS files (filename TEXT, filepath TEXT);");
if ($_GET["search"] ?? "" !== "") {
  $search = $_GET["search"];
  $q = "SELECT * FROM files WHERE filename='$search';";
} else {
  $q = "SELECT * FROM files;";
}

$conn->multi_query($q);

echo "<ol>";
do {
  if ($result = $conn->store_result()) {
    while($row = $result->fetch_assoc()) {
      $filename = $row["filename"];
      $filepath = $row["filepath"];
      echo "<li>";
      echo "<a href='$filepath'>$filename</a>";
      echo "</li>\n";
    }
  }
} while ($conn -> next_result());
echo "</ol>";
?>


</body>
</html>

<?php

$dir = "/var/www/uploads/";

if (isset($_FILES["file"])) {
    $name = $_FILES["file"]["name"];
    move_uploaded_file($_FILES["file"]["tmp_name"], $dir . $name);
    echo "saved " . $name;
}

if (isset($_GET["view"])) {
    $f = $_GET["view"];
    echo file_get_contents($dir . $f);
}

if (isset($_GET["convert"])) {
    $src = $_GET["convert"];
    system("convert " . $src . " /tmp/out.png");
}

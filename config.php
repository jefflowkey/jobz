<?php
/* Database credentials. Assuming you are running MySQL
server with default setting (user 'root' with no password) */
define('DB_SERVER', 'sql109.epizy.com');
define('DB_USERNAME', 'epiz_33029643');
define('DB_PASSWORD', 'ymwqHW6mvpeLoY');
define('DB_NAME', 'epiz_33029643_jobz_db');

/* Attempt to connect to MySQL database */
$link = mysqli_connect(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

// Check connection
if($link === false){
    die("ERROR: Could not connect. " . mysqli_connect_error());
}

?>
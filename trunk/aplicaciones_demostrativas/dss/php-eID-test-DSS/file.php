<?php
session_start();
header('Content-Type: '.$_SESSION['file_type']);
header('Content-Disposition: inline; filename="'.$_SESSION['file_name'].'"');
echo base64_decode($_SESSION["SignatureResponse"]);
?>
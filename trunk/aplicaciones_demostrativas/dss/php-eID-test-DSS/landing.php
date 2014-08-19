<?php
session_start();
?>
<html>
    <head>
        <title>eID DSS Test</title>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
    </head>
    <body>
        <h1>Aplicación demostrativa - eID DSS</h1><br>
        <?php
        if ($_POST['SignatureStatus'] == "OK") {
            $_SESSION["SignatureResponse"] = $_POST["SignatureResponse"];
            print 'Firma Exitosa<br>';
            print '<a href=file.php>Descargar Archivo</a><br>';
        } else {
            print 'Firma Corrupta<br><br>';
        }
        ?>
        <a href="upload.php">Realizar Firma Digital</a><br/>
    </body>
</html>

<?php
require_once('/var/simplesamlphp/lib/_autoload.php');
$as = new SimpleSAML_Auth_Simple('default-sp');
$as->requireAuth();
?>
<html>
    <head>
        <title>eID IDP Test</title>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
    </head>
    <body>
        <h1>Aplicación demostrativa -  eID IDP - eID DSS</h1><br>
        <?php
        if ($_POST['SignatureStatus'] == "OK") {
            $_SESSION["SignatureResponse"] = $_POST["SignatureResponse"];
            print 'Firma Exitosa<br>';
            print '<a href=file.php>Descargar Archivo</a><br>';
        } else {
            print 'Firma Corrupta<br><br>';
        }
        print ('<a href="upload.php">Realizar Firma Digital</a><br/>');
        print ('<a href="login.php">Inicio</a><br/>');
        ?>
        <br>
        <hr>
        <a href="logout.php">Cerrar Sesión</a>
    </body>
</html>

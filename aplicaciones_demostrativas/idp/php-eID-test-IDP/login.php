<?php
require_once('/var/simplesamlphp/lib/_autoload.php');
$as = new SimpleSAML_Auth_Simple('default-sp');
$as->requireAuth();
?>
<html>
    <head>
        <title>eID IDP Test </title>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
    </head>
    <body>
        <h1>Aplicación demostrativa -  eID IDP - eID DSS</h1><br>
        <?php
        $attributes = $as->getAttributes();
        print ("Bienvenido: " . $attributes["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name"][0] . "<br />");
        print ("Atributos provistos por eID IDP: <br />");

        print ('<table border="1">');
        foreach ($attributes as $key => $value) {
            print ("<tr><td><strong>" . $key . "</strong></td><td>" . $value[0] . "</td></tr>");
        }
        print ("</table><br/><br/><br/>");

        print ('<a href="upload.php">Realizar Firma Digital</a><br/>');

        print ('<hr><a href="logout.php">Cerrar Sesión</a>');
        ?>
    </body>
</html>
<?php
session_start();
?>
<html>
    <head>
        <title>eID DSS Test</title>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8"/>
    </head>
    <body>
        <h1>Aplicación demostrativa -  eID DSS</h1><br>
        <?php
        if (isset($_FILES['the_file'])) {

            $file_name = $_FILES['the_file']['name'];

            $file_size = $_FILES['the_file']['size'];
            $file_type = $_FILES['the_file']['type'];
            $file_tmp = $_FILES['the_file']['tmp_name'];

            $type = pathinfo($file_tmp, PATHINFO_EXTENSION);
            $data = file_get_contents($file_tmp);
            $base64 = base64_encode($data);

            echo 'Archivo: ' . $file_name . '<br>';
            echo 'Tipo: ' . $file_type . '<br>';
            echo 'Tamano: ' . round(($file_size / 1024), 1) . ' [KB]<br>';
            echo '<a href="sign.php">Firmar</a><br>';

            //echo "Contenido del archivo en Base64 es ".$base64;

            $_SESSION['the_file'] = $base64;
            $_SESSION['file_name'] = $file_name;
            $_SESSION['file_type'] = $file_type;
        ?>
            <br>

        <?php
        } else {
        ?>

            <form action="upload.php" method="POST" enctype="multipart/form-data">

                <p> Seleccione el archivo a firmar:<br><br><br>
                    <input type="file" name="the_file" />
                    <input type="submit" value="Subir">

                </p>
            </form>

        <?php
        }
        ?>
    </body>
</html>

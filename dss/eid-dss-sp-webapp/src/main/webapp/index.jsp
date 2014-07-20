<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
        "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
<head>
<title>eID DSS - Proveedor de Servicio de Prueba (SP)</title>
</head>
<body>
	<h1>eID DSS - Proveedor de Servicio de Prueba (SP)</h1>

	<h2>HTTP Post Binding</h2>

	<form enctype="multipart/form-data" action="upload" method="post">

		<table border="1">
			<tr>
				<td><b>Elija el archivo a subir:</b></td>
				<td><input name="upload" type="file" /></td>
				<td align="right"><input type="submit" value="Firmar" /></td>
			</tr>
		</table>

	</form>

	<h2>HTTP Post / Artifact Binding</h2>

	<form enctype="multipart/form-data" action="upload-artifact"
		method="post">

		<table border="1">
			<tr>
				<td><b>Elija el archivo a subir:</b></td>
				<td><input name="upload" type="file" /></td>
				<td align="right"><input type="submit" value="Firmar" /></td>
			</tr>
		</table>

	</form>

	<h2>Signed HTTP Post Binding with SDK Request Servlet</h2>

	<form enctype="multipart/form-data" action="upload-sdk" method="post">

		<table border="1">
			<tr>
				<td><b>Elija el archivo a subir:</b></td>
				<td><input name="upload" type="file" /></td>
				<td align="right"><input type="submit" value="Firmar" /></td>
			</tr>
		</table>

	</form>

	<h2>Signed HTTP Post / Artifact Binding</h2>

	<form enctype="multipart/form-data" action="upload-artifact-signed"
		method="post">

		<table border="1">
			<tr>
				<td><b>Elija el archivo a subir:</b></td>
				<td><input name="upload" type="file" /></td>
				<td align="right"><input type="submit" value="Firmar" /></td>
			</tr>
		</table>

	</form>

	<h2>Identida del SP </h2>

	Descargar el Certificado del Proveedor de Servicios de Prueba
	<a href="./pki">here</a>

</body>
</html>
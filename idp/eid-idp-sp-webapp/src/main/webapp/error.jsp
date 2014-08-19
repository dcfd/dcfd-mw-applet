<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
        "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<%@ page contentType="text/html; charset=UTF-8"%>

<html>
<head>
<title>eID Identity Provider (IdP) - Proveedor de Servicios de Prueba (SP)</title>
</head>
<body>

	<h1>Fallo en la Autentication</h1>
	<p>
		Motivo:<%=session.getAttribute("ErrorMessage")%>
	</p>
	<a href="index.jsp">Atras</a>
</body>
</html>
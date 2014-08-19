<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
        "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
<head>
<title>eID Identity Provider (IdP) - Proveedor de Servicios de Prueba (SP)</title>
</head>
<body>
	<h1>eID Identity Provider (IdP) - Proveedor de Servicios de Prueba (SP)</h1>
	<p>Este Proveedor de Servicios de Prueba (SP) muestra los diferentes protocolos de
		identificación/autenticación hacia el eID IdP.</p>
	<ul>
		<li><a
			href="https://<%=request.getServerName()%>:<%=request.getServerPort()%>/eid-idp/protocol/foobar">
				Protocolo no soportado </a></li>
	</ul>

	<h2>SAML v2.0 Browser Post</h2>
	<ul>
		<li><a href="saml2/post/auth.jsp">Autenticación</a></li>
	</ul>

	<h2>SAML v2.0 Browser POST con Enlace de Artefactos en la Repuesta (Artifact Binding on Response)</h2>
	<ul>

		<li><a href="saml2/artifact/auth.jsp">Autenticación</a></li>
	</ul>

	<h2>WS-Federation</h2>
	<ul>
		<li><a href="ws-federation/auth.jsp">Autenticación</a></li>
	</ul>

	<h2>OpenID v2.0</h2>

	<ul>

		<li><a href="openid/auth.jsp">Autenticación</a></li>
	</ul>

	<h2>Configuración del SP</h2>

	<p>
		<a href="./configuration">Configurar SP...</a>
	</p>

	<h2>Identidad del SP</h2>

	Descargar el Certificado del Proveedor de Servicio de Prueba
	<a href="./pki">aqui</a>
	<br /> Descargar la clave Publica del Proveedor de Servicio de Prueba
	<a href="./public">aqui</a>
	<br />
	<jsp:useBean id="sp" scope="request"
		class="be.fedict.eid.idp.sp.SPBean" />
	Secreto AES-128:
	<jsp:getProperty name="sp" property="aes128SecretKey" />
</body>
</html>
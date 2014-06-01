<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
        "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
<head>
<title>eID Identity Provider (IdP) - Test Service Provider (SP)</title>
</head>
<body>
	<h1>eID Identity Provider (IdP) - Test Service Provider (SP)</h1>
	<p>This test Service Provider (SP) demos the different
		identification/authentication protocols towards the eID IdP.</p>
	<ul>
		<li><a
			href="https://<%=request.getServerName()%>:<%=request.getServerPort()%>/eid-idp/protocol/foobar">
				Unsupported Protocol </a></li>
	</ul>

	<h2>SAML v2.0 Browser Post</h2>
	<ul>
		<li><a href="saml2/post/ident.jsp">Identification</a></li>
		<li><a href="saml2/post/auth.jsp">Authentication</a></li>
		<li><a href="saml2/post/auth-ident.jsp">Authentication +
				Identification </a></li>
	</ul>

	<h2>SAML v2.0 Browser POST with Artifact Binding on Response</h2>
	<ul>

		<li><a href="saml2/artifact/ident.jsp">Identification</a></li>
		<li><a href="saml2/artifact/auth.jsp">Authentication</a></li>
		<li><a href="saml2/artifact/auth-ident.jsp">Authentication +
				Identification </a></li>
	</ul>

	<h2>WS-Federation</h2>
	<ul>
		<li><a href="ws-federation/ident.jsp">Identification</a></li>
		<li><a href="ws-federation/auth.jsp">Authentication</a></li>
		<li><a href="ws-federation/auth-ident.jsp">Authentication +
				Identification (validation via STS)</a></li>
	</ul>

	<h2>OpenID v2.0</h2>

	<ul>

		<li><a href="openid/ident.jsp">Identification</a></li>
		<li><a href="openid/auth.jsp">Authentication</a></li>
		<li><a href="openid/auth-ident.jsp">Authentication +
				Identification </a></li>
	</ul>

	<h2>SP Configuration</h2>

	<p>
		<a href="./configuration">Configure Test SP...</a>
	</p>

	<h2>SP Identity</h2>

	Download the Test Service Provider's Certificate
	<a href="./pki">here</a>
	<br /> Download the Test Service Provider's Public Key
	<a href="./public">here</a>
	<br />
	<jsp:useBean id="sp" scope="request"
		class="be.fedict.eid.idp.sp.SPBean" />
	AES-128 secret:
	<jsp:getProperty name="sp" property="aes128SecretKey" />
</body>
</html>
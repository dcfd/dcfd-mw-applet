<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
        "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<%@ page contentType="text/html; charset=UTF-8"%>

<html>
<head>
<title>eID Identity Provider (IdP) - Test Service Provider (SP)</title>
</head>
<body>

	<h1>Authentication Failed</h1>
	<p>
		Reason:<%=session.getAttribute("ErrorMessage")%>
	</p>
	<a href="index.jsp">Back</a>
</body>
</html>
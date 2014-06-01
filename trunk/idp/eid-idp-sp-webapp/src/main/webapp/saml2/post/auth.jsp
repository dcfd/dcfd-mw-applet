<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<%@ page contentType="text/html; charset=UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>

<html>
<head>
</head>
<body>

	<jsp:useBean id="saml2" scope="request"
		class="be.fedict.eid.idp.sp.saml2.Saml2Bean" />
	<jsp:setProperty name="saml2" property="request" value="<%= request %>" />
	<jsp:setProperty name="saml2" property="idPEntryPoint"
		value="saml2/post/auth" />
	<jsp:setProperty name="saml2" property="spResponseEndpoint"
		value="saml2-landing" />
	<c:redirect url="../../saml-request" />

</body>
</html>
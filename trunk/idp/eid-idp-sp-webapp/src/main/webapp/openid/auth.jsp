<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<%@ page contentType="text/html; charset=UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>

<html>
<head>
</head>
<body>

	<jsp:useBean id="openid" scope="request"
		class="be.fedict.eid.idp.sp.openid.OpenIDBean" />
	<jsp:setProperty name="openid" property="request"
		value="<%= request %>" />
	<jsp:setProperty name="openid" property="idPEntryPoint"
		value="openid/auth" />
	<jsp:setProperty name="openid" property="spResponseEndpoint"
		value="openid-landing" />
	<jsp:setProperty name="openid" property="preferredLanguages" value="nl" />
	<c:redirect url="../openid-request" />

</body>
</html>
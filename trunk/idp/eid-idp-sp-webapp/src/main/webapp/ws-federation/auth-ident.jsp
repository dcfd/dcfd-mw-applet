<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<%@ page contentType="text/html; charset=UTF-8"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>

<html>
<head>
</head>
<body>

	<jsp:useBean id="wsfed" scope="request"
		class="be.fedict.eid.idp.sp.wsfed.WSFedBean" />
	<jsp:setProperty name="wsfed" property="request" value="<%= request %>" />
	<jsp:setProperty name="wsfed" property="idPEntryPoint"
		value="ws-federation/auth-ident" />
	<jsp:setProperty name="wsfed" property="spResponseEndpoint"
		value="wsfed-landing" />
	<jsp:setProperty name="wsfed" property="idPValidationService"
		value="ws/sts" />
	<jsp:setProperty name="wsfed" property="spRealm"
		value="urn:be:fedict:eid:idp:realm:test" />
	<c:redirect url="../wsfed-request" />

</body>
</html>
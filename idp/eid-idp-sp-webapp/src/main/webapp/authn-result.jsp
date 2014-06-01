<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
        "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">

<%@ page contentType="text/html; charset=UTF-8"%>

<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>

<html>
<head>
<title>eID Identity Provider (IdP) - Test Service Provider (SP)</title>
</head>
<body>

	<jsp:useBean id="auth_response" scope="request"
		class="be.fedict.eid.idp.sp.ResponseBean" />

	<jsp:setProperty name="auth_response" property="session"
		value="<%= request.getSession() %>" />

	<h1>Authentication Results</h1>

	<p>Authentication Policy: ${auth_response.policy}</p>

	<c:if test="${sessionScope.Photo != null}">
		<img src="photo.jpg" />
	</c:if>


	<table>
		<tr>
			<th>Identifier</th>
			<td>${auth_response.identifier}</td>
		</tr>
		<c:forEach var="entry" items="${auth_response.attributeMap}">
			<tr>
				<th>${entry.key}</th>
				<td>${entry.value}</td>
			</tr>
		</c:forEach>
	</table>
	<a href="index.jsp">Back</a>
</body>
</html>
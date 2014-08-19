<%-- 
    Document   : authenticate-result
    Author     : jubarran
--%>

<%@page contentType="text/html" pageEncoding="UTF-8"%>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
   "http://www.w3.org/TR/html4/loose.dtd">

<html>
    <head>
        <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
        <title>JSP Page</title>
    </head>
    <body>
    <h1>P&aacutegina con el resultado de la Autenticaci&oacute;n</h1>
<p>Usuario: <%=session.getAttribute("eid.identifier")%>
</p>
<p>Resultado de la
    Autenticaci&oacute;n: <%=session.getAttribute("AuthenticationResult")%>
</p>

<a href="authenticate.jsp">Autenticar nuevamente</a>
|
<a href=".">P&aacute;gina de Inicio</a>
</body>
</html>

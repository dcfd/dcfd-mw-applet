<%-- 
    Document   : authenticate-result
    Created on : Jan 14, 2014, 5:48:23 PM
    Author     : jubarran
--%>

<%@page contentType="text/html" pageEncoding="UTF-8"%>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
   "http://www.w3.org/TR/html4/loose.dtd">

<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
<title>Applicaci&oacute;n Web Demostrativa - DCFD - eid Applet</title>
</head>
    <body style="background-image: url(images/fondo.jpg); width: 800px">
        <div >
            <div style="float: left">
                <img src="images/logo_micitt.png" height:="160px" width="380px">
            </div>
            <div style="float: right">
                <img src="images/logo_firmadigital.png"  height:="160px" width="380px">
            </div>
        </div>
        <div style="clear: both; border-bottom: 2px solid #000"></div>

    <h1>P&aacutegina con el resultado de la Autenticaci&oacute;n</h1>
<p>Usuario Autenticado con &eacute;xito: <%=session.getAttribute("eid.identifier")%>
</p>

<a href="authenticate.jsp">Autenticar nuevamente</a>
|
<a href=".">P&aacute;gina de Inicio</a>
</body>
</html>
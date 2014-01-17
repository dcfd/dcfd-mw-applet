<%-- 
    Document   : sign-result
    Created on : Jan 16, 2014, 9:51:18 AM
    Author     : jubarran
--%>

<%@page contentType="text/html" pageEncoding="UTF-8"%>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
   "http://www.w3.org/TR/html4/loose.dtd">

<html>
<head>
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

<h1>Firma - eID Applet Demo</h1>
<p>Firma exitosa!!</p>
<p>Valor Firma:</p>
<div style="height: 100px; overflow-y: scroll;padding: 0 10px; border-top: solid 1px #ccc;border-bottom: solid 1px #ccc;border-left: solid 1px #ccc;margin-bottom:25px;">
<pre>
<%=session.getAttribute("SignatureValue")%>
</pre>
</div>
<p>Signing Certificate Chain:</p>
<div style="height: 300px; overflow-y: scroll;padding: 0 10px; border-top: solid 1px #ccc;border-bottom: solid 1px #ccc;border-left: solid 1px #ccc;margin-bottom:25px;">
<pre>
<%=session.getAttribute("SigningCertificateChain")%>
</pre>
</div>
<p><a href="sign-text.jsp">Firmar Nuevamente</a> | <a href=".">P&aacute;gina de Inicio</a></p>
</body>
</html>
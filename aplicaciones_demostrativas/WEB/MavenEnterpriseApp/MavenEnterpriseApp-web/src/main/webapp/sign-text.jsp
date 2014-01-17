<%-- 
    Document   : sign-text
    Created on : Jan 16, 2014, 9:48:40 AM
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
<form method="post" action="sign.jsp">
<p>Texto a firmar:</p>
<textarea rows="10" cols="60" name="toBeSigned">Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do
eiusmod tempor incididunt ut labore et dolore magna aliqua.
Ut enim ad minim veniam, quis nostrud exercitation ullamco
 laboris nisi ut aliquip ex ea commodo consequat.
</textarea>
<div style="visibility: hidden;">
    <input type="hidden" name="digestAlgo" value="SHA-1">
</div>
<p><input type="submit" value="Firmar" /></p>
</form>
</body>
</html>
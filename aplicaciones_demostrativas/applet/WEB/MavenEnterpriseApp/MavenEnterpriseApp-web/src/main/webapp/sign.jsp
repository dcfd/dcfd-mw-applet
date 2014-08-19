<%@page contentType="text/html" pageEncoding="UTF-8"%>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
   "http://www.w3.org/TR/html4/loose.dtd">
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<c:set var="toBeSigned" scope="session" value="${param.toBeSigned}" />
<c:set var="digestAlgo" scope="session" value="${param.digestAlgo}" />
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
<script src="https://www.java.com/js/deployJava.js"></script>
<script>
	var attributes = {
		code :'be.fedict.eid.applet.Applet.class',
		archive :'eid-applet-package-1.1.2-SNAPSHOT.jar',
		width :600,
		height :400
	};
	var parameters = {
		TargetPage :'sign-result.jsp',
		AppletService :'applet-service-sign;jsessionid=<%=session.getId()%> ',
		BackgroundColor :'#cccccc',
		Language :'es'
	};
	var version = '1.5';
	deployJava.runApplet(attributes, parameters, version);
</script>
</body>
</html>
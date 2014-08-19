<%-- 
    Document   : authenticate
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
        
<h1>Autenticaci&oacute;n - eID Applet Demo</h1>
<script src="https://www.java.com/js/deployJava.js"></script>
<script>
	var attributes = {
		code :'be.fedict.eid.applet.Applet.class',
		archive :'eid-applet-package-1.1.2-SNAPSHOT.jar',
		width :600,
		height :400
	};
	var parameters = {
		TargetPage :'authenticate-result.jsp',
		AppletService :'applet-service-authn;jsessionid=<%=session.getId()%> ',
		BackgroundColor :'#cccccc',
		Language : 'es'
	};
	var version = '1.6';
	deployJava.runApplet(attributes, parameters, version);
</script>

    </body>
</html>

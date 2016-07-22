<%@page import="net.paygate.saml.util.RequestUtil"%>
<%@page import="java.net.*"%>
<% 
      String error = (String) request.getAttribute("error");
	  String authnRequest = (String) request.getAttribute("authnRequest");
      String redirectURL = (String) request.getAttribute("redirectURL");
%>
<html>
<head>
  <meta http-equiv="content-type" content="text/html; charset=UTF-8">
  <title>SAML-based Single Sign-On Service </title>
</head>
<% 
	if (error != null) {
%>
		<body>
  		<center><font color="red"><b><%= error %></b></font></center><p>
<%
	} else {
		if (authnRequest != null && redirectURL != null) {		
%>
		<body onload="document.location = '<%=redirectURL%>'; return true;">
  		<h1 style="margin-bottom:6px">Submitting login request to Identity provider</h1>
     <%
       } else {
       %>
       <body>
  		<center><font color="red"><b>no SAMLRequest or redirectURL</b></font></center><p>
  		<%
       }
     }
     %>
</body>
</html>
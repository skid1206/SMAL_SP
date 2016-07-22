<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%

	String id = (String)session.getAttribute("ssoUserId");

%>

<html>
<head>
	<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
	<title>Guidebook</title>
</head>
<body>
<fieldset>
	로그인을 한 사용자라면 이 서비스를 이용할 수 있다. 
	세션이 없을 경우 로그인으로의 Redirection을 수행하는 이 페이지는 실제로는 보여질 필요는 없다. 자동으로 IP의 로그인 페이지로 이동할 수 있다.
</fieldset>
<%

if (null == id) { %>
    Guidebook<br />
	<a href="./saml_request_generator_form.jsp">Please Login</a><br />
<%
} else { %>
	Hello <%= id %> :) You successfully logged in via SAML SSO service
<%
}
%>

</body>
</html>

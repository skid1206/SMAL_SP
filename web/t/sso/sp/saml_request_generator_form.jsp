<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8"%>
<%
	String context = request.getContextPath();
	String base = request.getScheme() + "://" + request.getServerName() + ":" +  request.getServerPort() + context;
%>
<html>
<head>
	<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
	<title>Service Provicer : Public SAML Request Generator for Test</title>
	<style type="text/css">
	input {
		width: 500px;
	}
	</style>
</head>
<body>
<fieldset>
	이 폼은 실제로는 보이는 페이지가 아니다. 
	service_front.jsp 에서 사실 사용자는 자동으로 CreateRequestRequestServlet을 통해 
	SAML Request를 가지고 IP의 login_form.jsp로 이동해야 할 것이다.
	세밀한 설정 및 테스트를 위해서 만들었다.
</fieldset>
<form method="post" action="<%= base %>/sso/saml/CreateRequestServlet">
	<ul>
	
		<li style="font-weight:bold">Maybe Fixed Value by SP admin</li>
		<li>ACS Full Path (URL for IP) : <input type="text" name="acsURI" value="<%= base %>/sso/saml/acs"  /></li>
		
		<li>Provider Name (Name) : <input type="text" name="providerName" value="Guidebook"  /></li>
		<li>Page of Request Forwarding to IP (URI) : <input type="text" name="forwardingURI" value="/t/sso/sp/service_proc.jsp"  /></li>
		
		<li style="font-weight:bold">Variable pre-defined by SSO-Admin of IP</li>
		<li>IP SSO Login Path (URL) : <input type="text" name="loginForm" value="http://interface.nuskinkorea.co.kr/sso/saml2/login.jsp"/></li>
		
		<li style="font-weight:bold">URL or Parameter typed by user</li>
		<li>Front Page to Service(URI) : <input type="text" name="RelayState" value="<%= base %>/t/sso/sp/service_front.jsp"  /></li>
		<li>IP Name (Name for Selecting Public Key of IP) : <input type="text" name="IPType" value="Test Identity Provider"  /></li>
		
	</ul>
	<input type="submit" value="Generate SAML Reqeust" />
</form>
</body>
</html>

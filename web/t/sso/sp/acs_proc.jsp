<%--
/*
 * Filename	:	login_proc.jsp
 * History		:	2008/1/8 
 * Version	:	1.0
 * Author		:	Copyright (c) 2008 by PayGate Corp. All Rights Reserved.
 */
--%>
<%@ page contentType="text/html; charset=UTF-8"%>
<%
	String RelayState = (String) request.getAttribute("RelayState");
	String mid = (String) request.getAttribute("mid");
	String sessionno = (String) request.getAttribute("sessionno");
	String signature = (String) request.getAttribute("signature");
%>
<html>
<head>
	<script type="text/javascript">
		function autoSubmit() {
		
			document.loginform.submit();
			
		}
	</script>
</head>
<body onload="autoSubmit();">
	<form name=loginform method=post action="<%=RelayState%>">
	<input type=hidden name=mid value="<%=mid%>">
	<input type=hidden name=sessionno value="<%=sessionno%>">
	<input type=hidden name=signature value="<%=signature%>">
	</form>
</body>
</html>

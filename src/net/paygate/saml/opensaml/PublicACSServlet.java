package net.paygate.saml.opensaml;

import net.paygate.saml.dsig.SAMLVerifier;
import net.paygate.saml.util.SamlException;
import net.paygate.saml.util.Util;
import org.apache.commons.lang.SystemUtils;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;
import org.jdom.Content;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.filter.ElementFilter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.interfaces.RSAPublicKey;
import java.util.Iterator;

public class PublicACSServlet extends HttpServlet {
	private final String keysDIR = System.getProperty("PGV3_HOME")
			+ SystemUtils.FILE_SEPARATOR + "CryptoServer"
			+ SystemUtils.FILE_SEPARATOR + "keys" + SystemUtils.FILE_SEPARATOR;

	public void doGet(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		doPost(request, response);
	}

	public void doPost(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		String SAMLResponse = request.getParameter("SAMLResponse");
		String RelayState = request.getParameter("RelayState");
		String domainName = request.getParameter("domainName");

		try {
			SAMLResponse = new String(Base64.decode(SAMLResponse));
		} catch (Base64DecodingException e) {
			throw new RuntimeException(e);
		}

		System.out.println("------------SAMLResponse:" + SAMLResponse);
		System.out.println("------------RelayState:" + RelayState);
		System.out.println("------------domainName:" + domainName);

		// acs knows public key only.
		// String publicKeyFilePath = keysDIR + "dsa_public.der";
		try {
			String loginid = null;
			Document doc = Util.createJdomDoc(SAMLResponse);

			System.out.println("------------doc:" + doc);

			Iterator itr = doc.getDescendants();

			itr = doc.getDescendants(new ElementFilter());
			while (itr.hasNext()) {
				Content c = (Content) itr.next();
				if (c instanceof Element) {
					Element e = (Element) c;

					if ("NameID".equals(e.getName())) {
						loginid = e.getText().trim();
						break;
					}
				}
			}

			String ipType = (String) request.getSession()
					.getAttribute("IPType");

			String	publicKeyFilePath = "/Volumes/Data/source_2016/SMAL_SP/web/WEB-INF/cert/cert_nuskinkorea.pem";

			RSAPublicKey publicKey;
			publicKey = (RSAPublicKey) Util.getPublicKey(publicKeyFilePath,
					"RSA");

			boolean isVerified = SAMLVerifier
					.verifyXML(SAMLResponse, publicKey);

			if (isVerified) {

				// request.setAttribute("mid", loginid);
				request.setAttribute("RelayState", RelayState);

				System.out.println("logged in user : " + loginid);

				request.getSession().setAttribute("ssoUserId", loginid);

				response.setContentType("text/html; charset=UTF-8");
				request.getRequestDispatcher("/t/sso/sp/acs_proc.jsp").include(
						request, response);
			} else {
				System.out.println("SAMLResponse is modified!!");
				return;
			}

		} catch (SamlException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	/**
	 * IP�� �ش��ϴ� ������ ���丮 �̸��� ��ȯ�Ѵ�. DB�� LDAP�̵�.
	 * 
	 * @param ipType
	 * @return
	 */
	private String getPublicKeyPath(String ipType) {
		// ipType => Test Identity Provider

		if ("Test Identity Provider".equals(ipType))
			return "";

		return "";
	}
}
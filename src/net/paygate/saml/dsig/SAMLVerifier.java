package net.paygate.saml.dsig;

import java.io.ByteArrayInputStream;
import java.security.Provider;
import java.security.PublicKey;

import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.parsers.DocumentBuilderFactory;

import net.paygate.saml.util.XmlDigitalSigner;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

public class SAMLVerifier {

	public static boolean verifyXML(String signedXML, PublicKey pubKey)
			throws Exception {

		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setNamespaceAware(true);
		Document encDoc = dbf.newDocumentBuilder().parse(
				new ByteArrayInputStream(signedXML.getBytes()));

		// Signature 요소 및 그 하위요소를 추출한다.
		NodeList nl = encDoc.getElementsByTagNameNS(XMLSignature.XMLNS,
				"Signature");
		if (nl.getLength() == 0) {
			throw new Exception("Cannot find Signature element");
		}

		// XML 서명을 unmarshaling 하기 위한 XMLSignatureFactory와 DOMValidateObject를
		// 생성한다.
		String providerName = System.getProperty("jsr105Provider",
				XmlDigitalSigner.JSR_105_PROVIDER);
		XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM",
				(Provider) Class.forName(providerName).newInstance());

		DOMValidateContext valContext = new DOMValidateContext(pubKey, nl
				.item(0));

		// 적절한 XMLSignature Object를 얻을 후에는, validate 를 호출하여서 서명의 유효성 여부를 확인 할 수
		// 있다.
		XMLSignature signature = fac.unmarshalXMLSignature(valContext);

		return signature.validate(valContext);

	}
}

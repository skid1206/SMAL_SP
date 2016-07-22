/*
 * Copyright (C) 2006 Google Inc.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package net.paygate.saml.util;

import org.jdom.Document;
import org.jdom.JDOMException;
import org.jdom.input.DOMBuilder;
import org.jdom.input.SAXBuilder;
import org.jdom.output.XMLOutputter;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Random;

/**
 * This utility class is used across the various servlets that make up the
 * SAML-based Single Sign-On Reference Tool. It includes various helper methods
 * that are used for the SAML transactions.
 */
public class Util {

	// Private key file using PKCS #1 encoding
	public static final String P1_BEGIN_MARKER
			= "-----BEGIN RSA PRIVATE KEY"; //$NON-NLS-1$
	public static final String P1_END_MARKER
			= "-----END RSA PRIVATE KEY"; //$NON-NLS-1$

	// Private key file using PKCS #8 encoding
	public static final String P8_BEGIN_MARKER
			= "-----BEGIN PRIVATE KEY"; //$NON-NLS-1$
	public static final String P8_END_MARKER
			= "-----END PRIVATE KEY"; //$NON-NLS-1$

	// used for creating a randomly generated string
	private static Random random = new Random();
	private static final char[] charMapping = {'a', 'b', 'c', 'd', 'e', 'f',
			'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p'};

	/**
	 * Returns a String containing the contents of the file located at the
	 * specified path.
	 *
	 * @param path location of file to be read
	 * @return String containing contents of file, null if error reading file
	 * @throws IOException
	 */
	public static String readFileContents(String path) throws SamlException {
		String requestXML = "";
		StringBuffer contents = new StringBuffer();
		BufferedReader input = null;
		try {
			input = new BufferedReader(new FileReader(new File(path)));
			String line = null;
			while ((line = input.readLine()) != null) {
				contents.append(line);
			}
			input.close();
			return contents.toString();
		} catch (FileNotFoundException e) {
			throw new SamlException("File not found: " + path);
		} catch (IOException e) {
			throw new SamlException("Error reading file: " + path);
		}
	}

	/**
	 * Converts a JDOM Document to a W3 DOM document.
	 *
	 * @param doc JDOM Document
	 * @return W3 DOM Document if converted successfully, null otherwise
	 */
	public static org.w3c.dom.Document toDom(org.jdom.Document doc)
			throws SamlException {
		try {
			XMLOutputter xmlOutputter = new XMLOutputter();
			StringWriter elemStrWriter = new StringWriter();
			xmlOutputter.output(doc, elemStrWriter);
			byte[] xmlBytes = elemStrWriter.toString().getBytes();
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setNamespaceAware(true);
			return dbf.newDocumentBuilder().parse(
					new ByteArrayInputStream(xmlBytes));
		} catch (IOException e) {
			throw new SamlException(
					"Error converting JDOM document to W3 DOM document: "
							+ e.getMessage());
		} catch (ParserConfigurationException e) {
			throw new SamlException(
					"Error converting JDOM document to W3 DOM document: "
							+ e.getMessage());
		} catch (SAXException e) {
			throw new SamlException(
					"Error converting JDOM document to W3 DOM document: "
							+ e.getMessage());
		}
	}

	/**
	 * Converts a JDOM Element to a W3 DOM Element
	 *
	 * @param element JDOM Element
	 * @return W3 DOM Element if converted successfully, null otherwise
	 */
	public static org.w3c.dom.Element toDom(org.jdom.Element element)
			throws SamlException {
		return toDom(element.getDocument()).getDocumentElement();
	}

	/**
	 * Converts a W3 DOM Element to a JDOM Element
	 *
	 * @param e W3 DOM Element
	 * @return JDOM Element
	 */
	public static org.jdom.Element toJdom(org.w3c.dom.Element e) {
		DOMBuilder builder = new DOMBuilder();
		org.jdom.Element jdomElem = builder.build(e);
		return jdomElem;
	}

	/**
	 * Creates a JDOM Document from a string containing XML
	 *
	 * @param samlRequestString String version of XML
	 * @return JDOM Document if file contents converted successfully, null
	 * otherwise
	 */
	public static Document createJdomDoc(String xmlString) throws SamlException {
		try {
			SAXBuilder builder = new SAXBuilder();
			Document doc = builder.build(new ByteArrayInputStream(xmlString
					.getBytes()));
			return doc;
		} catch (IOException e) {
			throw new SamlException(
					"Error creating JDOM document from XML string: "
							+ e.getMessage());
		} catch (JDOMException e) {
			throw new SamlException(
					"Error creating JDOM document from XML string: "
							+ e.getMessage());
		}
	}

	/**
	 * Creates a PublicKey from the specified public key file and algorithm.
	 * Returns null if failure to generate PublicKey.
	 *
	 * @param publicKeyFilepath location of public key file
	 * @param algorithm         algorithm of specified key file
	 * @return PublicKey object representing contents of specified public key
	 * file, null if error in generating key or invalid file specified
	 */
	public static PublicKey getPublicKey(String publicKeyFilepath,
										 String algorithm) throws SamlException {

		FileInputStream is = null;

		try {
			CertificateFactory fact = CertificateFactory.getInstance("X.509");
			is = new FileInputStream (publicKeyFilepath);
			X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
			return cer.getPublicKey();

		} catch (FileNotFoundException e) {
			throw new SamlException("ERROR: Public key file not found - "
					+ publicKeyFilepath);
		} catch (IOException e) {
			throw new SamlException("ERROR: Invalid public key file - "
					+ e.getMessage());
		} catch (CertificateException e) {
			throw new RuntimeException(e);
		} finally {
			if(is != null) {
				try {
					is.close();
				} catch (IOException e) {
					e.printStackTrace();;
				}
			}
		}
	}

	/**
	 * Creates a PrivateKey from the specified public key file and algorithm.
	 * Returns null if failure to generate PrivateKey.
	 *
	 * @param PrivateKeyFilepath location of public key file
	 * @param algorithm          algorithm of specified key file
	 * @return PrivateKey object representing contents of specified private key
	 * file, null if error in generating key or invalid file specified
	 */
	public static PrivateKey getPrivateKey(String privateKeyFilepath,
										   String algorithm) throws SamlException {
		try {

			byte[] bytes = Files.readAllBytes(Paths.get(privateKeyFilepath));

			PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(bytes);

			KeyFactory factory = KeyFactory.getInstance(algorithm);

			return factory.generatePrivate(privSpec);

		} catch (FileNotFoundException e) {
			e.printStackTrace();
			throw new SamlException("ERROR: Private key file not found - "
					+ privateKeyFilepath);
		} catch (IOException e) {
			e.printStackTrace();
			throw new SamlException("ERROR: Invalid private key file - "
					+ e.getMessage());
		} catch (Exception e) {
			e.printStackTrace();
			throw new SamlException(e.getMessage());
		}
	}

	/**
	 * Create a randomly generated string conforming to the xsd:ID datatype.
	 * containing 160 bits of non-cryptographically strong pseudo-randomness, as
	 * suggested by SAML 2.0 core 1.2.3. This will also apply to version 1.1
	 *
	 * @return the randomly generated string
	 */
	public static String createID() {
		byte[] bytes = new byte[20]; // 160 bits
		random.nextBytes(bytes);

		char[] chars = new char[40];

		for (int i = 0; i < bytes.length; i++) {
			int left = (bytes[i] >> 4) & 0x0f;
			int right = bytes[i] & 0x0f;
			chars[i * 2] = charMapping[left];
			chars[i * 2 + 1] = charMapping[right];
		}

		return String.valueOf(chars);
	}

	/**
	 * Gets the current date and time in the format specified by xsd:dateTime in
	 * UTC form, as described in SAML 2.0 core 1.2.2 This will also apply to
	 * Version 1.1
	 *
	 * @return the date and time as a String
	 */
	public static String getDateAndTime() {
		SimpleDateFormat dayFormat = new SimpleDateFormat("yyyy-MM-dd");
		SimpleDateFormat timeFormat = new SimpleDateFormat("HH:mm:ss");

		Date date = new Date();
		return dayFormat.format(date) + 'T' + timeFormat.format(date) + 'Z';
	}
}
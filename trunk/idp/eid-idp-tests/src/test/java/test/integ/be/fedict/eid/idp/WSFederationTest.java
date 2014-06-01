/*
 * eID Identity Provider Project.
 * Copyright (C) 2012 FedICT.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License version
 * 3.0 as published by the Free Software Foundation.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, see 
 * http://www.gnu.org/licenses/.
 */

package test.integ.be.fedict.eid.idp;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.InputStream;
import java.io.StringWriter;
import java.security.cert.X509Certificate;

import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.Init;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.easymock.EasyMock;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import be.fedict.eid.idp.sp.protocol.ws_federation.AuthenticationResponseProcessor;
import be.fedict.eid.idp.sp.protocol.ws_federation.spi.AuthenticationResponseService;
import be.fedict.eid.idp.sp.protocol.ws_federation.spi.ValidationService;
import be.fedict.eid.idp.sp.protocol.ws_federation.sts.SecurityTokenServiceClient;

public class WSFederationTest {

	private static final Log LOG = LogFactory.getLog(WSFederationTest.class);

	@BeforeClass
	public static void beforeClass() {
		Init.init();
	}

	@Test
	public void testSAML2AssertionTokenSignature() throws Exception {
		InputStream documentInputStream = WSFederationTest.class
				.getResourceAsStream("/eid-idp-ws-fed-response.xml");
		assertNotNull(documentInputStream);

		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory
				.newDocumentBuilder();
		Document wsFedDocument = documentBuilder.parse(documentInputStream);

		NodeList assertionNodeList = wsFedDocument.getElementsByTagNameNS(
				"urn:oasis:names:tc:SAML:2.0:assertion", "Assertion");
		assertEquals(1, assertionNodeList.getLength());

		Element assertionElement = (Element) assertionNodeList.item(0);

		Document tokenDocument = documentBuilder.newDocument();
		Node assertionTokenNode = tokenDocument.importNode(assertionElement,
				true);
		tokenDocument.appendChild(assertionTokenNode);
		LOG.debug("assertion token: " + toString(tokenDocument));

		NodeList signatureNodeList = tokenDocument.getElementsByTagNameNS(
				"http://www.w3.org/2000/09/xmldsig#", "Signature");
		assertEquals(1, signatureNodeList.getLength());

		Element signatureElement = (Element) signatureNodeList.item(0);
		XMLSignature xmlSignature = new XMLSignature(signatureElement, "");
		KeyInfo keyInfo = xmlSignature.getKeyInfo();
		X509Certificate certificate = keyInfo.getX509Certificate();
		boolean result = xmlSignature.checkSignatureValue(certificate);
		assertTrue(result);
	}

	@Test
	public void testSecurityTokenServiceClient() throws Exception {
		SecurityTokenServiceClient securityTokenServiceClient = new SecurityTokenServiceClient(
				"http://localhost/eid-idp/ws/sts");

		InputStream documentInputStream = WSFederationTest.class
				.getResourceAsStream("/eid-idp-ws-fed-response.xml");
		assertNotNull(documentInputStream);

		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory
				.newDocumentBuilder();
		Document wsFedDocument = documentBuilder.parse(documentInputStream);

		NodeList assertionNodeList = wsFedDocument.getElementsByTagNameNS(
				"urn:oasis:names:tc:SAML:2.0:assertion", "Assertion");
		assertEquals(1, assertionNodeList.getLength());

		Element assertionElement = (Element) assertionNodeList.item(0);

		securityTokenServiceClient.validateToken(assertionElement,
				"https://www.e-contract.be:443/eid-idp-sp/wsfed-landing");
	}

	@Test
	public void testAuthenticationResponseProcessorWithValidationService()
			throws Exception {
		// setup
		AuthenticationResponseService mockAuthenticationResponseService = EasyMock
				.createMock(AuthenticationResponseService.class);
		AuthenticationResponseProcessor authenticationResponseProcessor = new AuthenticationResponseProcessor(
				mockAuthenticationResponseService);

		EasyMock.expect(
				mockAuthenticationResponseService.getAttributeSecretKey())
				.andStubReturn(null);
		EasyMock.expect(
				mockAuthenticationResponseService.getAttributePrivateKey())
				.andStubReturn(null);
		EasyMock.expect(
				mockAuthenticationResponseService.getMaximumTimeOffset())
				.andStubReturn(-1);
		EasyMock.expect(
				mockAuthenticationResponseService.requiresResponseSignature())
				.andStubReturn(true);

		ValidationService mockValidationService = EasyMock
				.createMock(ValidationService.class);

		EasyMock.expect(
				mockAuthenticationResponseService.getValidationService())
				.andStubReturn(mockValidationService);

		EasyMock.expect(mockValidationService.getLocation()).andStubReturn(
				"http://localhost:8080/eid-idp/ws/sts");

		HttpServletRequest mockHttpServletRequest = EasyMock
				.createMock(HttpServletRequest.class);

		mockHttpServletRequest.setCharacterEncoding("UTF8");

		EasyMock.expect(mockHttpServletRequest.getParameter("wa"))
				.andStubReturn("wsignin1.0");

		EasyMock.expect(mockHttpServletRequest.getParameter("wctx"))
				.andStubReturn(null);

		InputStream wsFedResponseInputStream = WSFederationTest.class
				.getResourceAsStream("/eid-idp-ws-fed-response.xml");
		assertNotNull(wsFedResponseInputStream);
		String wresult = IOUtils.toString(wsFedResponseInputStream);
		EasyMock.expect(mockHttpServletRequest.getParameter("wresult"))
				.andStubReturn(wresult);

		// prepare
		EasyMock.replay(mockAuthenticationResponseService,
				mockHttpServletRequest, mockValidationService);

		// operate
		authenticationResponseProcessor.process(
				"https://www.e-contract.be:443/eid-idp-sp/wsfed-landing", null,
				true, mockHttpServletRequest);

		// verify
		EasyMock.verify(mockAuthenticationResponseService,
				mockHttpServletRequest, mockValidationService);
	}

	static String toString(Node dom) throws TransformerException {
		Source source = new DOMSource(dom);
		StringWriter stringWriter = new StringWriter();
		Result result = new StreamResult(stringWriter);
		TransformerFactory transformerFactory = TransformerFactory
				.newInstance();
		Transformer transformer = transformerFactory.newTransformer();
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		transformer.transform(source, result);
		return stringWriter.getBuffer().toString();
	}
}

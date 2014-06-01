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

package test.unit.be.fedict.eid.idp.protocol.ws_federation.sts;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import javax.annotation.Resource;
import javax.servlet.ServletContext;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.Unmarshaller;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.easymock.EasyMock;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import be.fedict.eid.idp.protocol.ws_federation.sts.SecurityTokenServicePortImpl;
import be.fedict.eid.idp.protocol.ws_federation.sts.WSSecuritySoapHandler;
import be.fedict.eid.idp.spi.IdentityProviderConfiguration;
import be.fedict.eid.idp.spi.IdentityProviderConfigurationFactory;
import be.fedict.eid.idp.wstrust.WSTrustConstants;
import be.fedict.eid.idp.wstrust.jaxb.wstrust.ObjectFactory;
import be.fedict.eid.idp.wstrust.jaxb.wstrust.RequestSecurityTokenResponseCollectionType;
import be.fedict.eid.idp.wstrust.jaxb.wstrust.RequestSecurityTokenResponseType;
import be.fedict.eid.idp.wstrust.jaxb.wstrust.RequestSecurityTokenType;
import be.fedict.eid.idp.wstrust.jaxb.wstrust.StatusType;

public class SecurityTokenServicePortImplTest {

	private static final Log LOG = LogFactory
			.getLog(SecurityTokenServicePortImplTest.class);

	@Test
	public void testValidation() throws Exception {
		// setup
		InputStream requestInputStream = SecurityTokenServicePortImplTest.class
				.getResourceAsStream("/sts-validation-request.xml");
		assertNotNull(requestInputStream);

		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory
				.newDocumentBuilder();
		Document document = documentBuilder.parse(requestInputStream);

		Element requestSecurityTokenElement = (Element) document
				.getElementsByTagNameNS(
						"http://docs.oasis-open.org/ws-sx/ws-trust/200512",
						"RequestSecurityToken").item(0);

		Element x509Certificate = (Element) document.getElementsByTagNameNS(
				"http://www.w3.org/2000/09/xmldsig#", "X509Certificate")
				.item(0);
		CertificateFactory certificateFactory = CertificateFactory
				.getInstance("X.509");
		X509Certificate certificate = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(Base64
						.decodeBase64(x509Certificate.getFirstChild()
								.getNodeValue())));
		List<X509Certificate> certificateChain = Collections
				.singletonList(certificate);

		JAXBContext jaxbContext = JAXBContext.newInstance(ObjectFactory.class,
				be.fedict.eid.idp.wstrust.jaxb.wspolicy.ObjectFactory.class,
				be.fedict.eid.idp.wstrust.jaxb.wsaddr.ObjectFactory.class);
		Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();

		JAXBElement<RequestSecurityTokenType> resultElement = (JAXBElement<RequestSecurityTokenType>) unmarshaller
				.unmarshal(requestSecurityTokenElement);
		RequestSecurityTokenType requestSecurityToken = resultElement
				.getValue();

		SecurityTokenServicePortImpl testedInstance = new SecurityTokenServicePortImpl();

		WebServiceContext mockWebServiceContext = EasyMock
				.createMock(WebServiceContext.class);
		injectResource(mockWebServiceContext, testedInstance);

		MessageContext mockMessageContext = EasyMock
				.createMock(MessageContext.class);

		EasyMock.expect(mockWebServiceContext.getMessageContext())
				.andStubReturn(mockMessageContext);

		ServletContext mockServletContext = EasyMock
				.createMock(ServletContext.class);

		EasyMock.expect(mockMessageContext.get(MessageContext.SERVLET_CONTEXT))
				.andReturn(mockServletContext);

		IdentityProviderConfiguration mockIdentityProviderConfiguration = EasyMock
				.createMock(IdentityProviderConfiguration.class);

		EasyMock.expect(
				mockServletContext
						.getAttribute(IdentityProviderConfigurationFactory.IDENTITY_PROVIDER_CONFIGURATION_CONTEXT_ATTRIBUTE))
				.andReturn(mockIdentityProviderConfiguration);

		EasyMock.expect(
				mockIdentityProviderConfiguration.getIdentityCertificateChain())
				.andReturn(certificateChain);

		EasyMock.expect(mockIdentityProviderConfiguration.getDefaultIssuer())
				.andReturn("e-contract-2012");

		Element samlElement = (Element) document.getElementsByTagNameNS(
				WSTrustConstants.SAML2_NAMESPACE, "Assertion").item(0);
		EasyMock.expect(
				mockMessageContext.get(WSSecuritySoapHandler.class.getName()
						+ ".samlToken")).andStubReturn(samlElement);

		// prepare
		EasyMock.replay(mockWebServiceContext, mockMessageContext,
				mockServletContext, mockIdentityProviderConfiguration);

		// operate
		RequestSecurityTokenResponseCollectionType result = testedInstance
				.requestSecurityToken(requestSecurityToken);

		// verify
		EasyMock.verify(mockWebServiceContext, mockMessageContext,
				mockServletContext, mockIdentityProviderConfiguration);
		assertNotNull(result);

		List<RequestSecurityTokenResponseType> resultList = result
				.getRequestSecurityTokenResponse();
		assertEquals(1, resultList.size());
		RequestSecurityTokenResponseType requestSecurityTokenResponse = resultList
				.get(0);
		List<Object> responseObjects = requestSecurityTokenResponse.getAny();
		boolean valid = false;
		String reason = null;
		for (Object responseObject : responseObjects) {
			LOG.debug("response object type: " + responseObject);
			if (responseObject instanceof JAXBElement) {
				JAXBElement jaxbElement = (JAXBElement) responseObject;
				QName qname = jaxbElement.getName();
				LOG.debug("qname: " + qname);
				if (new QName(WSTrustConstants.WS_TRUST_NAMESPACE, "Status")
						.equals(qname)) {
					StatusType status = (StatusType) jaxbElement.getValue();
					String code = status.getCode();
					LOG.debug("status code: " + code);
					if (WSTrustConstants.VALID_STATUS_CODE.equals(code)) {
						valid = true;
					}
					reason = status.getReason();
				}
			}
		}
		LOG.debug("status reason: " + reason);
		assertTrue(reason.indexOf("policy") != -1);
	}

	private void injectResource(WebServiceContext webServiceContext, Object bean)
			throws IllegalArgumentException, IllegalAccessException {
		Field[] fields = bean.getClass().getDeclaredFields();
		for (Field field : fields) {
			Resource resourceAnnotation = field.getAnnotation(Resource.class);
			if (null != resourceAnnotation) {
				field.setAccessible(true);
				field.set(bean, webServiceContext);
			}
		}
	}
}

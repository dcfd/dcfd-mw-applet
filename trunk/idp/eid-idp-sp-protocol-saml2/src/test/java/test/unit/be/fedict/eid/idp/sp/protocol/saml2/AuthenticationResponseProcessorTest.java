/*
 * eID Identity Provider Project.
 * Copyright (C) 2010 FedICT.
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

package test.unit.be.fedict.eid.idp.sp.protocol.saml2;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;
import javax.xml.namespace.QName;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.utils.Base64;
import org.joda.time.DateTime;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.OneTimeUse;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.xml.util.IndexedXMLObjectChildrenList;
import org.w3c.dom.Element;

import be.fedict.eid.idp.common.Attribute;
import be.fedict.eid.idp.common.AttributeType;
import be.fedict.eid.idp.common.SamlAuthenticationPolicy;
import be.fedict.eid.idp.common.saml2.AuthenticationResponse;
import be.fedict.eid.idp.common.saml2.Saml2Util;
import be.fedict.eid.idp.sp.protocol.saml2.AuthenticationResponseProcessorException;
import be.fedict.eid.idp.sp.protocol.saml2.post.AuthenticationResponseProcessor;
import be.fedict.eid.idp.sp.protocol.saml2.spi.AuthenticationResponseService;

public class AuthenticationResponseProcessorTest {

	private static final Log LOG = LogFactory
			.getLog(AuthenticationResponseProcessorTest.class);

	private AuthenticationResponseService mockAuthenticationResponseService;
	private HttpServletRequest mockHttpServletRequest;

	@Before
	public void setUp() throws Exception {

		this.mockAuthenticationResponseService = createMock(AuthenticationResponseService.class);
		this.mockHttpServletRequest = createMock(HttpServletRequest.class);
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testPostSamlResponse() throws Exception {

		// Setup
		String userId = UUID.randomUUID().toString();
		String attributeName = "urn:test:attribute";
		Attribute attribute = new Attribute(attributeName,
				AttributeType.STRING, UUID.randomUUID().toString());
		Map<String, Attribute> attributes = new HashMap<String, Attribute>();
		attributes.put(attributeName, attribute);

		String issuerName = "test-issuer";

		String requestId = UUID.randomUUID().toString();
		String audience = "request-issuer";
		String recipient = "http://www.testsp.com/saml";
		String relayState = "test-relay-state";

		Response samlResponse = Saml2Util.getResponse(requestId, recipient,
				issuerName);

		Assertion assertion = Saml2Util.getAssertion(issuerName, requestId,
				audience, recipient, 5, samlResponse.getIssueInstant(),
				SamlAuthenticationPolicy.IDENTIFICATION, userId, attributes,
				null, null);
		samlResponse.getAssertions().add(assertion);

		Element samlResponseElement = Saml2Util.marshall(samlResponse);
		String encodedSamlResponse = Base64.encode(Saml2Util.domToString(
				samlResponseElement, true).getBytes());

		AuthenticationResponseProcessor responseProcessor = new AuthenticationResponseProcessor(
				mockAuthenticationResponseService);

		// Expectations
		expect(mockHttpServletRequest.getMethod()).andReturn("POST");
		expect(mockHttpServletRequest.getParameter("SAMLRequest")).andReturn(
				null);
		expect(mockHttpServletRequest.getParameter("SAMLResponse")).andReturn(
				encodedSamlResponse);
		expect(mockHttpServletRequest.getParameter("RelayState")).andReturn(
				relayState).times(2);
		expect(mockHttpServletRequest.getRequestURL()).andReturn(
				new StringBuffer(recipient));

		expect(mockAuthenticationResponseService.getMaximumTimeOffset())
				.andReturn(5);
		expect(mockAuthenticationResponseService.getAttributeSecretKey())
				.andReturn(null);
		expect(mockAuthenticationResponseService.getAttributePrivateKey())
				.andReturn(null);
		expect(mockAuthenticationResponseService.requiresResponseSignature())
				.andReturn(false);

		replay(mockAuthenticationResponseService, mockHttpServletRequest);

		// Operate
		AuthenticationResponse authenticationResponse = responseProcessor
				.process(requestId, audience, recipient, relayState, false,
						mockHttpServletRequest);

		// Verify
		verify(mockAuthenticationResponseService, mockHttpServletRequest);

		assertNotNull(authenticationResponse);
		assertEquals(userId, authenticationResponse.getIdentifier());
		assertEquals(relayState, authenticationResponse.getRelayState());
		assertEquals(SamlAuthenticationPolicy.IDENTIFICATION,
				authenticationResponse.getAuthenticationPolicy());
		assertNotNull(authenticationResponse.getAssertion());
		assertNotNull(authenticationResponse.getAuthenticationTime());
		assertNotNull(authenticationResponse.getAttributeMap());
		assertEquals(1, authenticationResponse.getAttributeMap().size());
		assertEquals(attribute.getValue(), authenticationResponse
				.getAttributeMap().get(attributeName));
	}

	@Test
	public void testPostSamlResponseInvalidInResponseTo() throws Exception {

		new ProcessingFailTest() {

			@Override
			protected void modifyResponse(Response response) {
				response.setInResponseTo("Foo");
			}
		}.doTest();
	}

	@Test
	public void testPostSamlResponseFailedStatus() throws Exception {

		new ProcessingFailTest() {

			@Override
			protected void modifyResponse(Response response) {
				response.getStatus().getStatusCode()
						.setValue(StatusCode.AUTHN_FAILED_URI);
			}
		}.doTest();
	}

	@Test
	public void testPostSamlResponseNoAssertion() throws Exception {

		new ProcessingFailTest() {

			@Override
			protected void modifyResponse(Response response) {
				response.getAssertions().clear();
			}
		}.doTest();
	}

	@Test
	public void testPostSamlResponseMissingAuthnStatement() throws Exception {

		new ProcessingFailTest() {

			@Override
			protected void modifyResponse(Response response) {
				response.getAssertions().get(0).getAuthnStatements().clear();
			}
		}.doTest();
	}

	@Test
	public void testPostSamlResponseMissingAuthnContext() throws Exception {

		new ProcessingFailTest() {

			@Override
			protected void modifyResponse(Response response) {
				response.getAssertions().get(0).getAuthnStatements().get(0)
						.setAuthnContext(null);
			}
		}.doTest();
	}

	@Test
	public void testPostSamlResponseMissingAuthnContextRef() throws Exception {

		new ProcessingFailTest() {

			@Override
			protected void modifyResponse(Response response) {
				response.getAssertions().get(0).getAuthnStatements().get(0)
						.getAuthnContext().setAuthnContextClassRef(null);
			}
		}.doTest();
	}

	@Test
	public void testPostSamlResponseMissingSubjectConfirmation()
			throws Exception {

		new ProcessingFailTest() {

			@Override
			protected void modifyResponse(Response response) {
				response.getAssertions().get(0).getSubject()
						.getSubjectConfirmations().clear();
			}
		}.doTest();
	}

	@Test
	public void testPostSamlResponseWrongSubjectConfirmationMethod()
			throws Exception {

		new ProcessingFailTest() {

			@Override
			protected void modifyResponse(Response response) {
				response.getAssertions().get(0).getSubject()
						.getSubjectConfirmations().get(0)
						.setMethod(SubjectConfirmation.METHOD_HOLDER_OF_KEY);
			}
		}.doTest();
	}

	@Test
	public void testPostSamlResponseWrongSubjectConfirmationDataInResponseTo()
			throws Exception {

		new ProcessingFailTest() {

			@Override
			protected void modifyResponse(Response response) {
				response.getAssertions().get(0).getSubject()
						.getSubjectConfirmations().get(0)
						.getSubjectConfirmationData().setInResponseTo("foo");
			}
		}.doTest();
	}

	@Test
	public void testPostSamlResponseWrongSubjectConfirmationDataRecipient()
			throws Exception {

		new ProcessingFailTest() {

			@Override
			protected void modifyResponse(Response response) {
				response.getAssertions().get(0).getSubject()
						.getSubjectConfirmations().get(0)
						.getSubjectConfirmationData().setRecipient("foo");
			}
		}.doTest();
	}

	@Test
	public void testPostSamlResponseWrongSubjectConfirmationDataTime()
			throws Exception {

		new ProcessingFailTest() {

			@Override
			protected void modifyResponse(Response response) {
				response.getAssertions().get(0).getSubject()
						.getSubjectConfirmations().get(0)
						.getSubjectConfirmationData()
						.setNotOnOrAfter(new DateTime().minusDays(1));
				response.getAssertions().get(0).getSubject()
						.getSubjectConfirmations().get(0)
						.getSubjectConfirmationData()
						.setNotBefore(new DateTime().minusDays(2));
			}
		}.doTest();
	}

	@Test
	public void testPostSamlResponseWrongConditionsTime() throws Exception {

		new ProcessingFailTest() {

			@Override
			protected void modifyResponse(Response response) {
				response.getAssertions().get(0).getConditions()
						.setNotOnOrAfter(new DateTime().minusDays(1));
				response.getAssertions().get(0).getConditions()
						.setNotBefore(new DateTime().minusDays(2));
			}
		}.doTest();
	}

	@Test
	public void testPostSamlResponseNoAudienceRestriction() throws Exception {

		new ProcessingFailTest() {

			@Override
			protected void modifyResponse(Response response) {
				response.getAssertions().get(0).getConditions()
						.getAudienceRestrictions().clear();
			}
		}.doTest();
	}

	@Test
	public void testPostSamlResponseNoAudience() throws Exception {

		new ProcessingFailTest() {

			@Override
			protected void modifyResponse(Response response) {
				response.getAssertions().get(0).getConditions()
						.getAudienceRestrictions().get(0).getAudiences()
						.clear();
			}
		}.doTest();
	}

	@Test
	public void testPostSamlResponseWrongAudience() throws Exception {

		new ProcessingFailTest() {

			@Override
			protected void modifyResponse(Response response) {
				response.getAssertions().get(0).getConditions()
						.getAudienceRestrictions().get(0).getAudiences().get(0)
						.setAudienceURI("foo");
			}
		}.doTest();
	}

	@Test
	public void testPostSamlResponseNoOneTimeUse() throws Exception {

		new ProcessingFailTest() {

			@Override
			protected void modifyResponse(Response response) {

				QName oneTimeUseQName = new QName(SAMLConstants.SAML20_NS,
						OneTimeUse.DEFAULT_ELEMENT_LOCAL_NAME,
						SAMLConstants.SAML20_PREFIX);

				List oneTimeUseList = ((IndexedXMLObjectChildrenList) (response
						.getAssertions().get(0).getConditions().getConditions()))
						.subList(oneTimeUseQName);

				response.getAssertions().get(0).getConditions().getConditions()
						.remove(oneTimeUseList.get(0));
			}
		}.doTest();
	}

	@Test
	public void testPostSamlResponseExpectSignatureButNoneFound()
			throws Exception {

		new ProcessingFailTest() {

			@Override
			protected void modifyResponse(Response response) {

			}
		}.doTest(true);
	}

	abstract class ProcessingFailTest {

		public void doTest() {

			doTest(false);
		}

		public void doTest(boolean expectResponseSigned) {

			// Setup
			String userId = UUID.randomUUID().toString();
			String attributeName = "urn:test:attribute";
			Attribute attribute = new Attribute(attributeName,
					AttributeType.STRING, UUID.randomUUID().toString());
			Map<String, Attribute> attributes = new HashMap<String, Attribute>();
			attributes.put(attributeName, attribute);

			String issuerName = "test-issuer";

			String requestId = UUID.randomUUID().toString();
			String audience = "request-issuer";
			String recipient = "http://www.testsp.com/saml";
			String relayState = "test-relay-state";

			Response samlResponse = Saml2Util.getResponse(requestId, recipient,
					issuerName);

			Assertion assertion = Saml2Util.getAssertion(issuerName, requestId,
					audience, recipient, 5, samlResponse.getIssueInstant(),
					SamlAuthenticationPolicy.IDENTIFICATION, userId,
					attributes, null, null);
			samlResponse.getAssertions().add(assertion);

			// callback to modify assertion for failure
			modifyResponse(samlResponse);

			Element samlResponseElement = Saml2Util.marshall(samlResponse);
			String encodedSamlResponse = Base64.encode(Saml2Util.domToString(
					samlResponseElement, true).getBytes());

			AuthenticationResponseProcessor responseProcessor = new AuthenticationResponseProcessor(
					mockAuthenticationResponseService);

			// Expectations
			expect(mockHttpServletRequest.getMethod()).andReturn("POST");
			expect(mockHttpServletRequest.getParameter("SAMLRequest"))
					.andReturn(null);
			expect(mockHttpServletRequest.getParameter("SAMLResponse"))
					.andReturn(encodedSamlResponse);
			expect(mockHttpServletRequest.getParameter("RelayState"))
					.andReturn(relayState).anyTimes();
			expect(mockHttpServletRequest.getRequestURL()).andReturn(
					new StringBuffer(recipient));

			expect(mockAuthenticationResponseService.getMaximumTimeOffset())
					.andReturn(5);
			expect(mockAuthenticationResponseService.getAttributeSecretKey())
					.andReturn(null);
			expect(mockAuthenticationResponseService.getAttributePrivateKey())
					.andReturn(null);
			expect(
					mockAuthenticationResponseService
							.requiresResponseSignature()).andReturn(
					expectResponseSigned);

			replay(mockAuthenticationResponseService, mockHttpServletRequest);

			try {
				responseProcessor.process(requestId, audience, recipient, null,
						null, mockHttpServletRequest);
				fail();
			} catch (AuthenticationResponseProcessorException e) {
				// expected
				LOG.error("Expected failure: " + e.getMessage());
			}

			// Verify
			verify(mockAuthenticationResponseService, mockHttpServletRequest);

		}

		protected abstract void modifyResponse(Response response);

	}

}

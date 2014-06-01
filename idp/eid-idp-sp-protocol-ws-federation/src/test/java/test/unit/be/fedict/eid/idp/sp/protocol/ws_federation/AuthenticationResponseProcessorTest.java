/*
 * eID Identity Provider Project.
 * Copyright (C) 2011 FedICT.
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

package test.unit.be.fedict.eid.idp.sp.protocol.ws_federation;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.easymock.Capture;
import org.easymock.EasyMock;
import org.junit.Test;

import be.fedict.eid.idp.common.SamlAuthenticationPolicy;
import be.fedict.eid.idp.common.saml2.AuthenticationResponse;
import be.fedict.eid.idp.sp.protocol.ws_federation.AuthenticationResponseProcessor;
import be.fedict.eid.idp.sp.protocol.ws_federation.AuthenticationResponseProcessorException;
import be.fedict.eid.idp.sp.protocol.ws_federation.spi.AuthenticationResponseService;

public class AuthenticationResponseProcessorTest {

	private static final Log LOG = LogFactory
			.getLog(AuthenticationResponseProcessorTest.class);

	@Test
	public void testResponse() throws Exception {
		// setup

		String wsFederationResponse = IOUtils
				.toString(AuthenticationResponseProcessorTest.class
						.getResourceAsStream("/ws-federation-response.xml"));
		AuthenticationResponseService mockService = EasyMock
				.createMock(AuthenticationResponseService.class);
		AuthenticationResponseProcessor testedInstance = new AuthenticationResponseProcessor(
				mockService);
		HttpServletRequest mockRequest = EasyMock
				.createMock(HttpServletRequest.class);

		EasyMock.expect(mockService.requiresResponseSignature())
				.andReturn(true);
		EasyMock.expect(mockService.getAttributeSecretKey())
				.andStubReturn(null);
		EasyMock.expect(mockService.getAttributePrivateKey()).andStubReturn(
				null);
		EasyMock.expect(mockService.getMaximumTimeOffset()).andStubReturn(-1);
		EasyMock.expect(mockService.getValidationService()).andStubReturn(null);

		mockRequest.setCharacterEncoding("UTF8");
		EasyMock.expect(mockRequest.getParameter("wa")).andStubReturn(
				"wsignin1.0");
		EasyMock.expect(mockRequest.getParameter("wctx")).andStubReturn(null);
		EasyMock.expect(mockRequest.getParameter("wresult")).andStubReturn(
				wsFederationResponse);

		Capture<SamlAuthenticationPolicy> policyCapture = new Capture<SamlAuthenticationPolicy>();
		Capture<List<X509Certificate>> chainCapture = new Capture<List<X509Certificate>>();
		mockService.validateServiceCertificate(EasyMock.capture(policyCapture),
				EasyMock.capture(chainCapture));

		// prepare
		EasyMock.replay(mockService, mockRequest);

		// operate
		AuthenticationResponse response = testedInstance.process(
				"https://www.e-contract.be:443/eid-idp-sp/wsfed-landing", null,
				true, mockRequest);

		// verify
		EasyMock.verify(mockService, mockRequest);
		assertNotNull(response);
		LOG.debug("identifier: " + response.getIdentifier());
		assertEquals("79102520991", response.getIdentifier());
		SamlAuthenticationPolicy responsePolicy = response
				.getAuthenticationPolicy();
		LOG.debug("policy: " + responsePolicy.getUri());
		assertEquals("urn:be:fedict:eid:idp:AuthenticationWithIdentification",
				responsePolicy.getUri());
		Map<String, Object> responseAttributes = response.getAttributeMap();
		LOG.debug("attributes: " + responseAttributes);
		assertEquals(
				"Vilvoorde",
				responseAttributes
						.get("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/locality"));
	}

	@Test
	public void testBrokenSignature() throws Exception {
		// setup

		String wsFederationResponse = IOUtils
				.toString(AuthenticationResponseProcessorTest.class
						.getResourceAsStream("/ws-federation-response-broken-signature.xml"));
		AuthenticationResponseService mockService = EasyMock
				.createMock(AuthenticationResponseService.class);
		AuthenticationResponseProcessor testedInstance = new AuthenticationResponseProcessor(
				mockService);
		HttpServletRequest mockRequest = EasyMock
				.createMock(HttpServletRequest.class);

		EasyMock.expect(mockService.requiresResponseSignature())
				.andReturn(true);
		EasyMock.expect(mockService.getAttributeSecretKey())
				.andStubReturn(null);
		EasyMock.expect(mockService.getAttributePrivateKey()).andStubReturn(
				null);
		EasyMock.expect(mockService.getMaximumTimeOffset()).andStubReturn(-1);
		EasyMock.expect(mockService.getValidationService()).andStubReturn(null);

		mockRequest.setCharacterEncoding("UTF8");
		EasyMock.expect(mockRequest.getParameter("wa")).andStubReturn(
				"wsignin1.0");
		EasyMock.expect(mockRequest.getParameter("wctx")).andStubReturn(null);
		EasyMock.expect(mockRequest.getParameter("wresult")).andStubReturn(
				wsFederationResponse);

		// prepare
		EasyMock.replay(mockService, mockRequest);

		// operate & verify
		try {
			testedInstance.process(
					"https://www.e-contract.be:443/eid-idp-sp/wsfed-landing",
					null, true, mockRequest);
			fail();
		} catch (AuthenticationResponseProcessorException ex) {
			// expected
			EasyMock.verify(mockService, mockRequest);
			LOG.debug("expected exception message: " + ex.getMessage());
		}
	}
}

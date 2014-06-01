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

package be.fedict.eid.idp.sp.protocol.saml2;

import java.lang.reflect.Method;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.crypto.SecretKey;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;

import be.fedict.eid.idp.common.saml2.AssertionValidationException;
import be.fedict.eid.idp.common.saml2.AuthenticationResponse;
import be.fedict.eid.idp.common.saml2.Saml2Util;
import be.fedict.eid.idp.sp.protocol.saml2.spi.AuthenticationResponseService;

/**
 * Processor for SAML v2.0 Responses, used by
 * {@link AbstractAuthenticationResponseServlet}
 * <p/>
 * Will process the SAML v2.0 Response returned by the HTTP-POST
 * {@link be.fedict.eid.idp.sp.protocol.saml2.post.AuthenticationResponseProcessor}
 * and HTTP-Arfifact
 * {@link be.fedict.eid.idp.sp.protocol.saml2.artifact.AuthenticationResponseProcessor}
 * implementations of this processor.
 * <p/>
 * On complete of this response, will returned an {@link AuthenticationResponse}
 * containing all available details of the authenticated subject.
 * 
 * @author Frank Cornelis
 * @author Wim Vandenhaute
 */
public abstract class AbstractAuthenticationResponseProcessor {

	private static final String RELAY_STATE_PARAM = "RelayState";

	protected static final Log LOG = LogFactory
			.getLog(AbstractAuthenticationResponseProcessor.class);

	static {
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			throw new RuntimeException(
					"could not bootstrap the OpenSAML2 library", e);
		}
	}

	/**
	 * Process the incoming SAML v2.0 response.
	 * 
	 * @param requestId
	 *            AuthnRequest.ID, should match response's InResponseTo
	 * @param audience
	 *            expected audience
	 * @param recipient
	 *            recipient, should match response's
	 *            Subject.SubjectConfirmation.Recipient
	 * @param relayState
	 *            optional expected relay state
	 * @param requiresResponseSignature
	 *            do we expect a signature on the response or not, or
	 *            <code>null</code> if to be retrieved from the
	 *            {@link AuthenticationResponseService}.
	 * @param request
	 *            the HTTP servlet request that holds the SAML2 response.
	 * @return the SAML2 {@link AuthenticationResponse}
	 * @throws AuthenticationResponseProcessorException
	 *             case something went wrong
	 */
	public AuthenticationResponse process(String requestId, String audience,
			String recipient, String relayState,
			Boolean requiresResponseSignature, HttpServletRequest request)
			throws AuthenticationResponseProcessorException {

		Response samlResponse = getSamlResponse(request);
		DateTime now = new DateTime();
		SecretKey secretKey = null;
		PrivateKey privateKey = null;
		int maxOffset = 5;
		boolean expectResponseSigned = null != requiresResponseSignature ? requiresResponseSignature
				: false;

		AuthenticationResponseService service = getAuthenticationResponseService();
		if (null != service) {
			secretKey = service.getAttributeSecretKey();
			privateKey = service.getAttributePrivateKey();
			maxOffset = service.getMaximumTimeOffset();
			expectResponseSigned = service.requiresResponseSignature();
		}

		// validate InResponseTo
		if (!samlResponse.getInResponseTo().equals(requestId)) {

			throw new AuthenticationResponseProcessorException(
					"SAML Response not belonging to AuthnRequest!");
		}

		// validate status
		Status status = samlResponse.getStatus();
		StatusCode statusCode = status.getStatusCode();
		String statusValue = statusCode.getValue();
		if (!StatusCode.SUCCESS_URI.equals(statusValue)) {
			throw new AuthenticationResponseProcessorException(
					"no successful SAML response");
		}

		List<Assertion> assertions = samlResponse.getAssertions();
		if (assertions.isEmpty()) {
			throw new AuthenticationResponseProcessorException(
					"missing SAML assertions");
		}

		Assertion assertion = assertions.get(0);

		AuthenticationResponse authenticationResponse;
		try {
			authenticationResponse = Saml2Util.validateAssertion(assertion,
					now, maxOffset, audience, recipient, requestId, secretKey,
					privateKey);
		} catch (AssertionValidationException e) {
			throw new AuthenticationResponseProcessorException(e);
		}

		// check if SP expects a signature and if there is one
		if (null == samlResponse.getSignature() && expectResponseSigned) {
			throw new AuthenticationResponseProcessorException(
					"Expected a signed response but was not so! ");
		}

		// get signature cert.chain if any and pass along to service
		{
			if (null != samlResponse.getSignature()) {

				try {
					List<X509Certificate> certChain = KeyInfoHelper
							.getCertificates(samlResponse.getSignature()
									.getKeyInfo());

					if (null != service) {
						service.validateServiceCertificate(
								authenticationResponse
										.getAuthenticationPolicy(), certChain);
					}
				} catch (CertificateException e) {
					throw new AuthenticationResponseProcessorException(e);
				} catch (Exception e) {

					if ("javax.ejb.EJBException".equals(e.getClass().getName())) {
						Exception exception;
						try {
							Method getCausedByExceptionMethod = e.getClass()
									.getMethod("getCausedByException",
											new Class[] {});
							exception = (Exception) getCausedByExceptionMethod
									.invoke(e, new Object[] {});
						} catch (Exception e2) {
							LOG.debug("error: " + e.getMessage(), e);
							throw new AuthenticationResponseProcessorException(
									"error retrieving the root cause: "
											+ e2.getMessage());
						}

						throw new AuthenticationResponseProcessorException(
								"Validation exception: "
										+ (null != exception ? exception
												.getMessage() : e.getMessage()));
					}

					throw new AuthenticationResponseProcessorException(e);
				}
			}
		}

		// validate optional relaystate
		String returnedRelayState = request.getParameter(RELAY_STATE_PARAM);
		if (null != relayState) {
			if (!relayState.equals(returnedRelayState)) {
				throw new AuthenticationResponseProcessorException(
						"Returned RelayState does not match original RelayState");
			}
		} else {
			if (null != returnedRelayState) {
				throw new AuthenticationResponseProcessorException(
						"Did not expect RelayState to be returned.");
			}
		}
		authenticationResponse.setRelayState(relayState);

		return authenticationResponse;
	}

	/**
	 * @param request
	 *            HTTP Servlet Request
	 * @return the SAML v2.0 Response
	 * @throws AuthenticationResponseProcessorException
	 *             something went wrong getting the SAML v2.0 Response
	 */

	protected abstract Response getSamlResponse(HttpServletRequest request)
			throws AuthenticationResponseProcessorException;

	/**
	 * @return the (optional for HTTP-POST)
	 *         {@link AuthenticationResponseService} used for e.g. validation of
	 *         the optional signature on the response, ...
	 */
	protected abstract AuthenticationResponseService getAuthenticationResponseService();
}

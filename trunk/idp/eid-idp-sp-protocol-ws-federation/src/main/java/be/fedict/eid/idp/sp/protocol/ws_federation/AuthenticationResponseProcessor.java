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

package be.fedict.eid.idp.sp.protocol.ws_federation;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.Method;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.crypto.SecretKey;
import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.ws.wstrust.KeyType;
import org.opensaml.ws.wstrust.RequestSecurityTokenResponse;
import org.opensaml.ws.wstrust.RequestSecurityTokenResponseCollection;
import org.opensaml.ws.wstrust.RequestType;
import org.opensaml.ws.wstrust.RequestedSecurityToken;
import org.opensaml.ws.wstrust.TokenType;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import be.fedict.eid.idp.common.saml2.AssertionValidationException;
import be.fedict.eid.idp.common.saml2.AuthenticationResponse;
import be.fedict.eid.idp.common.saml2.Saml2Util;
import be.fedict.eid.idp.sp.protocol.ws_federation.spi.AuthenticationResponseService;
import be.fedict.eid.idp.sp.protocol.ws_federation.spi.ValidationService;
import be.fedict.eid.idp.sp.protocol.ws_federation.sts.SecurityTokenServiceClient;

/**
 * WS-Federation Authentication Response Processor.
 * 
 * @author Wim Vandenhaute
 */
public class AuthenticationResponseProcessor {

	protected static final Log LOG = LogFactory
			.getLog(AuthenticationResponseProcessor.class);

	private final AuthenticationResponseService service;

	/**
	 * Main Constructor
	 * 
	 * @param service
	 *            optional {@link AuthenticationResponseService} for validation
	 *            of certificate chain in returned SAML v2.0 Assertion.
	 */
	public AuthenticationResponseProcessor(AuthenticationResponseService service) {

		this.service = service;
	}

	/**
	 * Process the incoming WS-Federation response.
	 * 
	 * @param recipient
	 *            recipient, should match SAML v2.0 assertions's
	 *            AudienceRestriction
	 * @param context
	 *            optional expected context
	 * @param requiresResponseSignature
	 *            do we expect a signature on the response or not, or
	 *            <code>null</code> if to be retrieved from the
	 *            {@link AuthenticationResponseService}.
	 * @param request
	 *            the HTTP servlet request that holds the SAML2 response.
	 * @return the {@link be.fedict.eid.idp.common.saml2.AuthenticationResponse}
	 * @throws AuthenticationResponseProcessorException
	 *             case something went wrong
	 */
	public AuthenticationResponse process(String recipient, String context,
			Boolean requiresResponseSignature, HttpServletRequest request)
			throws AuthenticationResponseProcessorException {

		DateTime now = new DateTime();
		SecretKey secretKey = null;
		PrivateKey privateKey = null;
		int maxOffset = 5;
		boolean expectAssertionSigned = null != requiresResponseSignature ? requiresResponseSignature
				: false;
		ValidationService validationService = null;

		if (null != this.service) {
			secretKey = this.service.getAttributeSecretKey();
			privateKey = this.service.getAttributePrivateKey();
			maxOffset = this.service.getMaximumTimeOffset();
			expectAssertionSigned = this.service.requiresResponseSignature();
			validationService = this.service.getValidationService();
		}

		// force UTF8 encoding!
		try {
			request.setCharacterEncoding("UTF8");
		} catch (UnsupportedEncodingException e) {
			throw new AuthenticationResponseProcessorException(e);
		}

		// check wa
		String wa = request.getParameter("wa");
		if (null == wa) {
			throw new AuthenticationResponseProcessorException(
					"Missing \"wa\" param.");
		}
		if (!wa.equals("wsignin1.0")) {
			throw new AuthenticationResponseProcessorException(
					"Unexpected value for \"wa\" param.");
		}

		// validate optional ctx
		validateContext(context, request.getParameter("wctx"));

		// get wresult
		String wresult = request.getParameter("wresult");
		LOG.debug("wresult=\"" + wresult + "\"");

		if (null == wresult) {
			throw new AuthenticationResponseProcessorException(
					"Missing \"wresult\" param.");
		}
		Document responseDocument = Saml2Util.parseDocument(wresult);
		RequestSecurityTokenResponseCollection rstCollections = Saml2Util
				.unmarshall(responseDocument.getDocumentElement());

		if (rstCollections.getRequestSecurityTokenResponses().size() != 1) {
			throw new AuthenticationResponseProcessorException(
					"Expected exactly 1 RequestSecurityTokenResponse");
		}

		RequestSecurityTokenResponse rstResponse = rstCollections
				.getRequestSecurityTokenResponses().get(0);

		// context
		validateContext(context, rstResponse.getContext());

		// tokentype
		validateTokenType(rstResponse);

		// requesttype
		validateRequestType(rstResponse);

		// keytype
		validateKeyType(rstResponse);

		// validate security token
		Assertion assertion = validateSecurityToken(rstResponse);

		// validate assertion
		AuthenticationResponse authenticationResponse;
		try {
			authenticationResponse = Saml2Util.validateAssertion(assertion,
					now, maxOffset, recipient, recipient, null, secretKey,
					privateKey);
		} catch (AssertionValidationException e) {
			throw new AuthenticationResponseProcessorException(e);
		}

		// check if SP expects a signature and if there is one
		if (null == assertion.getSignature() && expectAssertionSigned) {
			throw new AuthenticationResponseProcessorException(
					"Expected a signed assertion but was not so! ");
		}

		// validate assertion's signature if any
		if (null != assertion.getSignature()) {
			try {
				// fix for recent versions of Apache xmlsec
				assertion.getDOM().setIdAttribute("ID", true);
				
				List<X509Certificate> certificateChain = Saml2Util
						.validateSignature(assertion.getSignature());

				if (null != validationService) {
					// have to reparse the document here
					NodeList assertionNodeList = Saml2Util.parseDocument(
							wresult).getElementsByTagNameNS(
							"urn:oasis:names:tc:SAML:2.0:assertion",
							"Assertion");
					LOG.debug("number of SAML2 assertions: "
							+ assertionNodeList.getLength());
					if (1 != assertionNodeList.getLength()) {
						throw new AuthenticationResponseProcessorException(
								"missing SAML2 Assertion");
					}
					Element assertionElement = (Element) assertionNodeList
							.item(0);

					DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
							.newInstance();
					documentBuilderFactory.setNamespaceAware(true);
					DocumentBuilder documentBuilder = documentBuilderFactory
							.newDocumentBuilder();
					Document tokenDocument = documentBuilder.newDocument();
					Node assertionTokenNode = tokenDocument.importNode(
							assertionElement, true);
					tokenDocument.appendChild(assertionTokenNode);

					String validationServiceLocation = validationService
							.getLocation();
					String expectedAudience = validationService
							.getExpectedAudience();
					SecurityTokenServiceClient securityTokenServiceClient = new SecurityTokenServiceClient(
							validationServiceLocation);
					securityTokenServiceClient.validateToken(
							tokenDocument.getDocumentElement(),
							expectedAudience);
				}
				if (null != this.service) {
					this.service.validateServiceCertificate(
							authenticationResponse.getAuthenticationPolicy(),
							certificateChain);
				}

			} catch (CertificateException e) {
				throw new AuthenticationResponseProcessorException(e);
			} catch (ValidationException e) {
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

		return authenticationResponse;
	}

	private Assertion validateSecurityToken(
			RequestSecurityTokenResponse rstResponse)
			throws AuthenticationResponseProcessorException {

		List<XMLObject> securityTokens = rstResponse
				.getUnknownXMLObjects(RequestedSecurityToken.ELEMENT_NAME);
		if (securityTokens.size() != 1) {
			throw new AuthenticationResponseProcessorException(
					"Expected exactly 1 RequestedSecurityToken " + "element.");
		}

		RequestedSecurityToken securityToken = (RequestedSecurityToken) securityTokens
				.get(0);

		if (!(securityToken.getUnknownXMLObject() instanceof Assertion)) {
			throw new AuthenticationResponseProcessorException(
					"Expected a SAML v2.0 Assertion as " + "SecurityToken!");
		}

		return (Assertion) securityToken.getUnknownXMLObject();
	}

	private void validateKeyType(RequestSecurityTokenResponse rstResponse)
			throws AuthenticationResponseProcessorException {

		List<XMLObject> keyTypes = rstResponse
				.getUnknownXMLObjects(KeyType.ELEMENT_NAME);
		if (keyTypes.size() != 1) {
			throw new AuthenticationResponseProcessorException(
					"Expected exactly 1 KeyType element.");
		}
		if (!((KeyType) keyTypes.get(0)).getValue().equals(
				"http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer")) {
			throw new AuthenticationResponseProcessorException(
					"Unexpected KeyType value.");
		}
	}

	private void validateRequestType(RequestSecurityTokenResponse rstResponse)
			throws AuthenticationResponseProcessorException {

		List<XMLObject> requestTypes = rstResponse
				.getUnknownXMLObjects(RequestType.ELEMENT_NAME);
		if (requestTypes.size() != 1) {
			throw new AuthenticationResponseProcessorException(
					"Expected exactly 1 RequestType element.");
		}
		if (!((RequestType) requestTypes.get(0)).getValue().equals(
				"http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue")) {
			throw new AuthenticationResponseProcessorException(
					"Unexpected RequestType value.");
		}
	}

	private void validateTokenType(RequestSecurityTokenResponse rstResponse)
			throws AuthenticationResponseProcessorException {

		List<XMLObject> tokenTypes = rstResponse
				.getUnknownXMLObjects(TokenType.ELEMENT_NAME);
		if (tokenTypes.size() != 1) {
			throw new AuthenticationResponseProcessorException(
					"Expected exactly 1 TokenType element.");
		}
		if (!((TokenType) tokenTypes.get(0)).getValue().equals(
				SAMLConstants.SAML20_NS)) {
			throw new AuthenticationResponseProcessorException(
					"Unexpected TokenType value.");
		}
	}

	private void validateContext(String expectedContext, String context)
			throws AuthenticationResponseProcessorException {

		if (null != expectedContext) {
			if (null == context) {
				throw new AuthenticationResponseProcessorException(
						"Missing wctx in response.");
			} else if (!expectedContext.equals(context)) {
				throw new AuthenticationResponseProcessorException(
						"Wrong wctx in response.");
			}
		}
	}
}

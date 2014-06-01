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

package be.fedict.eid.idp.protocol.saml2;

import java.net.URL;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.binding.decoding.HTTPRedirectDeflateDecoder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.ConfigurationException;

import be.fedict.eid.idp.common.Attribute;
import be.fedict.eid.idp.common.AttributeConstants;
import be.fedict.eid.idp.common.SamlAuthenticationPolicy;
import be.fedict.eid.idp.common.saml2.Saml2Util;
import be.fedict.eid.idp.spi.DefaultAttribute;
import be.fedict.eid.idp.spi.IdentityProviderConfiguration;
import be.fedict.eid.idp.spi.IdentityProviderFlow;
import be.fedict.eid.idp.spi.IdentityProviderProtocolService;
import be.fedict.eid.idp.spi.IncomingRequest;
import be.fedict.eid.idp.spi.ReturnResponse;

/**
 * SAML2 Browser POST Profile protocol service.
 * 
 * @author Frank Cornelis
 */
public abstract class AbstractSAML2ProtocolService implements
		IdentityProviderProtocolService {

	private static final Log LOG = LogFactory
			.getLog(AbstractSAML2ProtocolService.class);

	public static final String IDP_CONFIG_CONTEXT_ATTRIBUTE = AbstractSAML2ProtocolService.class
			.getName() + ".IdPConfig";

	public static final String TARGET_URL_SESSION_ATTRIBUTE = AbstractSAML2ProtocolService.class
			.getName() + ".TargetUrl";

	public static final String RELAY_STATE_SESSION_ATTRIBUTE = AbstractSAML2ProtocolService.class
			.getName() + ".RelayState";

	public static final String IN_RESPONSE_TO_SESSION_ATTRIBUTE = AbstractSAML2ProtocolService.class
			.getName() + ".InResponseTo";

	public static final String ISSUER_SESSION_ATTRIBUTE = AbstractSAML2ProtocolService.class
			.getName() + ".ISSUER";

	public static final String LANGUAGE_PARAM = "language";

	public String getId() {

		LOG.debug("get ID");
		return "SAML2";
	}

	public void init(ServletContext servletContext,
			IdentityProviderConfiguration configuration) {

		LOG.debug("init");

		setIdPConfiguration(servletContext, configuration);

		try {
			DefaultBootstrap.bootstrap();

		} catch (ConfigurationException e) {
			throw new RuntimeException("OpenSAML configuration error: "
					+ e.getMessage(), e);
		}
	}

	public IncomingRequest handleIncomingRequest(HttpServletRequest request,
			HttpServletResponse response) throws Exception {

		LOG.debug("handling incoming request");

		// get language param if any
		String language = null;
		if (null != request.getParameter(LANGUAGE_PARAM)) {
			language = request.getParameter(LANGUAGE_PARAM);
		}

		SAMLMessageDecoder decoder;
		if (request.getMethod().equals("POST")) {
			decoder = new HTTPPostDecoder();
		} else {
			decoder = new HTTPRedirectDeflateDecoder();
		}

		BasicSAMLMessageContext<SAMLObject, SAMLObject, SAMLObject> messageContext = new BasicSAMLMessageContext<SAMLObject, SAMLObject, SAMLObject>();
		messageContext
				.setInboundMessageTransport(new HttpServletRequestAdapter(
						request));

		decoder.decode(messageContext);

		SAMLObject samlObject = messageContext.getInboundSAMLMessage();
		LOG.debug("SAML object class: " + samlObject.getClass().getName());
		if (!(samlObject instanceof AuthnRequest)) {
			throw new IllegalArgumentException(
					"expected a SAML2 AuthnRequest document");
		}
		AuthnRequest authnRequest = (AuthnRequest) samlObject;

		String issuer = authnRequest.getIssuer().getValue();
		if (null == issuer) {
			throw new IllegalArgumentException("SAML2 AuthnRequest "
					+ "does not have an issuer set.");
		}
		LOG.debug("Issuer: " + issuer);
		setIssuer(issuer, request);

		String targetUrl = authnRequest.getAssertionConsumerServiceURL();
		LOG.debug("target URL: " + targetUrl);
		setTargetUrl(targetUrl, request);

		String relayState = messageContext.getRelayState();
		setRelayState(relayState, request);

		String inResponseTo = authnRequest.getID();
		setInResponseTo(inResponseTo, request);

		LOG.debug("request: "
				+ Saml2Util.domToString(Saml2Util.marshall(authnRequest)
						.getOwnerDocument(), true));

		// Signature validation
		X509Certificate certificate = null;
		if (null != authnRequest.getSignature()) {
			// fix for recent versions of Apache xmlsec.
			authnRequest.getDOM().setIdAttribute("ID", true);

			List<X509Certificate> certChain = Saml2Util
					.validateSignature(authnRequest.getSignature());
			certificate = Saml2Util.getEndCertificate(certChain);
		}

		// HTTP Referer check
		String referer = request.getHeader("referer");
		if (null != authnRequest.getAssertionConsumerServiceURL()
				&& null != referer) {

			URL refererUrl = new URL(referer);
			URL acsUrl = new URL(authnRequest.getAssertionConsumerServiceURL());

			LOG.debug("HTTP Referer check: referer=\"" + refererUrl.getHost()
					+ "\" request.acs=\"" + acsUrl.getHost() + "\"");

			if (!refererUrl.getHost().equalsIgnoreCase(acsUrl.getHost())) {
				throw new IllegalArgumentException("Invalid referer!");
			}
		}

		return new IncomingRequest(getAuthenticationFlow(), issuer,
				certificate, Collections.singletonList(language), null);

	}

	public ReturnResponse handleReturnResponse(HttpSession httpSession,
			String userId, Map<String, Attribute> attributes,
			SecretKey secretKey, PublicKey publicKey, String rpTargetUrl,
			HttpServletRequest request, HttpServletResponse response)
			throws Exception {

		LOG.debug("handle return response");
		LOG.debug("userId: " + userId);
		String targetUrl = rpTargetUrl;
		if (null == targetUrl) {
			targetUrl = getTargetUrl(httpSession);
		}

		IdentityProviderConfiguration configuration = getIdPConfiguration(httpSession
				.getServletContext());

		String requestIssuer = getIssuer(httpSession);
		String relayState = getRelayState(httpSession);
		String inResponseTo = getInResponseTo(httpSession);

		String issuerName = getResponseIssuer(configuration);

		Response samlResponse = Saml2Util.getResponse(inResponseTo, targetUrl,
				issuerName);

		// generate assertion
		Assertion assertion = Saml2Util.getAssertion(issuerName, inResponseTo,
				requestIssuer, targetUrl,
				configuration.getResponseTokenValidity(),
				samlResponse.getIssueInstant(), getAuthenticationPolicy(),
				userId, attributes, secretKey, publicKey);
		samlResponse.getAssertions().add(assertion);

		return handleSamlResponse(request, targetUrl, samlResponse, relayState);
	}

	public String findAttributeUri(String uri) {

		DefaultAttribute defaultAttribute = DefaultAttribute
				.findDefaultAttribute(uri);
		if (null != defaultAttribute) {
			switch (defaultAttribute) {

			case LAST_NAME:
				return AttributeConstants.LAST_NAME_CLAIM_TYPE_URI;
			case FIRST_NAME:
				return AttributeConstants.FIRST_NAME_CLAIM_TYPE_URI;
			case NAME:
				return AttributeConstants.NAME_CLAIM_TYPE_URI;
			case IDENTIFIER:
				return AttributeConstants.PPID_CLAIM_TYPE_URI;
			case ADDRESS:
				return AttributeConstants.STREET_ADDRESS_CLAIM_TYPE_URI;
			case LOCALITY:
				return AttributeConstants.LOCALITY_CLAIM_TYPE_URI;
			case POSTAL_CODE:
				return AttributeConstants.POSTAL_CODE_CLAIM_TYPE_URI;
			case GENDER:
				return AttributeConstants.GENDER_CLAIM_TYPE_URI;
			case DATE_OF_BIRTH:
				return AttributeConstants.DATE_OF_BIRTH_CLAIM_TYPE_URI;
			case NATIONALITY:
				return AttributeConstants.NATIONALITY_CLAIM_TYPE_URI;
			case PLACE_OF_BIRTH:
				return AttributeConstants.PLACE_OF_BIRTH_CLAIM_TYPE_URI;
			case PHOTO:
				return AttributeConstants.PHOTO_CLAIM_TYPE_URI;
			case CARD_NUMBER:
				return AttributeConstants.CARD_NUMBER_TYPE_URI;
			case CARD_VALIDITY_BEGIN:
				return AttributeConstants.CARD_VALIDITY_BEGIN_TYPE_URI;
			case CARD_VALIDITY_END:
				return AttributeConstants.CARD_VALIDITY_END_TYPE_URI;
			}
		}

		return null;
	}

	/*
	 * Helper methods for state handling
	 */

	protected void setTargetUrl(String targetUrl, HttpServletRequest request) {
		HttpSession httpSession = request.getSession();
		httpSession.setAttribute(TARGET_URL_SESSION_ATTRIBUTE, targetUrl);
	}

	protected String getTargetUrl(HttpSession httpSession) {
		return (String) httpSession.getAttribute(TARGET_URL_SESSION_ATTRIBUTE);
	}

	protected void setInResponseTo(String inResponseTo,
			HttpServletRequest request) {
		HttpSession httpSession = request.getSession();
		httpSession
				.setAttribute(IN_RESPONSE_TO_SESSION_ATTRIBUTE, inResponseTo);
	}

	protected String getInResponseTo(HttpSession httpSession) {
		return (String) httpSession
				.getAttribute(IN_RESPONSE_TO_SESSION_ATTRIBUTE);
	}

	protected void setRelayState(String relayState, HttpServletRequest request) {
		HttpSession httpSession = request.getSession();
		httpSession.setAttribute(RELAY_STATE_SESSION_ATTRIBUTE, relayState);
	}

	protected String getRelayState(HttpSession httpSession) {
		return (String) httpSession.getAttribute(RELAY_STATE_SESSION_ATTRIBUTE);
	}

	protected void setIssuer(String issuer, HttpServletRequest request) {
		HttpSession httpSession = request.getSession();
		httpSession.setAttribute(ISSUER_SESSION_ATTRIBUTE, issuer);
	}

	protected String getIssuer(HttpSession httpSession) {
		return (String) httpSession.getAttribute(ISSUER_SESSION_ATTRIBUTE);
	}

	protected void setIdPConfiguration(ServletContext servletContext,
			IdentityProviderConfiguration configuration) {
		servletContext
				.setAttribute(IDP_CONFIG_CONTEXT_ATTRIBUTE, configuration);
	}

	public static IdentityProviderConfiguration getIdPConfiguration(
			ServletContext servletContext) {
		return (IdentityProviderConfiguration) servletContext
				.getAttribute(IDP_CONFIG_CONTEXT_ATTRIBUTE);
	}

	/**
	 * Returns the SAML Response issuer name
	 * 
	 * @param configuration
	 *            IdP configuration
	 * @return response issuer
	 */
	public static String getResponseIssuer(
			IdentityProviderConfiguration configuration) {
		String issuerName = configuration.getDefaultIssuer();
		return issuerName;
	}

	private SamlAuthenticationPolicy getAuthenticationPolicy() {

		IdentityProviderFlow authenticationFlow = getAuthenticationFlow();
		switch (authenticationFlow) {

		case IDENTIFICATION:
			return SamlAuthenticationPolicy.IDENTIFICATION;
		case AUTHENTICATION:
			return SamlAuthenticationPolicy.AUTHENTICATION;
		case AUTHENTICATION_WITH_IDENTIFICATION:
			return SamlAuthenticationPolicy.AUTHENTICATION_WITH_IDENTIFICATION;
		}

		throw new RuntimeException("Unsupported authentication flow: "
				+ authenticationFlow);
	}

	protected abstract IdentityProviderFlow getAuthenticationFlow();

	protected abstract ReturnResponse handleSamlResponse(
			HttpServletRequest request, String targetUrl,
			Response samlResponse, String relayState) throws Exception;
}

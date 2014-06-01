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

package be.fedict.eid.idp.protocol.ws_federation;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.Charset;
import java.security.PublicKey;
import java.util.Collections;
import java.util.Map;

import javax.crypto.SecretKey;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.xml.transform.TransformerException;

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
import org.w3c.dom.Element;

import be.fedict.eid.idp.common.Attribute;
import be.fedict.eid.idp.common.AttributeConstants;
import be.fedict.eid.idp.common.SamlAuthenticationPolicy;
import be.fedict.eid.idp.common.saml2.Saml2Util;
import be.fedict.eid.idp.spi.DefaultAttribute;
import be.fedict.eid.idp.spi.IdPIdentity;
import be.fedict.eid.idp.spi.IdentityProviderConfiguration;
import be.fedict.eid.idp.spi.IdentityProviderFlow;
import be.fedict.eid.idp.spi.IdentityProviderProtocolService;
import be.fedict.eid.idp.spi.IncomingRequest;
import be.fedict.eid.idp.spi.ReturnResponse;

/**
 * WS-Federation Web (Passive) Requestors. We could use OpenAM (OpenSS0), but
 * then again they're also just doing a wrapping around the JAXB classes.
 * 
 * @author Frank Cornelis
 */
public abstract class AbstractWSFederationProtocolService implements
		IdentityProviderProtocolService {

	private static final Log LOG = LogFactory
			.getLog(AbstractWSFederationProtocolService.class);

	public static final String WS_FED_PROTOCOL_ID = "WS-Federation";

	public static final String WCTX_SESSION_ATTRIBUTE = AbstractWSFederationProtocolService.class
			.getName() + ".wctx";

	public static final String WTREALM_SESSION_ATTRIBUTE = AbstractWSFederationProtocolService.class
			.getName() + ".wtrealm";

	public static final String WREPLY_SESSION_ATTRIBUTE = AbstractWSFederationProtocolService.class
			.getName() + ".wreply";

	public static final String LANGUAGE_PARAM = "language";

	private IdentityProviderConfiguration configuration;

	private void storeWCtx(String wctx, HttpServletRequest request) {
		HttpSession httpSession = request.getSession();
		httpSession.setAttribute(WCTX_SESSION_ATTRIBUTE, wctx);
	}

	private String retrieveWctx(HttpSession httpSession) {
		return (String) httpSession.getAttribute(WCTX_SESSION_ATTRIBUTE);
	}

	private void storeWtrealm(String wtrealm, String wreply,
			HttpServletRequest request) {
		HttpSession httpSession = request.getSession();
		httpSession.setAttribute(WTREALM_SESSION_ATTRIBUTE, wtrealm);
		httpSession.setAttribute(WREPLY_SESSION_ATTRIBUTE, wreply);
	}

	private String retrieveWtrealm(HttpSession httpSession) {
		return (String) httpSession.getAttribute(WTREALM_SESSION_ATTRIBUTE);
	}

	private String retreiveWreply(HttpSession httpSession) {
		return (String) httpSession.getAttribute(WREPLY_SESSION_ATTRIBUTE);
	}

	@Override
	public String getId() {

		LOG.debug("get ID");
		return WS_FED_PROTOCOL_ID;
	}

	@Override
	public IncomingRequest handleIncomingRequest(HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		LOG.debug("handleIncomingRequest");

		String wa = request.getParameter("wa");
		if (null == wa) {
			throw new ServletException("wa parameter missing");
		}

		if ("wsignout1.0".equals(wa)) {
			LOG.debug("wa=wsignout1.0");
			String wreply = request.getParameter("wreply");
			LOG.debug("wreply: " + wreply);
			response.sendRedirect(wreply);
			return null;
		}

		if (!"wsignin1.0".equals(wa)) {
			throw new ServletException("wa action not \"wsignin1.0\"");
		}
		String wtrealm = request.getParameter("wtrealm");
		if (null == wtrealm) {
			throw new ServletException("missing wtrealm parameter");
		}
		LOG.debug("wtrealm: " + wtrealm);
		String wreply = request.getParameter("wreply");
		LOG.debug("wreply: " + wreply);

		// HTTP Referer check
		String referer = request.getHeader("referer");
		if (null != referer) {

			URL refererUrl = new URL(referer);
			URL targetUrl;
			if (null == wreply) {
				targetUrl = new URL(wtrealm);
			} else {
				targetUrl = new URL(wreply);
			}

			LOG.debug("HTTP Referer check: referer=\"" + refererUrl.getHost()
					+ "\" target URL=\"" + targetUrl.getHost() + "\"");

			if (!refererUrl.getHost().equalsIgnoreCase(targetUrl.getHost())) {
				throw new IllegalArgumentException("Invalid referer!");
			}
		}

		storeWtrealm(wtrealm, wreply, request);
		String wctx = request.getParameter("wctx");
		LOG.debug("wctx: " + wctx);
		storeWCtx(wctx, request);

		// get optional language hint
		String language = request.getParameter(LANGUAGE_PARAM);

		return new IncomingRequest(getAuthenticationFlow(), wtrealm, null,
				Collections.singletonList(language), null);
	}

	@Override
	public ReturnResponse handleReturnResponse(HttpSession httpSession,
			String userId, Map<String, Attribute> attributes,
			SecretKey secretKey, PublicKey publicKey, String rpTargetUrl,
			HttpServletRequest request, HttpServletResponse response)
			throws Exception {
		LOG.debug("handleReturnResponse");

		String wtrealm = retrieveWtrealm(httpSession);
		String wreply = retreiveWreply(httpSession);
		String targetUrl = rpTargetUrl;
		if (null == targetUrl) {
			if (null != wreply) {
				targetUrl = wreply;
			} else {
				targetUrl = wtrealm;
			}
		}
		ReturnResponse returnResponse = new ReturnResponse(targetUrl);
		returnResponse.addAttribute("wa", "wsignin1.0");
		String wctx = retrieveWctx(httpSession);
		returnResponse.addAttribute("wctx", wctx);

		String wresult = getWResult(wctx, wtrealm, userId, attributes,
				secretKey, publicKey);
		returnResponse.addAttribute("wresult", wresult);
		return returnResponse;
	}

	private String getWResult(String wctx, String wtrealm, String userId,
			Map<String, Attribute> attributes, SecretKey secretKey,
			PublicKey publicKey) throws TransformerException, IOException {

		RequestSecurityTokenResponseCollection requestSecurityTokenResponseCollection = Saml2Util
				.buildXMLObject(RequestSecurityTokenResponseCollection.class,
						RequestSecurityTokenResponseCollection.ELEMENT_NAME);

		RequestSecurityTokenResponse requestSecurityTokenResponse = Saml2Util
				.buildXMLObject(RequestSecurityTokenResponse.class,
						RequestSecurityTokenResponse.ELEMENT_NAME);
		requestSecurityTokenResponseCollection
				.getRequestSecurityTokenResponses().add(
						requestSecurityTokenResponse);

		if (null != wctx) {
			requestSecurityTokenResponse.setContext(wctx);
		}

		TokenType tokenType = Saml2Util.buildXMLObject(TokenType.class,
				TokenType.ELEMENT_NAME);
		tokenType.setValue(SAMLConstants.SAML20_NS);

		RequestType requestType = Saml2Util.buildXMLObject(RequestType.class,
				RequestType.ELEMENT_NAME);
		requestType
				.setValue("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue");

		KeyType keyType = Saml2Util.buildXMLObject(KeyType.class,
				KeyType.ELEMENT_NAME);
		keyType.setValue("http://docs.oasis-open.org/ws-sx/ws-trust/200512/Bearer");

		RequestedSecurityToken requestedSecurityToken = Saml2Util
				.buildXMLObject(RequestedSecurityToken.class,
						RequestedSecurityToken.ELEMENT_NAME);

		requestSecurityTokenResponse.getUnknownXMLObjects().add(tokenType);
		requestSecurityTokenResponse.getUnknownXMLObjects().add(requestType);
		requestSecurityTokenResponse.getUnknownXMLObjects().add(keyType);
		requestSecurityTokenResponse.getUnknownXMLObjects().add(
				requestedSecurityToken);

		String issuerName = this.configuration.getDefaultIssuer();

		DateTime issueInstantDateTime = new DateTime();
		Assertion assertion = Saml2Util.getAssertion(issuerName, null, wtrealm,
				wtrealm, configuration.getResponseTokenValidity(),
				issueInstantDateTime, getAuthenticationPolicy(), userId,
				attributes, secretKey, publicKey);

		requestedSecurityToken.setUnknownXMLObject(assertion);

		Element element;
		IdPIdentity idpIdentity = this.configuration.findIdentity();
		if (null != idpIdentity) {

			LOG.debug("sign assertion");
			element = Saml2Util.signAsElement(
					requestSecurityTokenResponseCollection, assertion,
					idpIdentity.getPrivateKeyEntry());
		} else {

			LOG.warn("assertion NOT signed!");
			element = Saml2Util
					.marshall(requestSecurityTokenResponseCollection);
		}

		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		Saml2Util.writeDocument(element.getOwnerDocument(), outputStream);
		String wresult = new String(outputStream.toByteArray(),
				Charset.forName("UTF-8"));
		LOG.debug("wresult=\"" + wresult + "\"");
		return wresult;
	}

	@Override
	public void init(ServletContext servletContext,
			IdentityProviderConfiguration configuration) {

		LOG.debug("init");
		this.configuration = configuration;
	}

	@Override
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
}

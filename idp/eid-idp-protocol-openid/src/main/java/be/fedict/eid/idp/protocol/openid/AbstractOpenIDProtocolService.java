/*
 * eID Identity Provider Project.
 * Copyright (C) 2010-2013 FedICT.
 * Copyright (C) 2014 e-Contract.be BVBA.
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

package be.fedict.eid.idp.protocol.openid;

import java.io.IOException;
import java.io.PrintWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.PublicKey;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.crypto.SecretKey;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openid4java.association.AssociationException;
import org.openid4java.association.AssociationSessionType;
import org.openid4java.discovery.UrlIdentifier;
import org.openid4java.message.AssociationRequest;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.Message;
import org.openid4java.message.MessageException;
import org.openid4java.message.MessageExtension;
import org.openid4java.message.ParameterList;
import org.openid4java.message.ax.AxMessage;
import org.openid4java.message.ax.FetchRequest;
import org.openid4java.message.ax.FetchResponse;
import org.openid4java.message.pape.PapeResponse;
import org.openid4java.server.InMemoryServerAssociationStore;
import org.openid4java.server.RealmVerifier;
import org.openid4java.server.ServerManager;

import be.fedict.eid.idp.common.Attribute;
import be.fedict.eid.idp.common.OpenIDAXConstants;
import be.fedict.eid.idp.sp.protocol.openid.UserInterfaceMessage;
import be.fedict.eid.idp.spi.DefaultAttribute;
import be.fedict.eid.idp.spi.IdentityProviderConfiguration;
import be.fedict.eid.idp.spi.IdentityProviderFlow;
import be.fedict.eid.idp.spi.IdentityProviderProtocolService;
import be.fedict.eid.idp.spi.IncomingRequest;
import be.fedict.eid.idp.spi.ReturnResponse;

/**
 * OpenID protocol service.
 * 
 * @author Frank Cornelis
 */
public abstract class AbstractOpenIDProtocolService implements
		IdentityProviderProtocolService {

	private static final Log LOG = LogFactory
			.getLog(AbstractOpenIDProtocolService.class);

	private String getServiceManagerAttribute() {

		return AbstractOpenIDProtocolService.class.getName()
				+ ".ServerManager." + getPath();
	}

	private ServerManager getServerManager(HttpServletRequest request) {

		HttpSession httpSession = request.getSession();
		ServletContext servletContext = httpSession.getServletContext();
		ServerManager serverManager = (ServerManager) servletContext
				.getAttribute(getServiceManagerAttribute());
		if (null != serverManager) {
			return serverManager;
		}
		LOG.debug("creating an OpenID server manager");
		serverManager = new ServerManager();
		/*
		 * Important that the shared association store and the private
		 * association store are different. See also:
		 * http://code.google.com/p/openid4java/source/detail?r=738
		 */
		serverManager
				.setSharedAssociations(new InMemoryServerAssociationStore());
		serverManager
				.setPrivateAssociations(new InMemoryServerAssociationStore());
		String location = "https://" + request.getServerName();
		if (request.getServerPort() != 443) {
			location += ":" + request.getServerPort();
		}
		location += "/eid-idp";
		String opEndpointUrl = location + "/protocol/" + getPath();
		LOG.debug("OP endpoint URL: " + opEndpointUrl);
		serverManager.setOPEndpointUrl(opEndpointUrl);
		servletContext
				.setAttribute(getServiceManagerAttribute(), serverManager);
		return serverManager;
	}

	public String getId() {

		LOG.debug("get ID");
		return "OpenID";
	}

	public void init(ServletContext servletContext,
			IdentityProviderConfiguration configuration) {

		LOG.debug("init");

		// add UI Extension message
		try {
			Message.addExtensionFactory(UserInterfaceMessage.class);
		} catch (MessageException e) {
			throw new RuntimeException(e);
		}
	}

	public IncomingRequest handleIncomingRequest(HttpServletRequest request,
			HttpServletResponse response) throws Exception {

		LOG.debug("handleIncomingRequest");
		ServerManager serverManager = getServerManager(request);
		ParameterList parameterList = new ParameterList(
				request.getParameterMap());
		String openIdMode = request.getParameter("openid.mode");
		if ("associate".equals(openIdMode)) {
			return doAssociation(request, response, serverManager,
					parameterList);
		}
		if ("check_authentication".equals(openIdMode)) {
			return doCheckAuthentication(response, serverManager, parameterList);
		}
		if ("checkid_setup".equals(openIdMode)) {
			return doCheckIdSetup(request, serverManager, parameterList);
		}
		throw new ServletException("unknown OpenID mode: " + openIdMode);
	}

	private IncomingRequest doCheckIdSetup(HttpServletRequest request,
			ServerManager serverManager, ParameterList parameterList)
			throws MessageException, MalformedURLException {

		LOG.debug("checkid_setup");
		RealmVerifier realmVerifier = serverManager.getRealmVerifier();
		AuthRequest authRequest = AuthRequest.createAuthRequest(parameterList,
				realmVerifier);
		// cannot store authRequest since it's not serializable.
		HttpSession httpSession = request.getSession();
		storeParameterList(parameterList, httpSession);

		// HTTP Referer check
		String referer = request.getHeader("referer");
		String returnTo = authRequest.getReturnTo();
		if (null != returnTo && null != referer) {

			URL refererUrl = new URL(referer);
			URL returnToUrl = new URL(returnTo);

			LOG.debug("HTTP Referer check: referer=\"" + refererUrl.getHost()
					+ "\" return_to=\"" + returnToUrl.getHost() + "\"");

			if (!refererUrl.getHost().equalsIgnoreCase(returnToUrl.getHost())) {
				throw new IllegalArgumentException("Invalid referer!");
			}
		}

		// check for UI Extension
		List<String> languages = null;
		if (authRequest.hasExtension(UserInterfaceMessage.OPENID_NS_UI)) {

			MessageExtension messageExtension = authRequest
					.getExtension(UserInterfaceMessage.OPENID_NS_UI);

			if (messageExtension instanceof UserInterfaceMessage) {

				UserInterfaceMessage uiMessage = (UserInterfaceMessage) messageExtension;

				languages = uiMessage.getLanguages();
			}
		}

		// Attribute Exchange Extension
		Set<String> requiredAttributes = new HashSet<String>();
		if (authRequest.hasExtension(AxMessage.OPENID_NS_AX)) {

			MessageExtension messageExtension = authRequest
					.getExtension(AxMessage.OPENID_NS_AX);

			if (messageExtension instanceof FetchRequest) {
				FetchRequest fetchRequest = (FetchRequest) messageExtension;

				@SuppressWarnings("unchecked")
				Map<String, String> requiredAttributesMap = fetchRequest
						.getAttributes(true);
				requiredAttributes.addAll(requiredAttributesMap.values());
			}
		}

		String openidRealm = parameterList.getParameterValue("openid.realm");
		if (null == openidRealm) {
			openidRealm = authRequest.getReturnTo();
		}

		return new IncomingRequest(getAuthenticationFlow(), openidRealm, null,
				languages, requiredAttributes);
	}

	private static final String OPENID_PARAMETER_LIST_SESSION_ATTRIBUTE = AbstractOpenIDProtocolService.class
			.getName() + ".ParameterList";

	private void storeParameterList(ParameterList parameterList,
			HttpSession httpSession) {

		httpSession.setAttribute(OPENID_PARAMETER_LIST_SESSION_ATTRIBUTE,
				parameterList);
	}

	private ParameterList retrieveParameterList(HttpSession httpSession) {

		ParameterList parameterList = (ParameterList) httpSession
				.getAttribute(OPENID_PARAMETER_LIST_SESSION_ATTRIBUTE);
		if (null == parameterList) {
			throw new IllegalStateException(
					"missing session OpenID ParameterList");
		}
		return parameterList;
	}

	private IncomingRequest doCheckAuthentication(HttpServletResponse response,
			ServerManager serverManager, ParameterList parameterList)
			throws IOException {

		LOG.debug("check_authentication");
		Message message = serverManager.verify(parameterList);
		String keyValueFormEncoding = message.keyValueFormEncoding();
		response.getWriter().print(keyValueFormEncoding);
		return null;
	}

	private IncomingRequest doAssociation(HttpServletRequest request,
			HttpServletResponse response, ServerManager serverManager,
			ParameterList parameterList) throws IOException, MessageException,
			AssociationException {

		/*
		 * If not running over SSL, only allow DH
		 */
		if (!request.isSecure()) {
			AssociationRequest associationRequest = AssociationRequest
					.createAssociationRequest(parameterList);
			AssociationSessionType associationSessionType = associationRequest
					.getType();
			if (associationSessionType.getHAlgorithm() == null) {
				throw new AssociationException("Not running over "
						+ "SSL requires DH.");
			}
		}

		LOG.debug("associate");
		Message message = serverManager.associationResponse(parameterList);
		String keyValueFormEncoding = message.keyValueFormEncoding();
		LOG.debug("form encoding: " + keyValueFormEncoding);
		PrintWriter printWriter = response.getWriter();
		printWriter.print(keyValueFormEncoding);
		return null;
	}

	@SuppressWarnings("unchecked")
	public ReturnResponse handleReturnResponse(HttpSession httpSession,
			String userId, Map<String, Attribute> attributes,
			SecretKey secretKey, PublicKey publicKey, String rpTargetUrl,
			HttpServletRequest request, HttpServletResponse response)
			throws Exception {

		LOG.debug("handleReturnResponse");
		ServerManager serverManager = getServerManager(request);
		RealmVerifier realmVerifier = serverManager.getRealmVerifier();
		ParameterList parameterList = retrieveParameterList(httpSession);
		AuthRequest authRequest = AuthRequest.createAuthRequest(parameterList,
				realmVerifier);

		String location = "https://" + request.getServerName();
		if (request.getServerPort() != 443) {
			location += ":" + request.getServerPort();
		}
		location += "/eid-idp/endpoints/" + getPath();

		String userIdentifier = location + "?" + userId;
		LOG.debug("user identifier: " + userIdentifier);
		UrlIdentifier urlIdentifier = new UrlIdentifier(userIdentifier);
		userIdentifier = urlIdentifier.getIdentifier();
		LOG.debug("normalized user identifier: " + userIdentifier);

		Message message = serverManager.authResponse(parameterList,
				userIdentifier, userIdentifier, true, false);

		if (message instanceof AuthSuccess) {
			AuthSuccess authSuccess = (AuthSuccess) message;

			// Attribute Exchange Extension
			if (authRequest.hasExtension(AxMessage.OPENID_NS_AX)) {

				MessageExtension messageExtension = authRequest
						.getExtension(AxMessage.OPENID_NS_AX);

				if (messageExtension instanceof FetchRequest) {
					FetchRequest fetchRequest = (FetchRequest) messageExtension;

					Map<String, String> requiredAttributes = fetchRequest
							.getAttributes(true);
					Map<String, String> optionalAttributes = fetchRequest
							.getAttributes(false);

					FetchResponse fetchResponse = FetchResponse
							.createFetchResponse();

					// required attributes
					for (Map.Entry<String, String> requiredAttribute : requiredAttributes
							.entrySet()) {
						String alias = requiredAttribute.getKey();
						String typeUri = requiredAttribute.getValue();

						LOG.debug("required attribute alias: " + alias);
						LOG.debug("required attribute typeUri: " + typeUri);

						String value = findAttribute(typeUri, attributes);
						if (null != value) {
							fetchResponse.addAttribute(alias, typeUri, value);
						}
					}

					// optional attributes
					for (Map.Entry<String, String> optionalAttribute : optionalAttributes
							.entrySet()) {
						String alias = optionalAttribute.getKey();
						String typeUri = optionalAttribute.getValue();

						LOG.debug("optional attribute alias: " + alias);
						LOG.debug("optional attribute typeUri: " + typeUri);

						String value = findAttribute(typeUri, attributes);
						if (null != value) {
							fetchResponse.addAttribute(alias, typeUri, value);
						}
					}

					authSuccess.addExtension(fetchResponse, "ax");
					authSuccess
							.setSignExtensions(new String[] { AxMessage.OPENID_NS_AX });
				}
			}

			// PaPe extension
			PapeResponse papeResponse = PapeResponse.createPapeResponse();
			papeResponse.setAuthTime(new Date());

			switch (getAuthenticationFlow()) {

			case IDENTIFICATION:
				papeResponse
						.setAuthPolicies(PapeResponse.PAPE_POLICY_PHISHING_RESISTANT);
				break;
			case AUTHENTICATION:
				papeResponse
						.setAuthPolicies(PapeResponse.PAPE_POLICY_MULTI_FACTOR_PHYSICAL);
				break;
			case AUTHENTICATION_WITH_IDENTIFICATION:
				papeResponse
						.addAuthPolicy(PapeResponse.PAPE_POLICY_PHISHING_RESISTANT);
				papeResponse
						.addAuthPolicy(PapeResponse.PAPE_POLICY_MULTI_FACTOR_PHYSICAL);
				break;
			}

			authSuccess.addExtension(papeResponse, "pape");
			/*
			 * We manually sign the auth response as we also want to add our own
			 * attributes.
			 */
			serverManager.sign(authSuccess);
		}

		String destinationUrl = rpTargetUrl;
		if (null == destinationUrl) {
			destinationUrl = authRequest.getReturnTo();
		}
		LOG.debug("destination URL: " + destinationUrl);
		Map<String, String> parameters = message.getParameterMap();
		ReturnResponse returnResponse = new ReturnResponse(destinationUrl);
		for (String paramKey : parameters.keySet()) {
			String paramValue = parameters.get(paramKey);
			returnResponse.addAttribute(paramKey, paramValue);
		}
		return returnResponse;
	}

	private String findAttribute(String typeUri,
			Map<String, Attribute> attributes) {

		for (Attribute attribute : attributes.values()) {

			if (attribute.getUri().equals(typeUri)) {

				switch (attribute.getAttributeType()) {

				case STRING:

					if (attribute.getUri().equals(
							OpenIDAXConstants.AX_GENDER_TYPE)) {
						String attributeValue = (String) attribute.getValue();
						if (attributeValue.equals("1")) {
							return "M";
						} else if (attributeValue.equals("2")) {
							return "F";
						} else {
							return attributeValue;
						}
					} else {
						return (String) attribute.getValue();
					}
				case INTEGER:
					return attribute.getValue().toString();
				case DATE:
					return new SimpleDateFormat("yyyy/MM/dd")
							.format(((GregorianCalendar) attribute.getValue())
									.getTime());
				case BINARY:
					return Base64.encodeBase64URLSafeString((byte[]) attribute
							.getValue());
				}
			}
		}

		return null;
	}

	public String findAttributeUri(String uri) {

		DefaultAttribute defaultAttribute = DefaultAttribute
				.findDefaultAttribute(uri);
		if (null != defaultAttribute) {
			switch (defaultAttribute) {

			case LAST_NAME:
				return OpenIDAXConstants.AX_LAST_NAME_PERSON_TYPE;
			case FIRST_NAME:
				return OpenIDAXConstants.AX_FIRST_NAME_PERSON_TYPE;
			case NAME:
				return OpenIDAXConstants.AX_NAME_PERSON_TYPE;
			case ADDRESS:
				return OpenIDAXConstants.AX_POSTAL_ADDRESS_TYPE;
			case LOCALITY:
				return OpenIDAXConstants.AX_CITY_TYPE;
			case POSTAL_CODE:
				return OpenIDAXConstants.AX_POSTAL_CODE_TYPE;
			case GENDER:
				return OpenIDAXConstants.AX_GENDER_TYPE;
			case DATE_OF_BIRTH:
				return OpenIDAXConstants.AX_BIRTHDATE_TYPE;
			case NATIONALITY:
				return OpenIDAXConstants.AX_NATIONALITY_TYPE;
			case PLACE_OF_BIRTH:
				return OpenIDAXConstants.AX_PLACE_OF_BIRTH_TYPE;
			case IDENTIFIER:
				return OpenIDAXConstants.AX_RRN_TYPE;
			case PHOTO:
				return OpenIDAXConstants.AX_PHOTO_TYPE;
			case CARD_NUMBER:
				return OpenIDAXConstants.AX_CARD_NUMBER_TYPE;
			case CARD_VALIDITY_BEGIN:
				return OpenIDAXConstants.AX_CARD_VALIDITY_BEGIN_TYPE;
			case CARD_VALIDITY_END:
				return OpenIDAXConstants.AX_CARD_VALIDITY_END_TYPE;
			case AUTHN_CERT:
				return OpenIDAXConstants.AX_CERT_AUTHN_TYPE;
			}
		}
		if ("be:fedict:eid:idp:age".equals(uri)) {
			return OpenIDAXConstants.AX_AGE_TYPE;
		}
		return null;
	}

	protected abstract String getPath();

	protected abstract IdentityProviderFlow getAuthenticationFlow();
}

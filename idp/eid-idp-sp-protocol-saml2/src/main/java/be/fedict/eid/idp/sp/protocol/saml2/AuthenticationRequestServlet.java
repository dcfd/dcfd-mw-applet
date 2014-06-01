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

import java.io.IOException;
import java.security.KeyStore;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.AuthnRequest;

import be.fedict.eid.idp.common.ServiceLocator;
import be.fedict.eid.idp.sp.protocol.saml2.spi.AuthenticationRequestService;

/**
 * Generates and sends out a SAML v2.0 Authentication Request.
 * <p/>
 * <p/>
 * Configuration can be provided either by providing:
 * <ul>
 * <li><tt>AuthenticationRequestService</tt>:
 * {@link AuthenticationRequestService} to provide the IdP protocol entry point,
 * SP response handling location, SP identity for signing the authentication
 * request, relay state, language</li>
 * </ul>
 * or by provinding:
 * <ul>
 * <li><tt>SPDestination</tt> or <tt>SPDestinationPage</tt>: Service Provider
 * destination that will handle the returned SAML2 response. One of the 2
 * parameters needs to be specified.</li>
 * <li><tt>IdPDestination</tt>: SAML2 entry point of the eID IdP.</li>
 * <li><tt>Language</tt>: optional language to display the eID IdP webapp in (if
 * available, else the browser's locale will be used).</li>
 * </ul>
 * 
 * @author Frank Cornelis
 * @author Wim Vandenhaute
 */
public class AuthenticationRequestServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;

	private static final Log LOG = LogFactory
			.getLog(AuthenticationRequestServlet.class);

	public static final String REQUEST_ID_SESSION_ATTRIBUTE = AuthenticationRequestServlet.class
			.getName() + ".RequestID";
	public static final String REQUEST_ISSUER_SESSION_ATTRIBUTE = AuthenticationRequestServlet.class
			.getName() + ".RequestIssuer";
	public static final String RECIPIENT_SESSION_ATTRIBUTE = AuthenticationRequestServlet.class
			.getName() + ".Recipient";
	public static final String RELAY_STATE_SESSION_ATTRIBUTE = AuthenticationRequestServlet.class
			.getName() + ".RelayState";

	private static final String AUTHN_REQUEST_SERVICE_PARAM = "AuthenticationRequestService";
	private static final String IDP_DESTINATION_PARAM = "IdPDestination";
	private static final String SP_DESTINATION_PARAM = "SPDestination";
	private static final String SP_DESTINATION_PAGE_PARAM = SP_DESTINATION_PARAM
			+ "Page";
	private static final String LANGUAGE_PARAM = "Language";

	private String idpDestination;
	private String spDestination;
	private String spDestinationPage;
	private String language;

	private ServiceLocator<AuthenticationRequestService> authenticationRequestServiceLocator;

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void init(ServletConfig config) throws ServletException {

		this.idpDestination = config.getInitParameter(IDP_DESTINATION_PARAM);
		this.spDestination = config.getInitParameter(SP_DESTINATION_PARAM);
		this.spDestinationPage = config
				.getInitParameter(SP_DESTINATION_PAGE_PARAM);
		this.language = config.getInitParameter(LANGUAGE_PARAM);
		this.authenticationRequestServiceLocator = new ServiceLocator<AuthenticationRequestService>(
				AUTHN_REQUEST_SERVICE_PARAM, config);

		// validate necessary configuration params
		if (null == this.idpDestination
				&& !this.authenticationRequestServiceLocator.isConfigured()) {
			throw new ServletException("need to provide either "
					+ IDP_DESTINATION_PARAM + " or "
					+ AUTHN_REQUEST_SERVICE_PARAM + "(Class) init-params");
		}

		if (null == this.spDestination && null == this.spDestinationPage
				&& !this.authenticationRequestServiceLocator.isConfigured()) {
			throw new ServletException("need to provide either "
					+ SP_DESTINATION_PARAM + " or " + SP_DESTINATION_PAGE_PARAM
					+ " or " + AUTHN_REQUEST_SERVICE_PARAM
					+ "(Class) init-param");
		}
	}

	/**
	 * {@inheritDoc}
	 */
	@SuppressWarnings("unchecked")
	@Override
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		LOG.debug("doGet");

		String idpDestination;
		String relayState;
		KeyStore.PrivateKeyEntry spIdentity = null;
		String language;

		AuthenticationRequestService service = this.authenticationRequestServiceLocator
				.locateService();
		if (null != service) {
			idpDestination = service.getIdPDestination();
			relayState = service.getRelayState(request.getParameterMap());
			spIdentity = service.getSPIdentity();
			language = service.getLanguage();
		} else {
			idpDestination = this.idpDestination;
			relayState = null;
			language = this.language;
		}

		// sp-destination
		String spDestination = null;
		if (null != service) {
			spDestination = service.getSPDestination();
		}
		if (null == spDestination) {
			// not provided by the service, check web.xml...
			if (null != this.spDestination) {
				spDestination = this.spDestination;
			} else {
				spDestination = request.getScheme() + "://"
						+ request.getServerName() + ":"
						+ request.getServerPort() + request.getContextPath()
						+ this.spDestinationPage;
			}
		}

		// issuer
		String issuer = null;
		if (null != service) {
			issuer = service.getIssuer();
		}
		if (null == issuer) {
			issuer = spDestination;
		}

		// generate and send an authentication request
		AuthnRequest authnRequest = AuthenticationRequestUtil.sendRequest(
				issuer, idpDestination, spDestination, relayState, spIdentity,
				response, language);

		// save state on session
		setRequestIssuer(authnRequest.getIssuer().getValue(),
				request.getSession());
		setRequestId(authnRequest.getID(), request.getSession());
		setRecipient(authnRequest.getAssertionConsumerServiceURL(),
				request.getSession());
		setRelayState(relayState, request.getSession());
	}

	/*
	 * State handling
	 */
	private void setRequestId(String requestId, HttpSession session) {
		session.setAttribute(REQUEST_ID_SESSION_ATTRIBUTE, requestId);
	}

	/**
	 * Used by the {@link AbstractAuthenticationResponseServlet} for validation
	 * of the SAML v2.0 Response <tt>InResponseTo</tt> field.
	 * 
	 * @param httpSession
	 *            the HTTP Session
	 * @return the SAML v2.0 Authentication Request ID.
	 */
	public static String getRequestId(HttpSession httpSession) {
		return (String) httpSession.getAttribute(REQUEST_ID_SESSION_ATTRIBUTE);
	}

	private void setRequestIssuer(String requestIssuer, HttpSession session) {
		session.setAttribute(REQUEST_ISSUER_SESSION_ATTRIBUTE, requestIssuer);
	}

	/**
	 * Used by the {@link AbstractAuthenticationResponseServlet} for validation
	 * of the SAML v2.0 Assertion Audience Restriction.
	 * 
	 * @param httpSession
	 *            the HTTP Session
	 * @return the SAML v2.0 Authentication Request ID.
	 */
	public static String getRequestIssuer(HttpSession httpSession) {
		return (String) httpSession
				.getAttribute(REQUEST_ISSUER_SESSION_ATTRIBUTE);
	}

	private void setRecipient(String recipient, HttpSession session) {
		session.setAttribute(RECIPIENT_SESSION_ATTRIBUTE, recipient);
	}

	/**
	 * Used by the {@link AbstractAuthenticationResponseServlet} for validation
	 * of the SAML v2.0 Response <tt>AudienceRestriction</tt>.
	 * 
	 * @param httpSession
	 *            the HTTP Session
	 * @return the SAML v2.0 Authentication Request AssertionConsumerServiceURL
	 */
	public static String getRecipient(HttpSession httpSession) {
		return (String) httpSession.getAttribute(RECIPIENT_SESSION_ATTRIBUTE);
	}

	private void setRelayState(String relayState, HttpSession session) {
		session.setAttribute(RELAY_STATE_SESSION_ATTRIBUTE, relayState);
	}

	/**
	 * Used by the {@link AbstractAuthenticationResponseServlet} for validation
	 * of the SAML v2.0 Response <tt>RelayState</tt>.
	 * 
	 * @param httpSession
	 *            the HTTP Session
	 * @return optional RelayState sent along with the SAML v2.0 Authentication
	 *         Request
	 */
	public static String getRelayState(HttpSession httpSession) {
		return (String) httpSession.getAttribute(RELAY_STATE_SESSION_ATTRIBUTE);
	}

}

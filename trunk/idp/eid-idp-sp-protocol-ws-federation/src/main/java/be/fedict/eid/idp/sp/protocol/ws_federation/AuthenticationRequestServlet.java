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

import java.io.IOException;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.idp.common.ServiceLocator;
import be.fedict.eid.idp.sp.protocol.ws_federation.spi.AuthenticationRequestService;

/**
 * Generates and sends out a WS-Federation SignIn request.
 * <p/>
 * <p/>
 * Configuration can be provided either by providing:
 * <ul>
 * <li><tt>AuthenticationRequestService</tt>:
 * {@link AuthenticationRequestService} to provide the IdP protocol entry point,
 * SP response handling location, SP identity for signing the authentication
 * request, context, language</li>
 * </ul>
 * or by providing:
 * <ul>
 * <li><tt>SPDestination</tt> or <tt>SPDestinationPage</tt>: Service Provider
 * destination that will handle the returned WS-Fedearation response. One of the
 * 2 parameters needs to be specified.</li>
 * <li><tt>IdPDestination</tt>: WS-Federation entry point of the eID IdP.</li>
 * <li><tt>Language</tt>: optional language to display the eID IdP webapp in (if
 * available, else the browser's locale will be used).</li>
 * </ul>
 * 
 * @author Wim Vandenhaute
 * @author Frank Cornelis
 */
public class AuthenticationRequestServlet extends HttpServlet {
	private static final long serialVersionUID = -2118698465810671071L;

	private static final Log LOG = LogFactory
			.getLog(AuthenticationRequestServlet.class);

	public static final String CONTEXT_SESSION_ATTRIBUTE = AuthenticationRequestServlet.class
			.getName() + ".Context";
	public static final String RECIPIENT_SESSION_ATTRIBUTE = AuthenticationRequestServlet.class
			.getName() + ".Recipient";

	private static final String AUTHN_REQUEST_SERVICE_PARAM = "AuthenticationRequestService";
	private static final String IDP_DESTINATION_PARAM = "IdPDestination";
	private static final String SP_DESTINATION_PARAM = "SPDestination";
	private static final String SP_REALM_PARAM = "SPRealm";
	private static final String SP_DESTINATION_PAGE_PARAM = SP_DESTINATION_PARAM
			+ "Page";
	private static final String LANGUAGE_PARAM = "Language";

	private String idpDestination;
	private String spDestination;
	private String spRealm;
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
		this.spRealm = config.getInitParameter(SP_REALM_PARAM);
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
		String spDestination;
		String context;
		String language;
		String spRealm;

		AuthenticationRequestService service = this.authenticationRequestServiceLocator
				.locateService();
		if (null != service) {
			idpDestination = service.getIdPDestination();
			context = service.getContext(request.getParameterMap());
			spDestination = service.getSPDestination();
			language = service.getLanguage();
			spRealm = service.getSPRealm();
		} else {
			idpDestination = this.idpDestination;
			context = null;
			if (null != this.spDestination) {
				spDestination = this.spDestination;
			} else {
				spDestination = request.getScheme() + "://"
						+ request.getServerName() + ":"
						+ request.getServerPort() + request.getContextPath()
						+ this.spDestinationPage;
			}
			language = this.language;
			spRealm = this.spRealm;
		}

		String targetUrl;
		if (null == spRealm) {
			targetUrl = idpDestination + "?wa=wsignin1.0" + "&wtrealm="
					+ spDestination;
		} else {
			targetUrl = idpDestination + "?wa=wsignin1.0" + "&wtrealm="
					+ spRealm + "&wreply=" + spDestination;
		}

		if (null != language && !language.trim().isEmpty()) {
			targetUrl += "&language=" + language;
		}
		if (null != context && !context.trim().isEmpty()) {
			targetUrl += "&wctx=" + context;
		}

		LOG.debug("targetURL: " + targetUrl);
		response.sendRedirect(targetUrl);

		// save state on session
		if (null == spRealm) {
			setRecipient(spDestination, request.getSession());
		} else {
			setRecipient(spRealm, request.getSession());
		}
		setContext(context, request.getSession());
	}

	private void setContext(String context, HttpSession session) {
		session.setAttribute(CONTEXT_SESSION_ATTRIBUTE, context);
	}

	/**
	 * Used by the {@link AuthenticationResponseServlet} for validation of the
	 * WS-Federation Response <tt>ctx</tt>.
	 * 
	 * @param httpSession
	 *            the HTTP Session
	 * @return optional context sent along with the WS-Federation Authentication
	 *         Request
	 */
	public static String getContext(HttpSession httpSession) {
		return (String) httpSession.getAttribute(CONTEXT_SESSION_ATTRIBUTE);
	}

	private void setRecipient(String recipient, HttpSession session) {
		session.setAttribute(RECIPIENT_SESSION_ATTRIBUTE, recipient);
	}

	/**
	 * Used by the {@link AuthenticationResponseServlet} for validation of the
	 * SAML v2.0 Response <tt>AudienceRestriction</tt>.
	 * 
	 * @param httpSession
	 *            the HTTP Session
	 * @return the SAML v2.0 Authentication Request AssertionConsumerServiceURL
	 */
	public static String getRecipient(HttpSession httpSession) {
		return (String) httpSession.getAttribute(RECIPIENT_SESSION_ATTRIBUTE);
	}
}

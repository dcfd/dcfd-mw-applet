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

package be.fedict.eid.idp.sp.protocol.openid;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.openid4java.OpenIDException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.discovery.Discovery;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.discovery.html.HtmlResolver;
import org.openid4java.discovery.xri.XriResolver;
import org.openid4java.discovery.yadis.YadisResolver;
import org.openid4java.message.AuthRequest;
import org.openid4java.message.ax.FetchRequest;
import org.openid4java.server.IncrementalNonceGenerator;
import org.openid4java.server.NonceGenerator;
import org.openid4java.server.RealmVerifierFactory;
import org.openid4java.util.HttpFetcherFactory;

import be.fedict.eid.idp.common.OpenIDAXConstants;
import be.fedict.eid.idp.common.ServiceLocator;
import be.fedict.eid.idp.sp.protocol.openid.spi.AuthenticationRequestService;

/**
 * Generates and sends out a OpenID Authentication Request.
 * <p/>
 * <p/>
 * Configuration can be provided either by providing:
 * <ul>
 * <li><tt>AuthenticationRequestService</tt>:
 * {@link AuthenticationRequestService} to provide the IdP protocol entry point,
 * SP response handling location, optional SSL certificate to trust, optional
 * list of preferred languages</li>
 * </ul>
 * or by provinding:
 * <ul>
 * <li><tt>SPDestination</tt> or <tt>SPDestinationPage</tt>: Service Provider
 * destination that will handle the returned SAML2 response. One of the 2
 * parameters needs to be specified.</li>
 * <li><tt>IdPDestination</tt>: SAML2 entry point of the eID IdP.</li>
 * <li><tt>TrustServer</tt>: optional boolean whether any SSL certificate is
 * regarded trusted.</li>
 * <li><tt>Language</tt>: optional comma-seperated list of preferred languages
 * to display the eID IdP webapp in (e.g.: "en,nl,fr"). If not specified, the
 * browsers's locale will be used.</li>
 * </ul>
 * 
 * @author Frank Cornelis
 */
public class AuthenticationRequestServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;

	private static final Log LOG = LogFactory
			.getLog(AuthenticationRequestServlet.class);

	private static final String AUTHN_REQUEST_SERVICE_PARAM = "AuthenticationRequestService";
	private static final String USER_IDENTIFIER_PARAM = "UserIdentifier";
	private static final String SP_DESTINATION_PARAM = "SPDestination";
	private static final String SP_DESTINATION_PAGE_PARAM = SP_DESTINATION_PARAM
			+ "Page";
	private static final String LANGUAGES_PARAM = "Language";

	private static final String TRUST_SERVER_PARAM = "TrustServer";

	public static final String CONSUMER_MANAGER_ATTRIBUTE = AuthenticationRequestServlet.class
			.getName() + ".ConsumerManager";

	public static final String RETURN_TO_SESSION_ATTRIBUTE = AuthenticationRequestServlet.class
			.getName() + ".ReturnToNonce";
	public static final String RETURN_TO_NONCE_PARAM = "janrain_nonce";

	private String userIdentifier;
	private String spDestination;
	private String spDestinationPage;
	private String languages;

	private ServiceLocator<AuthenticationRequestService> authenticationRequestServiceLocator;

	private ConsumerManager consumerManager;

	private boolean trustServer;

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void init(ServletConfig config) throws ServletException {

		this.userIdentifier = config.getInitParameter(USER_IDENTIFIER_PARAM);
		this.spDestination = config.getInitParameter(SP_DESTINATION_PARAM);
		this.spDestinationPage = config
				.getInitParameter(SP_DESTINATION_PAGE_PARAM);
		this.languages = config.getInitParameter(LANGUAGES_PARAM);
		this.authenticationRequestServiceLocator = new ServiceLocator<AuthenticationRequestService>(
				AUTHN_REQUEST_SERVICE_PARAM, config);

		// validate necessary configuration params
		if (null == this.userIdentifier
				&& !this.authenticationRequestServiceLocator.isConfigured()) {
			throw new ServletException("need to provide either "
					+ USER_IDENTIFIER_PARAM + " or "
					+ AUTHN_REQUEST_SERVICE_PARAM + "(Class) init-params");
		}

		if (null == this.spDestination && null == this.spDestinationPage
				&& !this.authenticationRequestServiceLocator.isConfigured()) {
			throw new ServletException("need to provide either "
					+ SP_DESTINATION_PARAM + " or " + SP_DESTINATION_PAGE_PARAM
					+ " or " + AUTHN_REQUEST_SERVICE_PARAM
					+ "(Class) init-param");
		}

		// SSL configuration
		String trustServer = config.getInitParameter(TRUST_SERVER_PARAM);
		if (null != trustServer) {
			this.trustServer = Boolean.parseBoolean(trustServer);
		}
		X509Certificate serverCertificate = null;
		if (this.authenticationRequestServiceLocator.isConfigured()) {
			AuthenticationRequestService service = this.authenticationRequestServiceLocator
					.locateService();
			serverCertificate = service.getServerCertificate();
		}

		if (this.trustServer) {

			LOG.warn("Trusting all SSL server certificates!");
			try {
				OpenIDSSLSocketFactory.installAllTrusted();
			} catch (Exception e) {
				throw new ServletException(
						"could not install OpenID SSL Socket Factory: "
								+ e.getMessage(), e);
			}
		} else if (null != serverCertificate) {

			LOG.info("Trusting specified SSL certificate: " + serverCertificate);
			try {
				OpenIDSSLSocketFactory.install(serverCertificate);
			} catch (Exception e) {
				throw new ServletException(
						"could not install OpenID SSL Socket Factory: "
								+ e.getMessage(), e);
			}
		}

		ServletContext servletContext = config.getServletContext();
		this.consumerManager = (ConsumerManager) servletContext
				.getAttribute(CONSUMER_MANAGER_ATTRIBUTE);

		if (null == this.consumerManager) {
			try {
				if (this.trustServer || null != serverCertificate) {

					TrustManager trustManager;
					if (this.trustServer) {
						trustManager = new OpenIDTrustManager();
					} else {
						trustManager = new OpenIDTrustManager(serverCertificate);
					}

					SSLContext sslContext = SSLContext.getInstance("SSL");
					TrustManager[] trustManagers = { trustManager };
					sslContext.init(null, trustManagers, null);
					HttpFetcherFactory httpFetcherFactory = new HttpFetcherFactory(
							sslContext,
							SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
					YadisResolver yadisResolver = new YadisResolver(
							httpFetcherFactory);
					RealmVerifierFactory realmFactory = new RealmVerifierFactory(
							yadisResolver);
					HtmlResolver htmlResolver = new HtmlResolver(
							httpFetcherFactory);
					XriResolver xriResolver = Discovery.getXriResolver();
					Discovery discovery = new Discovery(htmlResolver,
							yadisResolver, xriResolver);
					this.consumerManager = new ConsumerManager(realmFactory,
							discovery, httpFetcherFactory);

				} else {
					this.consumerManager = new ConsumerManager();
				}
			} catch (Exception e) {
				throw new ServletException(
						"could not init OpenID ConsumerManager");
			}
			servletContext.setAttribute(CONSUMER_MANAGER_ATTRIBUTE,
					this.consumerManager);
		}
	}

	/**
	 * Used by the {@link AuthenticationResponseServlet} for processing the
	 * returned OpenID response
	 * 
	 * @param request
	 *            HTTP Servlet Request, used to get the OpenID
	 *            {@link ConsumerManager} from the {@link ServletContext}
	 * @return the OpenID {@link ConsumerManager}
	 */
	public static ConsumerManager getConsumerManager(HttpServletRequest request) {
		HttpSession httpSession = request.getSession();
		ServletContext servletContext = httpSession.getServletContext();
		ConsumerManager consumerManager = (ConsumerManager) servletContext
				.getAttribute(CONSUMER_MANAGER_ATTRIBUTE);
		if (null == consumerManager) {
			throw new IllegalStateException(
					"no ConsumerManager found in ServletContext");
		}
		return consumerManager;
	}

	private String getReturnTo(String spDestination, HttpSession httpSession)
			throws UnsupportedEncodingException {

		// generate nonce for protection against CSRF
		NonceGenerator _consumerNonceGenerator = new IncrementalNonceGenerator();
		String nonce = _consumerNonceGenerator.next();

		// add to "return_to"
		String returnTo = spDestination;
		returnTo += (returnTo.indexOf('?') != -1) ? '&' : '?';
		returnTo += RETURN_TO_NONCE_PARAM + "="
				+ URLEncoder.encode(nonce, "UTF-8");

		// store return_to on session for response validation
		httpSession.setAttribute(RETURN_TO_SESSION_ATTRIBUTE, returnTo);

		return returnTo;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		String spDestination;
		String userIdentifier;
		String languages;

		AuthenticationRequestService service = this.authenticationRequestServiceLocator
				.locateService();
		if (null != service) {
			userIdentifier = service.getUserIdentifier();
			spDestination = service.getSPDestination();
			languages = service.getPreferredLanguages();
		} else {
			userIdentifier = this.userIdentifier;
			if (null != this.spDestination) {
				spDestination = this.spDestination;
			} else {
				spDestination = request.getScheme() + "://"
						+ request.getServerName() + ":"
						+ request.getServerPort() + request.getContextPath()
						+ this.spDestinationPage;
			}
			languages = this.languages;
		}

		try {
			LOG.debug("discovering the identity...");
			LOG.debug("user identifier: " + userIdentifier);
			List discoveries = this.consumerManager.discover(userIdentifier);
			LOG.debug("associating with the IdP...");
			DiscoveryInformation discovered = this.consumerManager
					.associate(discoveries);
			request.getSession().setAttribute("openid-disc", discovered);

			LOG.debug("SP destination: " + spDestination);

			AuthRequest authRequest = this.consumerManager.authenticate(
					discovered,
					getReturnTo(spDestination, request.getSession()),
					spDestination);

			/*
			 * We also piggy-back an attribute fetch request.
			 */
			FetchRequest fetchRequest = FetchRequest.createFetchRequest();

			// required attributes
			fetchRequest.addAttribute(
					OpenIDAXConstants.AX_FIRST_NAME_PERSON_TYPE, true);
			fetchRequest.addAttribute(
					OpenIDAXConstants.AX_LAST_NAME_PERSON_TYPE, true);
			fetchRequest.addAttribute(OpenIDAXConstants.AX_NAME_PERSON_TYPE,
					true);

			// optional attributes
			fetchRequest.addAttribute(OpenIDAXConstants.AX_GENDER_TYPE, false);
			fetchRequest.addAttribute(OpenIDAXConstants.AX_POSTAL_CODE_TYPE,
					false);
			fetchRequest.addAttribute(OpenIDAXConstants.AX_POSTAL_ADDRESS_TYPE,
					false);
			fetchRequest.addAttribute(OpenIDAXConstants.AX_CITY_TYPE, false);
			fetchRequest.addAttribute(OpenIDAXConstants.AX_NATIONALITY_TYPE,
					false);
			fetchRequest.addAttribute(OpenIDAXConstants.AX_PLACE_OF_BIRTH_TYPE,
					false);
			fetchRequest.addAttribute(OpenIDAXConstants.AX_BIRTHDATE_TYPE,
					false);
			fetchRequest.addAttribute(OpenIDAXConstants.AX_CARD_NUMBER_TYPE,
					false);
			fetchRequest.addAttribute(
					OpenIDAXConstants.AX_CARD_VALIDITY_BEGIN_TYPE, false);
			fetchRequest.addAttribute(
					OpenIDAXConstants.AX_CARD_VALIDITY_END_TYPE, false);
			fetchRequest.addAttribute(OpenIDAXConstants.AX_PHOTO_TYPE, false);
			fetchRequest.addAttribute(OpenIDAXConstants.AX_RRN_TYPE, false);
			fetchRequest.addAttribute(OpenIDAXConstants.AX_CERT_AUTHN_TYPE,
					false);
			fetchRequest.addAttribute(OpenIDAXConstants.AX_AGE_TYPE, false);

			authRequest.addExtension(fetchRequest, "ax");

			/*
			 * Piggy back UI Extension if any languages were specified
			 */
			if (null != languages) {
				UserInterfaceMessage uiMessage = new UserInterfaceMessage();
				uiMessage.setLanguages(languages);
				authRequest.addExtension(uiMessage, "ui");
			}

			LOG.debug("redirecting to producer with authn request...");
			response.sendRedirect(authRequest.getDestinationUrl(true));
		} catch (OpenIDException e) {
			throw new ServletException("OpenID error: " + e.getMessage(), e);
		}
	}
}

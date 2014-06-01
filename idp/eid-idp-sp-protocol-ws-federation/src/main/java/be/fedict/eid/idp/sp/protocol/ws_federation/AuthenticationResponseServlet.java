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
import be.fedict.eid.idp.common.saml2.AuthenticationResponse;
import be.fedict.eid.idp.sp.protocol.ws_federation.spi.AuthenticationResponseService;

/**
 * WS-Federation Authentication Response Servlet.
 * <p/>
 * This servlet will process the incoming WS-Federation Authentication Response
 * and construct a {@link AuthenticationResponse} from it, putting on the
 * requested HTTP Session parameter. After this it will redirect to the
 * configured redirect page
 * <p/>
 * Required intialization parameters are:
 * <ul>
 * <li><tt>ResponseSessionAttribute</tt>: HTTP Session Attribute on which the
 * {@link AuthenticationResponse} will be set.</li>
 * <li><tt>RedirectPage</tt>: Page to redirect to after having processed the
 * OpenID ID Resolution response</li>
 * </ul>
 * The following init-params are optional:
 * </p>
 * <ul>
 * <li><tt>AuthenticationResponseService</tt>: indicates the JNDI location of
 * the {@link AuthenticationResponseService} that can be used optionally for
 * e.g. validation of the certificate chain in the SAML v2.0 assertion's
 * signature.</li>
 * <li><tt>ErrorPage</tt>: indicates the page to be shown in case of errors.</li>
 * <li><tt>ErrorMessageSessionAttribute</tt>: indicates which session attribute
 * to use for reporting an error. This session attribute can be used on the
 * error page.</li>
 * </ul>
 * 
 * @author Wim Vandenhaute
 */
public class AuthenticationResponseServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;

	private static final Log LOG = LogFactory
			.getLog(AuthenticationResponseServlet.class);

	public static final String REQUIRES_RESPONSE_SIGNATURE_INIT_PARAM = "RequiresResponseSignature";

	public static final String RESPONSE_SESSION_ATTRIBUTE_INIT_PARAM = "ResponseSessionAttribute";
	public static final String REDIRECT_PAGE_INIT_PARAM = "RedirectPage";
	public static final String RESPONSE_SERVICE_INIT_PARAM = "AuthenticationResponseService";

	public static final String ERROR_PAGE_INIT_PARAM = "ErrorPage";
	public static final String ERROR_MESSAGE_SESSION_ATTRIBUTE_INIT_PARAM = "ErrorMessageSessionAttribute";

	private Boolean requiresResponseSignature = null;
	private String responseSessionAttribute;
	private String redirectPage;
	private String errorPage;
	private String errorMessageSessionAttribute;

	private ServiceLocator<AuthenticationResponseService> serviceLocator;

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void init(ServletConfig config) throws ServletException {

		String requiresResponseSignatureString = config
				.getInitParameter(REQUIRES_RESPONSE_SIGNATURE_INIT_PARAM);
		if (null != requiresResponseSignatureString) {
			requiresResponseSignature = Boolean
					.valueOf(requiresResponseSignatureString);
		}

		this.responseSessionAttribute = getRequiredInitParameter(
				RESPONSE_SESSION_ATTRIBUTE_INIT_PARAM, config);
		this.redirectPage = getRequiredInitParameter(REDIRECT_PAGE_INIT_PARAM,
				config);

		this.errorPage = config.getInitParameter(ERROR_PAGE_INIT_PARAM);
		this.errorMessageSessionAttribute = config
				.getInitParameter(ERROR_MESSAGE_SESSION_ATTRIBUTE_INIT_PARAM);

		this.serviceLocator = new ServiceLocator<AuthenticationResponseService>(
				RESPONSE_SERVICE_INIT_PARAM, config);
	}

	private String getRequiredInitParameter(String parameterName,
			ServletConfig config) throws ServletException {
		String value = config.getInitParameter(parameterName);
		if (null == value) {
			throw new ServletException(parameterName
					+ " init-param is required");
		}
		return value;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		throw new ServletException("GET not available");
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected void doPost(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		LOG.debug("doPost");

		// get request state
		String context = AuthenticationRequestServlet.getContext(request
				.getSession());
		String recipient = AuthenticationRequestServlet.getRecipient(request
				.getSession());

		// clear old session attributes
		HttpSession httpSession = request.getSession();
		clearAllSessionAttribute(httpSession);

		AuthenticationResponseProcessor processor = new AuthenticationResponseProcessor(
				this.serviceLocator.locateService());

		AuthenticationResponse authenticationResponse;
		try {
			authenticationResponse = processor.process(recipient, context,
					requiresResponseSignature, request);
		} catch (AuthenticationResponseProcessorException e) {
			showErrorPage(e.getMessage(), e, request, response);
			return;
		}

		// save response info to session
		request.getSession().setAttribute(this.responseSessionAttribute,
				authenticationResponse);

		// done, redirect
		response.sendRedirect(request.getContextPath() + this.redirectPage);
	}

	private void showErrorPage(String errorMessage, Throwable cause,
			HttpServletRequest request, HttpServletResponse response)
			throws IOException, ServletException {

		if (null == cause) {
			LOG.error("Error: " + errorMessage);
		} else {
			LOG.error("Error: " + errorMessage, cause);
		}
		if (null != this.errorMessageSessionAttribute) {
			request.getSession().setAttribute(
					this.errorMessageSessionAttribute, errorMessage);
		}
		if (null != this.errorPage) {
			response.sendRedirect(request.getContextPath() + this.errorPage);
		} else {
			throw new ServletException(errorMessage, cause);
		}
	}

	private void clearAllSessionAttribute(HttpSession httpSession) {

		httpSession.removeAttribute(this.responseSessionAttribute);
	}
}

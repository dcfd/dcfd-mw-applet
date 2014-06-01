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

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.idp.common.saml2.AuthenticationResponse;

/**
 * Abstract authentication response servlet for SAML v2.0 bindings.
 * <p/>
 * Passes the incoming HTTP Post to the binding specific authentication response
 * processor and puts the returned
 * {@link be.fedict.eid.idp.common.saml2.AuthenticationResponse} on the HTTP
 * Session.
 * 
 * @author Frank Cornelis
 * @author Wim Vandenhaute
 */
public abstract class AbstractAuthenticationResponseServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;

	private static final Log LOG = LogFactory
			.getLog(AbstractAuthenticationResponseServlet.class);

	public static final String REQUIRES_RESPONSE_SIGNATURE_INIT_PARAM = "RequiresResponseSignature";

	public static final String RESPONSE_SESSION_ATTRIBUTE_INIT_PARAM = "ResponseSessionAttribute";
	public static final String REDIRECT_PAGE_INIT_PARAM = "RedirectPage";

	public static final String ERROR_PAGE_INIT_PARAM = "ErrorPage";
	public static final String ERROR_MESSAGE_SESSION_ATTRIBUTE_INIT_PARAM = "ErrorMessageSessionAttribute";

	private Boolean requiresResponseSignature = null;
	private String responseSessionAttribute;
	private String redirectPage;
	private String errorPage;
	private String errorMessageSessionAttribute;

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

		initialize(config);
	}

	/**
	 * Get the required servlet init param
	 * 
	 * @param parameterName
	 *            parameter name
	 * @param config
	 *            Servlet Config
	 * @return the required param value
	 * @throws ServletException
	 *             no value was found.
	 */
	protected String getRequiredInitParameter(String parameterName,
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

		showErrorPage("SAML2 response handler not available via GET", null,
				request, response);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	protected void doPost(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		LOG.debug("doPost");

		// get request state
		String requestId = AuthenticationRequestServlet.getRequestId(request
				.getSession());
		String requestIssuer = AuthenticationRequestServlet
				.getRequestIssuer(request.getSession());
		String recipient = AuthenticationRequestServlet.getRecipient(request
				.getSession());
		String relayState = AuthenticationRequestServlet.getRelayState(request
				.getSession());

		// clear old session attributes
		HttpSession httpSession = request.getSession();
		clearAllSessionAttribute(httpSession);

		// process response
		AbstractAuthenticationResponseProcessor processor = getAuthenticationResponseProcessor();

		AuthenticationResponse authenticationResponse;
		try {
			authenticationResponse = processor.process(requestId,
					requestIssuer, recipient, relayState,
					requiresResponseSignature, request);
		} catch (AuthenticationResponseProcessorException e) {
			showErrorPage(e.getMessage(), e, request, response);
			return;
		}

		// save response info to session
		httpSession.setAttribute(this.responseSessionAttribute,
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

	/**
	 * Servlet initialization callback
	 * 
	 * @param config
	 *            the ServletConfig
	 * @throws ServletException
	 *             something went wrong
	 */
	protected abstract void initialize(ServletConfig config)
			throws ServletException;

	/**
	 * @return the {@link AbstractAuthenticationResponseProcessor} to be used
	 * @throws ServletException
	 *             something went wrong
	 */
	protected abstract AbstractAuthenticationResponseProcessor getAuthenticationResponseProcessor()
			throws ServletException;
}

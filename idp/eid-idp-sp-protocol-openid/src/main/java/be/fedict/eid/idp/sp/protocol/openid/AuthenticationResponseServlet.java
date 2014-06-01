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

package be.fedict.eid.idp.sp.protocol.openid;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.openid4java.association.AssociationException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.consumer.VerificationResult;
import org.openid4java.discovery.DiscoveryException;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.discovery.Identifier;
import org.openid4java.message.AuthSuccess;
import org.openid4java.message.Message;
import org.openid4java.message.MessageException;
import org.openid4java.message.MessageExtension;
import org.openid4java.message.ParameterList;
import org.openid4java.message.ax.AxMessage;
import org.openid4java.message.ax.FetchResponse;
import org.openid4java.message.pape.PapeResponse;

/**
 * OpenID Authentication Response Servlet.
 * <p/>
 * This servlet will process the incoming OpenID "ID Resolution" and construct a
 * {@link OpenIDAuthenticationResponse} from it, putting on the requested HTTP
 * Session parameter. After this it will redirect to the configured redirect
 * page
 * <p/>
 * Required intialization parameters are:
 * <ul>
 * <li><tt>ResponseSessionAttribute</tt>: HTTP Session Attribute on which the
 * {@link OpenIDAuthenticationResponse} will be set.</li>
 * <li><tt>RedirectPage</tt>: Page to redirect to after having processed the
 * OpenID ID Resolution response</li>
 * </ul>
 * 
 * @author Frank Cornelis
 * @author Wim Vandenhaute
 */
public class AuthenticationResponseServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;

	private static final Log LOG = LogFactory
			.getLog(AuthenticationResponseServlet.class);

	public static final String ERROR_PAGE_INIT_PARAM = "ErrorPage";
	public static final String ERROR_MESSAGE_SESSION_ATTRIBUTE_INIT_PARAM = "ErrorMessageSessionAttribute";

	private String responseSessionAttribute;

	private String redirectPage;
	private String errorPage;
	private String errorMessageSessionAttribute;

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void init(ServletConfig config) throws ServletException {
		this.responseSessionAttribute = getRequiredInitParameter(
				"ResponseSessionAttribute", config);

		this.redirectPage = getRequiredInitParameter("RedirectPage", config);
		this.errorPage = config.getInitParameter(ERROR_PAGE_INIT_PARAM);
		this.errorMessageSessionAttribute = config
				.getInitParameter(ERROR_MESSAGE_SESSION_ATTRIBUTE_INIT_PARAM);

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
		LOG.debug("doGet: size=" + request.getQueryString().length());
		String openIdMode = request.getParameter("openid.mode");
		if ("id_res".equals(openIdMode)) {
			try {
				doIdRes(request, response);
			} catch (Exception e) {
				showErrorPage(e.getMessage(), e, request, response);
			}
		}
	}

	@Override
	protected void doPost(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		try {
			doIdRes(request, response);
		} catch (Exception e) {
			showErrorPage(e.getMessage(), e, request, response);
		}
	}

	@SuppressWarnings("unchecked")
	private void doIdRes(HttpServletRequest request,
			HttpServletResponse response) throws MessageException,
			DiscoveryException, AssociationException, IOException,
			ServletException {
		LOG.debug("id_res");
		LOG.debug("request URL: " + request.getRequestURL());

		// force UTF-8 encoding
		try {
			request.setCharacterEncoding("UTF8");
			response.setCharacterEncoding("UTF8");
		} catch (UnsupportedEncodingException e) {
			throw new MessageException(e);
		}

		ParameterList parameterList = new ParameterList(
				request.getParameterMap());
		DiscoveryInformation discovered = (DiscoveryInformation) request
				.getSession().getAttribute("openid-disc");
		LOG.debug("request context path: " + request.getContextPath());
		LOG.debug("request URI: " + request.getRequestURI());
		String receivingUrl = request.getScheme() + "://"
				+ request.getServerName() + ":" + request.getLocalPort()
				+ request.getRequestURI();
		String queryString = request.getQueryString();
		if (queryString != null && queryString.length() > 0) {
			receivingUrl += "?" + queryString;
		}
		LOG.debug("receiving url: " + receivingUrl);
		ConsumerManager consumerManager = AuthenticationRequestServlet
				.getConsumerManager(request);
		VerificationResult verificationResult = consumerManager.verify(
				receivingUrl, parameterList, discovered);
		Identifier identifier = verificationResult.getVerifiedId();
		if (null != identifier) {

			Date authenticationTime = null;
			String userId = identifier.getIdentifier();
			List<String> authnPolicies = new LinkedList<String>();
			Map<String, Object> attributeMap = new HashMap<String, Object>();
			LOG.debug("userId: " + userId);
			Message authResponse = verificationResult.getAuthResponse();

			// verify return_to nonce
			AuthSuccess authResp = AuthSuccess.createAuthSuccess(parameterList);

			String returnTo = authResp.getReturnTo();
			String requestReturnTo = (String) request
					.getSession()
					.getAttribute(
							AuthenticationRequestServlet.RETURN_TO_SESSION_ATTRIBUTE);
			if (null == returnTo || null == requestReturnTo) {
				showErrorPage("Insufficient args for validation of "
						+ " \"openid.return_to\".", null, request, response);
				return;
			}
			if (!consumerManager.verifyReturnTo(requestReturnTo, authResp)) {
				showErrorPage("Invalid \"return_to\" in response!", null,
						request, response);
				return;
			}
			// cleanup
			request.getSession().removeAttribute(
					AuthenticationRequestServlet.RETURN_TO_SESSION_ATTRIBUTE);

			// AX
			if (authResponse.hasExtension(AxMessage.OPENID_NS_AX)) {

				MessageExtension messageExtension = authResponse
						.getExtension(AxMessage.OPENID_NS_AX);
				if (messageExtension instanceof FetchResponse) {

					FetchResponse fetchResponse = (FetchResponse) messageExtension;

					Map<String, String> attributeTypes = fetchResponse
							.getAttributeTypes();
					for (Map.Entry<String, String> entry : attributeTypes
							.entrySet()) {
						attributeMap
								.put(entry.getValue(), fetchResponse
										.getAttributeValue(entry.getKey()));
					}

				}

			}

			// PAPE
			if (authResponse.hasExtension(PapeResponse.OPENID_NS_PAPE)) {

				MessageExtension messageExtension = authResponse
						.getExtension(PapeResponse.OPENID_NS_PAPE);
				if (messageExtension instanceof PapeResponse) {

					PapeResponse papeResponse = (PapeResponse) messageExtension;

					authnPolicies = papeResponse.getAuthPoliciesList();
					authenticationTime = papeResponse.getAuthDate();

				}
			}

			OpenIDAuthenticationResponse openIDAuthenticationResponse = new OpenIDAuthenticationResponse(
					authenticationTime, userId, authnPolicies, attributeMap);
			request.getSession().setAttribute(this.responseSessionAttribute,
					openIDAuthenticationResponse);

			response.sendRedirect(request.getContextPath() + this.redirectPage);
		} else {
			showErrorPage("No verified identifier", null, request, response);
		}
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

}

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

package be.fedict.eid.idp.webapp;

import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.ejb.EJB;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.idp.entity.AttributeEntity;
import be.fedict.eid.idp.entity.RPAttributeEntity;
import be.fedict.eid.idp.entity.RPEntity;
import be.fedict.eid.idp.model.AccountingService;
import be.fedict.eid.idp.model.AttributeService;
import be.fedict.eid.idp.model.AttributeServiceManager;
import be.fedict.eid.idp.model.Constants;
import be.fedict.eid.idp.model.IdentityService;
import be.fedict.eid.idp.model.ProtocolServiceManager;
import be.fedict.eid.idp.model.RPService;
import be.fedict.eid.idp.spi.IdentityProviderAttributeService;
import be.fedict.eid.idp.spi.IdentityProviderProtocolService;
import be.fedict.eid.idp.spi.IncomingRequest;
import be.fedict.eid.idp.spi.attribute.IdentityProviderAttributeType;
import be.fedict.eid.idp.spi.protocol.IdentityProviderProtocolType;

/**
 * The main entry point for authentication protocols. This servlet serves as a
 * broker towards the different protocol services. Depending on the context path
 * the request will be delegated towards the correct protocol service.
 * 
 * @author Frank Cornelis
 */
public class ProtocolEntryServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;

	private static final Log LOG = LogFactory
			.getLog(ProtocolEntryServlet.class);

	public static final String CONTEXT_PATH_SESSION_ATTRIBUTE = ProtocolEntryServlet.class
			.getName() + ".ContextPath";

	public static final String PROTOCOL_SERVICES_ATTRIBUTE = ProtocolEntryServlet.class
			.getName() + ".ProtocolServices";

	public static final String ATTRIBUTE_SERVICES_ATTRIBUTE = ProtocolEntryServlet.class
			.getName() + ".AttributeServices";

	@EJB
	ProtocolServiceManager protocolServiceManager;

	@EJB
	AttributeServiceManager attributeServiceManager;

	@EJB
	IdentityService identityService;

	@EJB
	AccountingService accountingService;

	@EJB
	RPService rpService;

	@EJB
	AttributeService attributeService;

	private String unknownProtocolPageInitParam;

	private String unsupportedBrowserPageInitParam;

	private String protocolErrorPageInitParam;

	private String protocolErrorMessageSessionAttributeInitParam;

	private String blockedPageInitParam;

	private String blockedMessageSessionAttributeInitParam;

	private String identificationPageInitParam;

	private String authenticationPageInitParam;

	public static Map<String, IdentityProviderProtocolService> getProtocolServices(
			ServletContext servletContext) throws ServletException {
		return findProtocolServices(servletContext);
	}

	@SuppressWarnings("unchecked")
	public static Map<String, IdentityProviderProtocolService> findProtocolServices(
			ServletContext servletContext) throws ServletException {
		return (Map<String, IdentityProviderProtocolService>) servletContext
				.getAttribute(PROTOCOL_SERVICES_ATTRIBUTE);
	}

	private static void setProtocolService(
			Map<String, IdentityProviderProtocolService> protocolServices,
			ServletContext servletContext) {
		servletContext.setAttribute(PROTOCOL_SERVICES_ATTRIBUTE,
				protocolServices);
	}

	public static Map<String, IdentityProviderAttributeService> getAttributeServices(
			ServletContext servletContext) throws ServletException {
		return findAttributeServices(servletContext);
	}

	@SuppressWarnings("unchecked")
	public static Map<String, IdentityProviderAttributeService> findAttributeServices(
			ServletContext servletContext) throws ServletException {
		return (Map<String, IdentityProviderAttributeService>) servletContext
				.getAttribute(ATTRIBUTE_SERVICES_ATTRIBUTE);
	}

	private static void setAttributeServices(
			Map<String, IdentityProviderAttributeService> attributeServices,
			ServletContext servletContext) {
		servletContext.setAttribute(ATTRIBUTE_SERVICES_ATTRIBUTE,
				attributeServices);
	}

	@Override
	public void init(ServletConfig config) throws ServletException {
		/*
		 * Get init-params.
		 */
		this.unknownProtocolPageInitParam = getRequiredInitParameter(config,
				"UnknownProtocolPage");
		this.unsupportedBrowserPageInitParam = getRequiredInitParameter(config,
				"UnsupportedBrowserPage");
		this.protocolErrorPageInitParam = getRequiredInitParameter(config,
				"ProtocolErrorPage");
		this.protocolErrorMessageSessionAttributeInitParam = getRequiredInitParameter(
				config, "ProtocolErrorMessageSessionAttribute");
		this.identificationPageInitParam = getRequiredInitParameter(config,
				"IdentificationPage");
		this.authenticationPageInitParam = getRequiredInitParameter(config,
				"AuthenticationPage");
		this.blockedPageInitParam = getRequiredInitParameter(config,
				"BlockedPage");
		this.blockedMessageSessionAttributeInitParam = getRequiredInitParameter(
				config, "BlockedMessageSessionAttribute");

		/*
		 * Initialize the protocol services.
		 */
		ServletContext servletContext = config.getServletContext();
		if (null == findProtocolServices(servletContext)) {
			Map<String, IdentityProviderProtocolService> protocolServices = new HashMap<String, IdentityProviderProtocolService>();
			setProtocolService(protocolServices, servletContext);
			List<IdentityProviderProtocolType> identityProviderProtocols = this.protocolServiceManager
					.getProtocolServices();
			for (IdentityProviderProtocolType identityProviderProtocol : identityProviderProtocols) {
				String name = identityProviderProtocol.getName();
				LOG.debug("protocol name: " + name);
				IdentityProviderProtocolService protocolService = this.protocolServiceManager
						.getProtocolService(identityProviderProtocol);
				String contextPath = identityProviderProtocol.getContextPath();
				if (protocolServices.containsKey(contextPath)) {
					throw new ServletException(
							"protocol service for context path already registered: "
									+ contextPath);
				}

				protocolService.init(servletContext, this.identityService);
				protocolServices.put(contextPath, protocolService);
			}
		}

		/*
		 * Initialize the attribute services.
		 */
		if (null == findAttributeServices(servletContext)) {
			Map<String, IdentityProviderAttributeService> attributeServices = new HashMap<String, IdentityProviderAttributeService>();
			setAttributeServices(attributeServices, servletContext);
			List<IdentityProviderAttributeType> identityProviderAttributes = this.attributeServiceManager
					.getAttributeServiceTypes();
			for (IdentityProviderAttributeType identityProviderAttribute : identityProviderAttributes) {
				String uri = identityProviderAttribute.getURI();
				LOG.debug("attribute URI: " + uri);
				IdentityProviderAttributeService attributeService = this.attributeServiceManager
						.getAttributeService(identityProviderAttribute);
				if (attributeServices.containsKey(uri)) {
					throw new ServletException(
							"attribute service for URI already registered: "
									+ uri);
				}
				attributeService.init(servletContext);
				attributeServices.put(uri, attributeService);
			}
		}
	}

	private String getRequiredInitParameter(ServletConfig config,
			String initParamName) throws ServletException {
		String value = config.getInitParameter(initParamName);
		if (null == value) {
			throw new ServletException(initParamName + " init-param required");
		}
		return value;
	}

	@Override
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		handleRequest(request, response);
	}

	@Override
	protected void doPost(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		handleRequest(request, response);
	}

	private void setProtocolServiceContextPath(String contextPath,
			HttpServletRequest request) {
		LOG.debug("stored context path: " + contextPath);
		HttpSession httpSession = request.getSession();
		httpSession.setAttribute(CONTEXT_PATH_SESSION_ATTRIBUTE, contextPath);
	}

	public static String getProtocolServiceContextPath(
			HttpServletRequest request) {
		HttpSession httpSession = request.getSession();
		return (String) httpSession
				.getAttribute(CONTEXT_PATH_SESSION_ATTRIBUTE);
	}

	public static IdentityProviderProtocolService getProtocolService(
			HttpServletRequest request) throws ServletException {

		IdentityProviderProtocolService protocolService = findProtocolService(request);
		if (null == protocolService) {
			throw new ServletException("no protocol service for context path: "
					+ getProtocolServiceContextPath(request));
		}
		return protocolService;
	}

	public static IdentityProviderProtocolService findProtocolService(
			HttpServletRequest request) throws ServletException {

		String contextPath = getProtocolServiceContextPath(request);
		ServletContext servletContext = request.getServletContext();
		Map<String, IdentityProviderProtocolService> protocolServices = getProtocolServices(servletContext);
		if (null != protocolServices) {
			return protocolServices.get(contextPath);
		}
		return null;
	}

	private void handleRequest(HttpServletRequest request,
			HttpServletResponse response) throws IOException, ServletException {

		LOG.debug("handle request");
		LOG.debug("request URI: " + request.getRequestURI());
		LOG.debug("request method: " + request.getMethod());
		LOG.debug("request path info: " + request.getPathInfo());
		LOG.debug("request context path: " + request.getContextPath());
		LOG.debug("request query string: " + request.getQueryString());
		LOG.debug("request path translated: " + request.getPathTranslated());

		String userAgent = request.getHeader("User-Agent");
		if (invalidUserAgent(userAgent)) {
			LOG.warn("unsupported user agent: " + userAgent);
			response.sendRedirect(request.getContextPath()
					+ this.unsupportedBrowserPageInitParam);
			return;
		}

		String protocolServiceContextPath = request.getPathInfo();
		setProtocolServiceContextPath(protocolServiceContextPath, request);

		ServletContext servletContext = request.getServletContext();
		Map<String, IdentityProviderProtocolService> protocolServices = getProtocolServices(servletContext);
		IdentityProviderProtocolService protocolService = protocolServices
				.get(protocolServiceContextPath);
		if (null == protocolService) {
			LOG.warn("unsupported protocol: " + protocolServiceContextPath);
			response.sendRedirect(request.getContextPath()
					+ this.unknownProtocolPageInitParam);
			return;
		}

		try {
			IncomingRequest incomingRequest = protocolService
					.handleIncomingRequest(request, response);
			if (null == incomingRequest) {
				LOG.debug("the protocol service handler "
						+ "defined its own response flow");
				return;
			}

			// optionally authenticate RP
			LOG.debug("SP Domain: " + incomingRequest.getSpDomain());
			request.getSession().setAttribute(
					Constants.RP_DOMAIN_SESSION_ATTRIBUTE,
					incomingRequest.getSpDomain());
			RPEntity rp = this.rpService.find(incomingRequest.getSpDomain());
			if (null != rp) {

				if (!isValid(rp, incomingRequest, request, response)) {
					return;
				}
			}

			// set preferred language if possible
			LOG.debug("Languages: " + incomingRequest.getLanguages());
			if (null != incomingRequest.getLanguages()
					&& !incomingRequest.getLanguages().isEmpty()) {
				request.getSession().setAttribute(
						SP.LANGUAGE_LIST_SESSION_ATTRIBUTE,
						incomingRequest.getLanguages());
			}

			// check required attributes if set
			if (null != incomingRequest.getRequiredAttributes()
					&& !incomingRequest.getRequiredAttributes().isEmpty()) {

				for (String attributeProtocolUri : incomingRequest
						.getRequiredAttributes()) {

					// lookup attribute
					AttributeEntity attribute = this.attributeService
							.findAttribute(protocolService.getId(),
									attributeProtocolUri);

					if (null == attribute) {
						redirectToErrorPage("Required attribute \""
								+ attributeProtocolUri + "\" not available.",
								request, response);
						return;
					}

					// check RP's config if necessary
					if (null != rp) {
						boolean found = false;
						for (RPAttributeEntity rpAttribute : rp.getAttributes()) {
							if (rpAttribute.getAttribute().equals(attribute)) {
								found = true;
								break;
							}
						}

						if (!found) {
							redirectToErrorPage("Required attribute \""
									+ attributeProtocolUri
									+ "\" not available.", request, response);
							return;
						}
					}

				}
			}

			request.getSession().setAttribute(
					Constants.IDP_FLOW_SESSION_ATTRIBUTE,
					incomingRequest.getIdpFlow());

			switch (incomingRequest.getIdpFlow()) {
			case AUTHENTICATION:
			case AUTHENTICATION_WITH_IDENTIFICATION:
				response.sendRedirect(request.getContextPath()
						+ this.authenticationPageInitParam);
				break;
			case IDENTIFICATION:
				response.sendRedirect(request.getContextPath()
						+ this.identificationPageInitParam);
				break;
			default:
				throw new RuntimeException("cannot handle " + "IdP flow: "
						+ incomingRequest.getIdpFlow());
			}

			// accounting
			this.accountingService.addRequest(incomingRequest.getSpDomain());

		} catch (Exception e) {
			LOG.error("protocol error: " + e.getMessage(), e);
			redirectToErrorPage(e.getMessage(), request, response);
		}
	}

	private void redirectToErrorPage(String errorMessage,
			HttpServletRequest request, HttpServletResponse response)
			throws IOException {

		HttpSession httpSession = request.getSession();
		httpSession.setAttribute(
				this.protocolErrorMessageSessionAttributeInitParam,
				errorMessage);
		response.sendRedirect(request.getContextPath()
				+ this.protocolErrorPageInitParam);
	}

	private boolean isValid(RPEntity rp, IncomingRequest incomingRequest,
			HttpServletRequest request, HttpServletResponse response)
			throws IOException {

		LOG.debug("found RP: " + rp.getName());

		if (rp.isRequestSigningRequired()) {
			if (null == incomingRequest.getSpCertificate()) {
				request.getSession()
						.setAttribute(
								this.protocolErrorMessageSessionAttributeInitParam,
								"Request was not signed, which is required for this SP!");
				response.sendRedirect(request.getContextPath()
						+ this.protocolErrorPageInitParam);
				return false;
			}
		}

		if (null != incomingRequest.getSpCertificate()
				&& null != rp.getEncodedCertificate()) {

			// verify fingerprint
			try {
				String rpFingerprint = DigestUtils.shaHex(rp
						.getEncodedCertificate());
				String requestFingerPrint = DigestUtils.shaHex(incomingRequest
						.getSpCertificate().getEncoded());

				if (!rpFingerprint.equals(requestFingerPrint)) {
					request.getSession()
							.setAttribute(
									this.protocolErrorMessageSessionAttributeInitParam,
									"Request was not signed with the correct keystore!");
					response.sendRedirect(request.getContextPath()
							+ this.protocolErrorPageInitParam);
					return false;
				}
			} catch (CertificateEncodingException e) {
				return false;
			}

		}

		// check whether relying party has been blocked
		Boolean blocked = this.rpService.getBlocked(rp);
		if (null != blocked) {
			if (blocked) {
				LOG.warn("blocked relying party: " + rp.getName());
				String blockedMessage = this.rpService.getBlockedMessage(rp);
				if (null == blockedMessage) {
					blockedMessage = "Unknown reason.";
				}
				HttpSession httpSession = request.getSession();
				httpSession.setAttribute(
						this.blockedMessageSessionAttributeInitParam,
						blockedMessage);
				response.sendRedirect(request.getContextPath()
						+ this.blockedPageInitParam);
				return false;
			}
		}

		request.getSession().setAttribute(Constants.RP_SESSION_ATTRIBUTE, rp);
		return true;
	}

	private boolean invalidUserAgent(String userAgent) {

		LOG.debug("User-Agent: " + userAgent);
		return UserAgentUtil.isSmartPhone(userAgent);
	}
}

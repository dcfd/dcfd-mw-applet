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

package test.unit.be.fedict.eid.idp.protocol.openid;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.After;
import org.junit.Test;
import org.mortbay.jetty.SessionManager;
import org.mortbay.jetty.servlet.HashSessionManager;
import org.mortbay.jetty.servlet.SessionHandler;
import org.mortbay.jetty.testing.ServletTester;
import org.openid4java.OpenIDException;
import org.openid4java.association.Association;
import org.openid4java.association.AssociationException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.consumer.VerificationResult;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.discovery.Identifier;
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
import org.openid4java.server.ServerAssociationStore;
import org.openid4java.server.ServerManager;

public class OpenIDProtocolServiceTest {

	private static final Log LOG = LogFactory
			.getLog(OpenIDProtocolServiceTest.class);

	private ServletTester servletTester;

	private static String location;

	@After
	public void tearDown() throws Exception {
		if (null != this.servletTester) {
			this.servletTester.stop();
		}
	}

	public static class OpenIDIdentityServlet extends HttpServlet {

		private static final long serialVersionUID = 1L;

		private static final Log LOG = LogFactory
				.getLog(OpenIDIdentityServlet.class);

		private static final boolean USE_YADIS = true;

		@Override
		protected void doGet(HttpServletRequest request,
				HttpServletResponse response) throws ServletException,
				IOException {
			LOG.debug("doGet");
			PrintWriter printWriter = response.getWriter();
			if (request.getRequestURI().endsWith("/xrds")) {
				LOG.debug("returning the YADIS XRDS document");
				printWriter
						.println("<xrds:XRDS xmlns:xrds=\"xri://$xrds\" xmlns=\"xri://$xrd*($v*2.0)\">");
				printWriter.println("<XRD>");

				printWriter.println("<Service>");
				printWriter
						.println("<Type>http://specs.openid.net/auth/2.0/server</Type>");
				printWriter.println("<URI>"
						+ OpenIDProtocolServiceTest.location
						+ "/producer</URI>");
				printWriter.println("</Service>");

				/*
				 * Next is used by the RP to check whether the OP is allowed to
				 * issue this OP selected identifier.
				 */
				printWriter.println("<Service>");
				printWriter
						.println("<Type>http://specs.openid.net/auth/2.0/signon</Type>");
				printWriter.println("<URI>"
						+ OpenIDProtocolServiceTest.location
						+ "/producer</URI>");
				printWriter.println("</Service>");

				printWriter.println("</XRD>");
				printWriter.println("</xrds:XRDS>");
				return;
			}
			if (USE_YADIS) {
				printWriter.println("<html>");
				printWriter.println("<head>");
				printWriter
						.println("<meta http-equiv=\"X-XRDS-Location\" content=\""
								+ OpenIDProtocolServiceTest.location
								+ "/identity/xrds\"/>");
				printWriter.println("</head>");
				printWriter.println("<body><p>OpenID Identity URL</p></body>");
				printWriter.println("</html>");
			} else {
				printWriter.println("<html>");
				printWriter.println("<head>");
				printWriter.println("<link rel=\"openid2.provider\" href=\""
						+ OpenIDProtocolServiceTest.location + "/producer\"/>");

				printWriter.println("</head>");
				printWriter.println("<body><p>OpenID Identity URL</p></body>");
				printWriter.println("</html>");
			}
		}

	}

	public static class OpenIDConsumerServlet extends HttpServlet {

		private static final long serialVersionUID = 1L;

		private static final Log LOG = LogFactory
				.getLog(OpenIDConsumerServlet.class);

		public static final String CONSUMER_MANAGER_ATTRIBUTE = OpenIDConsumerServlet.class
				.getName() + ".ConsumerManager";

		public static final String USER_ID_SESSION_ATTRIBUTE = OpenIDConsumerServlet.class
				.getName() + ".UserId";

		public static final String FIRST_NAME_SESSION_ATTRIBUTE = OpenIDConsumerServlet.class
				.getName() + ".FirstName";

		private ConsumerManager consumerManager;

		@Override
		public void init(ServletConfig config) throws ServletException {
			super.init(config);
			ServletContext servletContext = config.getServletContext();
			this.consumerManager = (ConsumerManager) servletContext
					.getAttribute(CONSUMER_MANAGER_ATTRIBUTE);
			if (null == this.consumerManager) {
				try {
					this.consumerManager = new ConsumerManager();
				} catch (Exception e) {
					throw new ServletException(
							"could not init OpenID ConsumerManager");
				}
				servletContext.setAttribute(CONSUMER_MANAGER_ATTRIBUTE,
						this.consumerManager);
			}
		}

		@Override
		protected void doGet(HttpServletRequest request,
				HttpServletResponse response) throws ServletException,
				IOException {
			LOG.debug("doGet");
			try {
				String openIdMode = request.getParameter("openid.mode");
				if ("id_res".equals(openIdMode)) {
					LOG.debug("id_res");
					ParameterList parameterList = new ParameterList(
							request.getParameterMap());
					DiscoveryInformation discovered = (DiscoveryInformation) request
							.getSession().getAttribute("openid-disc");
					StringBuffer receivingUrl = request.getRequestURL();
					String queryString = request.getQueryString();
					if (queryString != null && queryString.length() > 0) {
						receivingUrl.append("?").append(queryString);
					}
					VerificationResult verificationResult = this.consumerManager
							.verify(receivingUrl.toString(), parameterList,
									discovered);
					Identifier identifier = verificationResult.getVerifiedId();
					if (null != identifier) {
						String userId = identifier.getIdentifier();
						LOG.debug("userId: " + userId);
						HttpSession httpSession = request.getSession();
						httpSession.setAttribute(USER_ID_SESSION_ATTRIBUTE,
								userId);
						Message authResponse = verificationResult
								.getAuthResponse();
						if (authResponse.hasExtension(AxMessage.OPENID_NS_AX)) {
							MessageExtension messageExtension = authResponse
									.getExtension(AxMessage.OPENID_NS_AX);
							if (messageExtension instanceof FetchResponse) {
								FetchResponse fetchResponse = (FetchResponse) messageExtension;
								String firstName = fetchResponse
										.getAttributeValueByTypeUri("http://schema.openid.net/namePerson/first");
								httpSession
										.setAttribute(
												FIRST_NAME_SESSION_ATTRIBUTE,
												firstName);
							}
						}
						PrintWriter printWriter = response.getWriter();
						printWriter.println("<html>");
						printWriter.println("<body>" + userId + "</body>");
						printWriter.println("</html>");
					} else {
						LOG.warn("no verified identifier");
					}
				} else {
					String userIdentifier = OpenIDProtocolServiceTest.location
							+ "/identity";
					LOG.debug("discovering the identity...");
					List discoveries = this.consumerManager
							.discover(userIdentifier);
					LOG.debug("associating with the IdP...");
					DiscoveryInformation discovered = consumerManager
							.associate(discoveries);
					request.getSession()
							.setAttribute("openid-disc", discovered);
					AuthRequest authRequest = consumerManager.authenticate(
							discovered, OpenIDProtocolServiceTest.location
									+ "/consumer");
					authRequest.setClaimed(AuthRequest.SELECT_ID);
					authRequest.setIdentity(AuthRequest.SELECT_ID);

					/*
					 * We also piggy-back an attribute fetch request.
					 */
					FetchRequest fetchRequest = FetchRequest
							.createFetchRequest();
					fetchRequest.addAttribute("name",
							"http://schema.openid.net/namePerson/first", true);
					authRequest.addExtension(fetchRequest);

					LOG.debug("redirecting to producer with authn request...");
					response.sendRedirect(authRequest.getDestinationUrl(true));
				}
			} catch (OpenIDException e) {
				throw new ServletException("OpenID error: " + e.getMessage(), e);
			}
		}
	}

	public static class OpenIDProducerServlet extends HttpServlet {

		private static final long serialVersionUID = 1L;

		private static final Log LOG = LogFactory
				.getLog(OpenIDProducerServlet.class);

		public static final String SERVER_MANAGER_ATTRIBUTE = OpenIDConsumerServlet.class
				.getName() + ".ServerManager";

		private ServerManager serverManager;

		@Override
		public void init(ServletConfig config) throws ServletException {
			super.init(config);
			ServletContext servletContext = config.getServletContext();
			this.serverManager = (ServerManager) servletContext
					.getAttribute(SERVER_MANAGER_ATTRIBUTE);
			if (null == this.serverManager) {
				this.serverManager = new ServerManager();
				this.serverManager
						.setSharedAssociations(new InMemoryServerAssociationStore());
				this.serverManager
						.setPrivateAssociations(new InMemoryServerAssociationStore());
				this.serverManager
						.setOPEndpointUrl(OpenIDProtocolServiceTest.location
								+ "/producer");
				servletContext.setAttribute(SERVER_MANAGER_ATTRIBUTE,
						this.serverManager);
			}
		}

		@Override
		protected void doGet(HttpServletRequest request,
				HttpServletResponse response) throws ServletException,
				IOException {
			LOG.debug("doGet");
			String openIdMode = request.getParameter("openid.mode");
			if ("checkid_setup".equals(openIdMode)) {
				LOG.debug("checkid_setup");
				ParameterList parameterList = new ParameterList(
						request.getParameterMap());
				LOG.debug("redirecting to the consumer...");

				try {
					RealmVerifier realmVerifier = this.serverManager
							.getRealmVerifier();
					AuthRequest authRequest = AuthRequest.createAuthRequest(
							parameterList, realmVerifier);
					String userId = OpenIDProtocolServiceTest.location
							+ "/identity/idp/123456789";
					Message message = this.serverManager.authResponse(
							parameterList, userId, userId, true, false);
					if (message instanceof AuthSuccess) {
						AuthSuccess authSuccess = (AuthSuccess) message;
						if (authRequest.hasExtension(AxMessage.OPENID_NS_AX)) {
							MessageExtension messageExtension = authRequest
									.getExtension(AxMessage.OPENID_NS_AX);
							if (messageExtension instanceof FetchRequest) {
								FetchRequest fetchRequest = (FetchRequest) messageExtension;
								Map<String, String> requiredAttributes = fetchRequest
										.getAttributes(true);
								FetchResponse fetchResponse = FetchResponse
										.createFetchResponse();
								for (Map.Entry<String, String> requiredAttribute : requiredAttributes
										.entrySet()) {
									String alias = requiredAttribute.getKey();
									String typeUri = requiredAttribute
											.getValue();
									LOG.debug("attribute alias: " + alias);
									LOG.debug("attribute typeUri: " + typeUri);
									if ("http://schema.openid.net/namePerson/first"
											.equals(requiredAttribute
													.getValue())) {
										fetchResponse.addAttribute(alias,
												typeUri, "sample-first-name");
									}
								}
								authSuccess.addExtension(fetchResponse);
								authSuccess
										.setSignExtensions(new String[] { AxMessage.OPENID_NS_AX });
							}
						}
						PapeResponse papeResponse = PapeResponse
								.createPapeResponse();
						papeResponse
								.setAuthPolicies(PapeResponse.PAPE_POLICY_MULTI_FACTOR_PHYSICAL);
						authSuccess.addExtension(papeResponse);
						/*
						 * We manually sign the auth response as we also want to
						 * add our own attributes.
						 */
						String handle = authRequest.getHandle();
						ServerAssociationStore serverAssociationStore = this.serverManager
								.getSharedAssociations();
						Association association = serverAssociationStore
								.load(handle);
						authSuccess.setSignature(association.sign(authSuccess
								.getSignedText()));
					}
					response.sendRedirect(message.getDestinationUrl(true));
				} catch (MessageException e) {
					LOG.error("message recreation error: " + e.getMessage(), e);
					throw new ServletException("message recreation error");
				} catch (AssociationException e) {
					LOG.error("association error: " + e.getMessage(), e);
					throw new ServletException("association error");
				}
			}
		}

		@Override
		protected void doPost(HttpServletRequest request,
				HttpServletResponse response) throws ServletException,
				IOException {
			LOG.debug("doPost");
			ParameterList parameterList = new ParameterList(
					request.getParameterMap());
			String openIdMode = request.getParameter("openid.mode");
			if ("associate".equals(openIdMode)) {
				/*
				 * We should only allow SSL here. Thus also no need for DH,
				 * no-encryption is just fine.
				 */
				LOG.debug("associate");
				Message message = this.serverManager
						.associationResponse(parameterList);
				String keyValueFormEncoding = message.keyValueFormEncoding();
				LOG.debug("form encoding: " + keyValueFormEncoding);
				PrintWriter printWriter = response.getWriter();
				printWriter.print(keyValueFormEncoding);
			} else if ("check_authentication".equals(openIdMode)) {
				LOG.debug("check_authentication");
				Message message = this.serverManager.verify(parameterList);
				String keyValueFormEncoding = message.keyValueFormEncoding();
				response.getWriter().print(keyValueFormEncoding);
			}
		}
	}

	@Test
	public void testOpenIDSpike() throws Exception {
		LOG.debug("OpenID spike");

		// setup
		this.servletTester = new ServletTester();
		this.servletTester.addServlet(OpenIDConsumerServlet.class,
				"/consumer/*");
		this.servletTester.addServlet(OpenIDIdentityServlet.class,
				"/identity/*");
		this.servletTester.addServlet(OpenIDProducerServlet.class, "/producer");
		this.servletTester.start();
		location = this.servletTester.createSocketConnector(true);
		LOG.debug("location: " + location);

		HttpClient httpClient = new HttpClient();
		httpClient.getParams().setParameter(
				"http.protocol.allow-circular-redirects", Boolean.TRUE);
		GetMethod getMethod = new GetMethod(location + "/consumer");

		// operate
		int statusCode = httpClient.executeMethod(getMethod);

		// verify
		LOG.debug("status code: " + statusCode);
		assertEquals(HttpServletResponse.SC_OK, statusCode);

		SessionHandler sessionHandler = this.servletTester.getContext()
				.getSessionHandler();
		SessionManager sessionManager = sessionHandler.getSessionManager();
		HashSessionManager hashSessionManager = (HashSessionManager) sessionManager;
		LOG.debug("# sessions: " + hashSessionManager.getSessions());
		assertEquals(1, hashSessionManager.getSessions());
		Map<String, HttpSession> sessionMap = hashSessionManager
				.getSessionMap();
		LOG.debug("session map: " + sessionMap);
		Entry<String, HttpSession> sessionEntry = sessionMap.entrySet()
				.iterator().next();
		HttpSession httpSession = sessionEntry.getValue();
		String userId = (String) httpSession
				.getAttribute(OpenIDConsumerServlet.USER_ID_SESSION_ATTRIBUTE);
		LOG.debug("userId session attribute: " + userId);
		assertEquals(location + "/identity/idp/123456789", userId);
		String firstName = (String) httpSession
				.getAttribute(OpenIDConsumerServlet.FIRST_NAME_SESSION_ATTRIBUTE);
		assertEquals("sample-first-name", firstName);
	}
}

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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.servlet.ServletConfig;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.httpclient.ConnectTimeoutException;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.httpclient.params.HttpConnectionParams;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.httpclient.protocol.ProtocolSocketFactory;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.joda.time.DateTime;
import org.junit.After;
import org.junit.Test;
import org.mortbay.jetty.SessionManager;
import org.mortbay.jetty.security.SslSocketConnector;
import org.mortbay.jetty.servlet.HashSessionManager;
import org.mortbay.jetty.servlet.SessionHandler;
import org.mortbay.jetty.testing.ServletTester;
import org.openid4java.OpenIDException;
import org.openid4java.association.Association;
import org.openid4java.association.AssociationException;
import org.openid4java.consumer.ConsumerManager;
import org.openid4java.consumer.VerificationResult;
import org.openid4java.discovery.Discovery;
import org.openid4java.discovery.DiscoveryInformation;
import org.openid4java.discovery.Identifier;
import org.openid4java.discovery.html.HtmlResolver;
import org.openid4java.discovery.xri.XriResolver;
import org.openid4java.discovery.yadis.YadisResolver;
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
import org.openid4java.server.RealmVerifierFactory;
import org.openid4java.server.ServerAssociationStore;
import org.openid4java.server.ServerManager;
import org.openid4java.util.HttpFetcherFactory;

public class OpenIDSSLProtocolServiceTest {

	private static final Log LOG = LogFactory
			.getLog(OpenIDProtocolServiceTest.class);

	private ServletTester servletTester;

	private static String location;

	private static String sslLocation;

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
			LOG.debug("request URL: " + request.getRequestURL());
			LOG.debug("request port: " + request.getLocalPort());
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
						+ OpenIDSSLProtocolServiceTest.sslLocation
						+ "/producer</URI>");
				printWriter.println("</Service>");

				printWriter.println("<Service>");
				printWriter
						.println("<Type>http://specs.openid.net/auth/2.0/signon</Type>");
				printWriter.println("<URI>"
						+ OpenIDSSLProtocolServiceTest.sslLocation
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
								+ OpenIDSSLProtocolServiceTest.sslLocation
								+ "/identity/xrds\"/>");
				printWriter.println("</head>");
				printWriter.println("<body><p>OpenID Identity URL</p></body>");
				printWriter.println("</html>");
			} else {
				printWriter.println("<html>");
				printWriter.println("<head>");
				printWriter.println("<link rel=\"openid2.provider\" href=\""
						+ OpenIDSSLProtocolServiceTest.location
						+ "/producer\"/>");

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
					SSLContext sslContext = SSLContext.getInstance("SSL");
					TrustManager trustManager = new OpenIDTrustManager();
					TrustManager[] trustManagers = { trustManager };
					sslContext.init(null, trustManagers, null);
					HttpFetcherFactory httpFetcherFactory = new HttpFetcherFactory(
							sslContext,
							org.apache.http.conn.ssl.SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
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
					LOG.debug("request URL: " + request.getRequestURL());
					ParameterList parameterList = new ParameterList(
							request.getParameterMap());
					DiscoveryInformation discovered = (DiscoveryInformation) request
							.getSession().getAttribute("openid-disc");
					String receivingUrl = "https://" + request.getServerName()
							+ ":" + request.getLocalPort() + "/consumer";
					String queryString = request.getQueryString();
					if (queryString != null && queryString.length() > 0) {
						receivingUrl += "?" + queryString;
					}
					LOG.debug("receiving url: " + receivingUrl);
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
					String userIdentifier = OpenIDSSLProtocolServiceTest.sslLocation
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
							discovered,
							OpenIDSSLProtocolServiceTest.sslLocation
									+ "/consumer");

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
						.setOPEndpointUrl(OpenIDSSLProtocolServiceTest.sslLocation
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
					String userId = OpenIDSSLProtocolServiceTest.sslLocation
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
	public void testDummy() throws Exception {
		// empty
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

		Security.addProvider(new BouncyCastleProvider());

		KeyPair keyPair = generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = generateSelfSignedCertificate(keyPair,
				"CN=localhost", notBefore, notAfter);
		File tmpP12File = File.createTempFile("ssl-", ".p12");
		tmpP12File.deleteOnExit();
		LOG.debug("p12 file: " + tmpP12File.getAbsolutePath());
		persistKey(tmpP12File, keyPair.getPrivate(), certificate,
				"secret".toCharArray(), "secret".toCharArray());

		SslSocketConnector sslSocketConnector = new SslSocketConnector();
		sslSocketConnector.setKeystore(tmpP12File.getAbsolutePath());
		sslSocketConnector.setTruststore(tmpP12File.getAbsolutePath());
		sslSocketConnector.setTruststoreType("pkcs12");
		sslSocketConnector.setKeystoreType("pkcs12");
		sslSocketConnector.setPassword("secret");
		sslSocketConnector.setKeyPassword("secret");
		sslSocketConnector.setTrustPassword("secret");
		sslSocketConnector.setMaxIdleTime(30000);
		int sslPort = getFreePort();
		sslSocketConnector.setPort(sslPort);
		this.servletTester.getContext().getServer()
				.addConnector(sslSocketConnector);
		sslLocation = "https://localhost:" + sslPort;

		this.servletTester.start();
		location = this.servletTester.createSocketConnector(true);
		LOG.debug("location: " + location);

		HttpClient httpClient = new HttpClient();
		httpClient.getParams().setParameter(
				"http.protocol.allow-circular-redirects", Boolean.TRUE);
		// GetMethod getMethod = new GetMethod(location + "/consumer");

		/*
		 * Next is for ConsumerManager to be able to trust the OP.
		 */
		// MySSLSocketFactory mySSLSocketFactory = new MySSLSocketFactory(
		// certificate);
		// HttpsURLConnection.setDefaultSSLSocketFactory(mySSLSocketFactory);

		ProtocolSocketFactory protocolSocketFactory = new MyProtocolSocketFactory(
				certificate);
		Protocol myProtocol = new Protocol("https", protocolSocketFactory,
				sslPort);
		Protocol.registerProtocol("https", myProtocol);
		GetMethod getMethod = new GetMethod(sslLocation + "/consumer");

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
		assertEquals(sslLocation + "/identity/idp/123456789", userId);
		String firstName = (String) httpSession
				.getAttribute(OpenIDConsumerServlet.FIRST_NAME_SESSION_ATTRIBUTE);
		assertEquals("sample-first-name", firstName);
	}

	private static class MyTrustManager implements X509TrustManager {

		private static final Log LOG = LogFactory.getLog(MyTrustManager.class);

		private final X509Certificate serverCertificate;

		public MyTrustManager(X509Certificate serverCertificate) {
			this.serverCertificate = serverCertificate;
		}

		public void checkClientTrusted(X509Certificate[] chain, String authType)
				throws CertificateException {
			LOG.error("checkClientTrusted");
			throw new UnsupportedOperationException();
		}

		public void checkServerTrusted(X509Certificate[] chain, String authType)
				throws CertificateException {
			LOG.debug("check server trusted");
			LOG.debug("auth type: " + authType);
			if (false == this.serverCertificate.equals(chain[0])) {
				throw new CertificateException("untrusted server certificate");
			}
		}

		public X509Certificate[] getAcceptedIssuers() {
			LOG.error("getAcceptedIssuers");
			return null;
		}
	}

	private static class MySSLSocketFactory extends SSLSocketFactory {

		private final SSLContext sslContext;

		public MySSLSocketFactory(X509Certificate serverCertificate)
				throws NoSuchAlgorithmException, KeyManagementException {
			this.sslContext = SSLContext.getInstance("SSL");
			TrustManager trustManager = new MyTrustManager(serverCertificate);
			TrustManager[] trustManagers = { trustManager };
			this.sslContext.init(null, trustManagers, null);
		}

		@Override
		public Socket createSocket() throws IOException {
			return this.sslContext.getSocketFactory().createSocket();
		}

		@Override
		public Socket createSocket(String host, int port,
				InetAddress clientHost, int clientPort) throws IOException,
				UnknownHostException {
			return this.sslContext.getSocketFactory().createSocket(host, port,
					clientHost, clientPort);
		}

		public Socket createSocket(String host, int port) throws IOException,
				UnknownHostException {
			return this.sslContext.getSocketFactory().createSocket(host, port);
		}

		public Socket createSocket(Socket socket, String host, int port,
				boolean autoClose) throws IOException, UnknownHostException {
			return this.sslContext.getSocketFactory().createSocket(socket,
					host, port, autoClose);
		}

		@Override
		public String[] getDefaultCipherSuites() {
			return this.sslContext.getSocketFactory().getDefaultCipherSuites();
		}

		@Override
		public String[] getSupportedCipherSuites() {
			return this.sslContext.getSocketFactory()
					.getSupportedCipherSuites();
		}

		@Override
		public Socket createSocket(InetAddress host, int port)
				throws IOException {
			return this.sslContext.getSocketFactory().createSocket(host, port);
		}

		@Override
		public Socket createSocket(InetAddress address, int port,
				InetAddress localAddress, int localPort) throws IOException {
			return this.sslContext.getSocketFactory().createSocket(address,
					port, localAddress, localPort);
		}

	}

	public static class MyProtocolSocketFactory implements
			ProtocolSocketFactory {
		private final SSLContext sslContext;

		public MyProtocolSocketFactory(X509Certificate serverCertificate)
				throws NoSuchAlgorithmException, KeyManagementException {
			this.sslContext = SSLContext.getInstance("SSL");
			TrustManager trustManager = new MyTrustManager(serverCertificate);
			TrustManager[] trustManagers = { trustManager };
			this.sslContext.init(null, trustManagers, null);
		}

		public Socket createSocket(String host, int port) throws IOException,
				UnknownHostException {
			return this.sslContext.getSocketFactory().createSocket(host, port);
		}

		public Socket createSocket(String host, int port,
				InetAddress localHost, int localPort) throws IOException,
				UnknownHostException {
			return this.sslContext.getSocketFactory().createSocket(host, port,
					localHost, localPort);
		}

		public Socket createSocket(String host, int port,
				InetAddress localHost, int localPort,
				HttpConnectionParams params) throws IOException,
				UnknownHostException, ConnectTimeoutException {
			return this.sslContext.getSocketFactory().createSocket(host, port,
					localHost, localPort);
		}

	}

	private KeyPair generateKeyPair() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		SecureRandom random = new SecureRandom();
		keyPairGenerator.initialize(new RSAKeyGenParameterSpec(1024,
				RSAKeyGenParameterSpec.F4), random);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		return keyPair;
	}

	private SubjectKeyIdentifier createSubjectKeyId(PublicKey publicKey)
			throws IOException {
		ByteArrayInputStream bais = new ByteArrayInputStream(
				publicKey.getEncoded());
		SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
				(ASN1Sequence) new ASN1InputStream(bais).readObject());
		return new SubjectKeyIdentifier(info);
	}

	private AuthorityKeyIdentifier createAuthorityKeyId(PublicKey publicKey)
			throws IOException {

		ByteArrayInputStream bais = new ByteArrayInputStream(
				publicKey.getEncoded());
		SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
				(ASN1Sequence) new ASN1InputStream(bais).readObject());

		return new AuthorityKeyIdentifier(info);
	}

	private void persistKey(File pkcs12keyStore, PrivateKey privateKey,
			X509Certificate certificate, char[] keyStorePassword,
			char[] keyEntryPassword) throws KeyStoreException,
			NoSuchAlgorithmException, CertificateException, IOException,
			NoSuchProviderException {
		KeyStore keyStore = KeyStore.getInstance("pkcs12",
				BouncyCastleProvider.PROVIDER_NAME);
		keyStore.load(null, keyStorePassword);
		keyStore.setKeyEntry("default", privateKey, keyEntryPassword,
				new Certificate[] { certificate });
		FileOutputStream keyStoreOut = new FileOutputStream(pkcs12keyStore);
		keyStore.store(keyStoreOut, keyStorePassword);
		keyStoreOut.close();
	}

	private X509Certificate generateSelfSignedCertificate(KeyPair keyPair,
			String subjectDn, DateTime notBefore, DateTime notAfter)
			throws IOException, InvalidKeyException, IllegalStateException,
			NoSuchAlgorithmException, SignatureException, CertificateException {
		PublicKey subjectPublicKey = keyPair.getPublic();
		PrivateKey issuerPrivateKey = keyPair.getPrivate();
		String signatureAlgorithm = "SHA1WithRSAEncryption";
		X509V3CertificateGenerator certificateGenerator = new X509V3CertificateGenerator();
		certificateGenerator.reset();
		certificateGenerator.setPublicKey(subjectPublicKey);
		certificateGenerator.setSignatureAlgorithm(signatureAlgorithm);
		certificateGenerator.setNotBefore(notBefore.toDate());
		certificateGenerator.setNotAfter(notAfter.toDate());
		X509Principal issuerDN = new X509Principal(subjectDn);
		certificateGenerator.setIssuerDN(issuerDN);
		certificateGenerator.setSubjectDN(new X509Principal(subjectDn));
		certificateGenerator.setSerialNumber(new BigInteger(128,
				new SecureRandom()));

		certificateGenerator.addExtension(X509Extensions.SubjectKeyIdentifier,
				false, createSubjectKeyId(subjectPublicKey));
		PublicKey issuerPublicKey;
		issuerPublicKey = subjectPublicKey;
		certificateGenerator.addExtension(
				X509Extensions.AuthorityKeyIdentifier, false,
				createAuthorityKeyId(issuerPublicKey));

		certificateGenerator.addExtension(X509Extensions.BasicConstraints,
				false, new BasicConstraints(true));

		X509Certificate certificate;
		certificate = certificateGenerator.generate(issuerPrivateKey);

		/*
		 * Next certificate factory trick is needed to make sure that the
		 * certificate delivered to the caller is provided by the default
		 * security provider instead of BouncyCastle. If we don't do this trick
		 * we might run into trouble when trying to use the CertPath validator.
		 */
		CertificateFactory certificateFactory = CertificateFactory
				.getInstance("X.509");
		certificate = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(certificate
						.getEncoded()));
		return certificate;
	}

	private static int getFreePort() throws Exception {
		ServerSocket serverSocket = new ServerSocket(0);
		int port = serverSocket.getLocalPort();
		serverSocket.close();
		return port;
	}
}

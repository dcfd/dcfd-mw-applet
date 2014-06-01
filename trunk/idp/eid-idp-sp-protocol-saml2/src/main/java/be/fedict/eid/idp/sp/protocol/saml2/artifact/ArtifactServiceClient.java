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

package be.fedict.eid.idp.sp.protocol.saml2.artifact;

import java.net.ProxySelector;
import java.security.InvalidKeyException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.xml.bind.JAXBElement;
import javax.xml.ws.Binding;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.handler.Handler;
import javax.xml.ws.handler.soap.SOAPHandler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.Artifact;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.StatusCode;

import be.fedict.eid.idp.common.saml2.Saml2Util;
import be.fedict.eid.idp.saml2.ws.ArtifactService;
import be.fedict.eid.idp.saml2.ws.ArtifactServiceFactory;
import be.fedict.eid.idp.saml2.ws.ArtifactServicePortType;
import be.fedict.eid.idp.saml2.ws.LoggingSoapHandler;
import be.fedict.eid.idp.saml2.ws.jaxb.ArtifactResolveType;
import be.fedict.eid.idp.saml2.ws.jaxb.ArtifactResponseType;
import be.fedict.eid.idp.saml2.ws.jaxb.ResponseType;
import be.fedict.eid.idp.sp.protocol.saml2.AuthenticationResponseProcessorException;

import com.sun.xml.ws.developer.JAXWSProperties;

/**
 * Client for the SAML v2.0 HTTP-Artifact Binding Web Service.
 * 
 * @author Wim Vandenhaute
 */
public class ArtifactServiceClient {

	private static final Log LOG = LogFactory
			.getLog(ArtifactServiceClient.class);

	private final ArtifactServicePortType port;

	private final String location;
	private final String issuerName;

	private final ArtifactServiceClientHandler clientHandler;

	private static ArtifactProxySelector proxySelector;

	static {
		ProxySelector defaultProxySelector = ProxySelector.getDefault();
		ArtifactServiceClient.proxySelector = new ArtifactProxySelector(
				defaultProxySelector);
		ProxySelector.setDefault(ArtifactServiceClient.proxySelector);
	}

	/**
	 * Main Constructor.
	 * <p/>
	 * The location is the complete WS location of the eID IdP Artifact
	 * Resolution Service.
	 * <p/>
	 * The SSL Hostname is used when sending requests over SSL and JAX-WS's
	 * default hostname verification needs to be overrided. Default it will
	 * validate the location's hostname against the SSL certificates CN, which
	 * can be unwanted behaviour, especially in test environments. Specifying
	 * <code>null</code> will accept any hostname.
	 * 
	 * @param location
	 *            location of the eID IdP Artifact Resolution Service.
	 * @param sslHostname
	 *            optional SSL hostname, can be <code>null</code>.
	 * @param spIdentity
	 *            optional Service Provider's identity to be used to sign
	 *            outgoing SAML2 Artifact Resolve requests.
	 * @param issuer
	 *            issuer of the ArtifactResolve request
	 */
	public ArtifactServiceClient(String location, String sslHostname,
			KeyStore.PrivateKeyEntry spIdentity, String issuer) {

		this.location = location;
		this.issuerName = issuer;

		ArtifactService artifactService = ArtifactServiceFactory.getInstance();
		this.port = artifactService.getArtifactServicePort();

		setEndpointAddress(sslHostname);

		// register client SOAP handler
		this.clientHandler = new ArtifactServiceClientHandler(spIdentity);
		registerSoapHandler(this.clientHandler);
	}

	/**
	 * Enables/disables logging of all SOAP requests/responses.
	 * 
	 * @param logging
	 *            logging or not
	 */
	public void setLogging(boolean logging) {

		if (logging) {
			registerSoapHandler(new LoggingSoapHandler());
		} else {
			removeSoapHandler(LoggingSoapHandler.class);
		}
	}

	/**
	 * Proxy configuration setting ( both http as https ).
	 * 
	 * @param proxyHost
	 *            proxy hostname
	 * @param proxyPort
	 *            proxy port
	 */
	public void setProxy(String proxyHost, int proxyPort) {
		ArtifactServiceClient.proxySelector.setProxy(this.location, proxyHost,
				proxyPort);
	}

	/**
	 * Resolve the specified artifact ID via the eID IdP's SAML v2.0 Artifact
	 * Service
	 * 
	 * @param artifactId
	 *            ID off the to be resolved SAML v2.0 artifact.
	 * @return SAML v2.0 Response
	 * @throws AuthenticationResponseProcessorException
	 *             something went wrong
	 */
	public Response resolve(String artifactId)
			throws AuthenticationResponseProcessorException {

		LOG.debug("resolve: " + artifactId);

		String resolveId = UUID.randomUUID().toString();

		ArtifactResolve artifactResolve = Saml2Util.buildXMLObject(
				ArtifactResolve.class, ArtifactResolve.DEFAULT_ELEMENT_NAME);
		artifactResolve.setID(resolveId);
		LOG.debug("request ID=" + resolveId);

		// Issuer
		Issuer issuer = Saml2Util.buildXMLObject(Issuer.class,
				Issuer.DEFAULT_ELEMENT_NAME);
		issuer.setValue(this.issuerName);
		artifactResolve.setIssuer(issuer);

		Artifact artifact = Saml2Util.buildXMLObject(Artifact.class,
				Artifact.DEFAULT_ELEMENT_NAME);
		artifact.setArtifact(artifactId);
		artifactResolve.setArtifact(artifact);

		// to JAXB
		ArtifactResolveType artifactResolveType = Saml2Util.toJAXB(
				artifactResolve, ArtifactResolveType.class);

		// Resolve
		ArtifactResponseType response = this.port.resolve(artifactResolveType);

		// Validate response
		if (null == response) {
			throw new AuthenticationResponseProcessorException(
					"No Artifact Response returned");
		}

		if (null == response.getStatus()) {
			throw new AuthenticationResponseProcessorException(
					"No Status Code in Artifact Response");
		}

		if (!response.getStatus().getStatusCode().getValue()
				.equals(StatusCode.SUCCESS_URI)) {
			throw new AuthenticationResponseProcessorException(
					"Resolve failed: "
							+ response.getStatus().getStatusCode().getValue());
		}

		if (!response.getInResponseTo().equals(resolveId)) {
			throw new AuthenticationResponseProcessorException(
					"Response not matching resolve?");
		}

		if (null == response.getAny()) {
			throw new AuthenticationResponseProcessorException(
					"No content in Artifact Response?");
		}

		if (!(response.getAny() instanceof JAXBElement)) {
			throw new AuthenticationResponseProcessorException(
					"Unexpected content in Artifact Response.");
		}

		if (!(((JAXBElement) response.getAny()).getValue() instanceof ResponseType)) {
			throw new AuthenticationResponseProcessorException(
					"Unexpected content in Artifact Response.");
		}

		/*
		 * We do not get the SAML v2.0 Response from JAXB but from the client
		 * SOAP handler as JAXB breaks any XML Signatures...
		 */
		if (null == this.clientHandler.getResponse()) {
			throw new AuthenticationResponseProcessorException(
					"Artifact Service SOAP handler did not return"
							+ "a SAML v2.0 Response.");
		}
		return this.clientHandler.getResponse();
	}

	/**
	 * If set, unilateral TLS authentication will occur, verifying the server
	 * {@link X509Certificate} specified against the {@link PublicKey}.
	 * 
	 * @param publicKey
	 *            public key to validate server TLS certificate against.
	 */
	public void setServicePublicKey(final PublicKey publicKey) {

		// Create TrustManager
		TrustManager[] trustManager = { new X509TrustManager() {

			public X509Certificate[] getAcceptedIssuers() {

				return null;
			}

			public void checkServerTrusted(X509Certificate[] chain,
					String authType) throws CertificateException {

				X509Certificate serverCertificate = chain[0];
				LOG.debug("server X509 subject: "
						+ serverCertificate.getSubjectX500Principal()
								.toString());
				LOG.debug("authentication type: " + authType);
				if (null == publicKey) {
					return;
				}

				try {
					serverCertificate.verify(publicKey);
					LOG.debug("valid server certificate");
				} catch (InvalidKeyException e) {
					throw new CertificateException("Invalid Key");
				} catch (NoSuchAlgorithmException e) {
					throw new CertificateException("No such algorithm");
				} catch (NoSuchProviderException e) {
					throw new CertificateException("No such provider");
				} catch (SignatureException e) {
					throw new CertificateException("Wrong signature");
				}
			}

			public void checkClientTrusted(X509Certificate[] chain,
					String authType) throws CertificateException {

				throw new CertificateException(
						"this trust manager cannot be used as server-side trust manager");
			}
		} };

		// Create SSL Context
		try {
			SSLContext sslContext = SSLContext.getInstance("TLS");
			SecureRandom secureRandom = new SecureRandom();
			sslContext.init(null, trustManager, secureRandom);
			LOG.debug("SSL context provider: "
					+ sslContext.getProvider().getName());

			// Setup TrustManager for validation
			Map<String, Object> requestContext = ((BindingProvider) this.port)
					.getRequestContext();
			requestContext.put(JAXWSProperties.SSL_SOCKET_FACTORY,
					sslContext.getSocketFactory());

		} catch (KeyManagementException e) {
			String msg = "key management error: " + e.getMessage();
			LOG.error(msg, e);
			throw new RuntimeException(msg, e);
		} catch (NoSuchAlgorithmException e) {
			String msg = "TLS algo not present: " + e.getMessage();
			LOG.error(msg, e);
			throw new RuntimeException(msg, e);
		}
	}

	private void setEndpointAddress(String sslHostname) {

		LOG.debug("ws location: " + location);
		if (null == location) {
			throw new IllegalArgumentException("SAML Artifact "
					+ "Service location URL cannot be null");
		}

		BindingProvider bindingProvider = (BindingProvider) this.port;
		bindingProvider.getRequestContext().put(
				BindingProvider.ENDPOINT_ADDRESS_PROPERTY, location);
		bindingProvider.getRequestContext().put(
				JAXWSProperties.HOSTNAME_VERIFIER,
				new CustomHostnameVerifier(sslHostname));

	}

	/*
	 * Registers the specifed SOAP handler on the given JAX-WS port component.
	 */
	protected void registerSoapHandler(SOAPHandler soapHandler) {

		BindingProvider bindingProvider = (BindingProvider) this.port;

		Binding binding = bindingProvider.getBinding();
		@SuppressWarnings("unchecked")
		List<Handler> handlerChain = binding.getHandlerChain();
		handlerChain.add(soapHandler);
		binding.setHandlerChain(handlerChain);
	}

	/*
	 * Unregister possible SOAP handlers of specified typeon the given JAX-WS
	 * port component.
	 */
	protected void removeSoapHandler(
			Class<? extends SOAPHandler> soapHandlerClass) {

		BindingProvider bindingProvider = (BindingProvider) this.port;

		Binding binding = bindingProvider.getBinding();
		@SuppressWarnings("unchecked")
		List<Handler> handlerChain = binding.getHandlerChain();
		Iterator<Handler> iter = handlerChain.iterator();
		while (iter.hasNext()) {
			Handler handler = iter.next();
			if (handler.getClass().isAssignableFrom(soapHandlerClass)) {
				iter.remove();
			}

		}
	}

	/**
	 * SSL Hostname verifier, hostname of WS call over SSL is checked against
	 * SSL's CN...
	 */
	class CustomHostnameVerifier implements HostnameVerifier {

		private final String hostname;

		public CustomHostnameVerifier(String hostname) {
			this.hostname = hostname;
		}

		public boolean verify(String hostname, SSLSession sslSession) {

			LOG.debug("verify: " + hostname);
			return null == this.hostname || this.hostname.equals(hostname);
		}
	}
}

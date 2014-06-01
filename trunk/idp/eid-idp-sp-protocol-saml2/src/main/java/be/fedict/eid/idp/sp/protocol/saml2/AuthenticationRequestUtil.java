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

import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.velocity.app.VelocityEngine;
import org.apache.velocity.runtime.RuntimeConstants;
import org.apache.velocity.runtime.log.Log4JLogChute;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObjectBuilder;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.encoding.HTTPPostEncoder;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.OutTransport;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;

/**
 * Utility class for generating and sending SAML v2.0 Auhentication Requests.
 * 
 * @author Wim Vandenhaute
 */
public class AuthenticationRequestUtil {

	private static final Log LOG = LogFactory
			.getLog(AuthenticationRequestUtil.class);

	static {
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			throw new RuntimeException(
					"could not bootstrap the OpenSAML2 library", e);
		}
	}

	private AuthenticationRequestUtil() {
		// empty
	}

	/**
	 * Generates a SAML v2.0 Authentication Request and performs a browser POST
	 * to the specified idpDestination.
	 * 
	 * @param issuerName
	 *            issuer of the SAML v2.0 AuthnRequest
	 * @param idpDestination
	 *            required eID IdP destination
	 * @param spDestination
	 *            Service Provider landing URL where the IdP will post the SAML2
	 *            Response to.
	 * @param relayState
	 *            optional relay state
	 * @param spIdentity
	 *            optional Service Provider Identity. If specified the
	 *            authentication request will be signed.
	 * @param response
	 *            response used for posting the request to the IdP
	 * @param language
	 *            optional language hint
	 * @return the SAML v2.0 AuthnRequest just sent over.
	 * @throws ServletException
	 *             something went wrong.
	 */
	@SuppressWarnings("unchecked")
	public static AuthnRequest sendRequest(String issuerName,
			String idpDestination, String spDestination, String relayState,
			KeyStore.PrivateKeyEntry spIdentity, HttpServletResponse response,
			String language) throws ServletException {

		if (null == idpDestination) {
			throw new ServletException("No IdP Destination specified");
		}
		if (null == spDestination) {
			throw new ServletException("No SP Destination specified");
		}

		LOG.debug("Issuer: " + issuerName);
		LOG.debug("IdP destination: " + idpDestination);
		LOG.debug("SP destination: " + spDestination);
		LOG.debug("relay state: " + relayState);
		LOG.debug("SP identity: " + spIdentity);

		String idpEndpoint = idpDestination;
		if (null != language) {
			idpEndpoint += "?language=" + language;
		}

		XMLObjectBuilderFactory builderFactory = Configuration
				.getBuilderFactory();

		SAMLObjectBuilder<AuthnRequest> requestBuilder = (SAMLObjectBuilder<AuthnRequest>) builderFactory
				.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME);
		AuthnRequest authnRequest = requestBuilder.buildObject();
		authnRequest.setID("authn-request-" + UUID.randomUUID().toString());
		authnRequest.setVersion(SAMLVersion.VERSION_20);
		authnRequest.setIssueInstant(new DateTime());
		authnRequest.setDestination(idpDestination);
		authnRequest.setAssertionConsumerServiceURL(spDestination);
		authnRequest.setForceAuthn(true);
		authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);

		SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) builderFactory
				.getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
		Issuer issuer = issuerBuilder.buildObject();
		issuer.setValue(issuerName);
		authnRequest.setIssuer(issuer);

		SAMLObjectBuilder<Endpoint> endpointBuilder = (SAMLObjectBuilder<Endpoint>) builderFactory
				.getBuilder(AssertionConsumerService.DEFAULT_ELEMENT_NAME);
		Endpoint samlEndpoint = endpointBuilder.buildObject();
		samlEndpoint.setLocation(idpEndpoint);
		samlEndpoint.setResponseLocation(spDestination);

		OutTransport outTransport = new HttpServletResponseAdapter(response,
				true);

		BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();
		messageContext.setOutboundMessageTransport(outTransport);
		messageContext.setPeerEntityEndpoint(samlEndpoint);
		messageContext.setOutboundSAMLMessage(authnRequest);
		messageContext.setRelayState(relayState);

		// sign request if a SP identity is specified
		if (null != spIdentity) {

			List<X509Certificate> certChain = new LinkedList<X509Certificate>();
			for (Certificate certificate : spIdentity.getCertificateChain()) {
				certChain.add((X509Certificate) certificate);
			}

			BasicX509Credential credential = new BasicX509Credential();
			credential.setPrivateKey(spIdentity.getPrivateKey());
			credential.setEntityCertificateChain(certChain);

			// enable adding the cert.chain as KeyInfo
			X509KeyInfoGeneratorFactory factory = (X509KeyInfoGeneratorFactory) org.opensaml.xml.Configuration
					.getGlobalSecurityConfiguration()
					.getKeyInfoGeneratorManager().getDefaultManager()
					.getFactory(credential);
			factory.setEmitEntityCertificateChain(true);

			messageContext.setOutboundSAMLMessageSigningCredential(credential);
		}

		VelocityEngine velocityEngine = new VelocityEngine();
		velocityEngine.setProperty(RuntimeConstants.RESOURCE_LOADER,
				"classpath");
		velocityEngine
				.setProperty("classpath.resource.loader.class",
						"org.apache.velocity.runtime.resource.loader.ClasspathResourceLoader");
		velocityEngine.setProperty(
				RuntimeConstants.RUNTIME_LOG_LOGSYSTEM_CLASS,
				Log4JLogChute.class.getName());
		try {
			velocityEngine.init();
		} catch (Exception e) {
			throw new ServletException("velocity engine init error: "
					+ e.getMessage(), e);
		}
		HTTPPostEncoder encoder = new HTTPPostEncoder(velocityEngine,
				"/templates/saml2-post-binding.vm");
		try {
			encoder.encode(messageContext);
		} catch (MessageEncodingException e) {
			throw new ServletException(
					"SAML encoding error: " + e.getMessage(), e);
		}

		return authnRequest;
	}
}

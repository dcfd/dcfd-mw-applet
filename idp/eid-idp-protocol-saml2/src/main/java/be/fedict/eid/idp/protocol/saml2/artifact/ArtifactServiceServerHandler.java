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

package be.fedict.eid.idp.protocol.saml2.artifact;

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.HashSet;
import java.util.Set;

import javax.servlet.ServletContext;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.namespace.QName;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPFactory;
import javax.xml.soap.SOAPFault;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;
import javax.xml.ws.soap.SOAPFaultException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.ArtifactResolve;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Element;

import be.fedict.eid.idp.common.saml2.Saml2Util;
import be.fedict.eid.idp.protocol.saml2.AbstractSAML2ProtocolService;
import be.fedict.eid.idp.spi.IdPIdentity;
import be.fedict.eid.idp.spi.IdentityProviderConfiguration;

/**
 * Server SOAP handler for the SAML v2.0 Artifact Binding Service.
 * <p/>
 * Used for validation and signing.
 * 
 * @author Wim Vandenhaute
 */
public class ArtifactServiceServerHandler implements
		SOAPHandler<SOAPMessageContext> {

	private static final Log LOG = LogFactory
			.getLog(ArtifactServiceServerHandler.class);

	private static final String XPATH_ARTIFACT_RESOLVE = "/soap:Envelope/soap:Body/samlp:ArtifactResolve";
	private static final String XPATH_ARTIFACT_RESOLVE_SIGNATURE = "/soap:Envelope/soap:Body/samlp:ArtifactResolve/ds:Signature";

	private static final String XPATH_ARTIFACT_RESPONSE = "/soap:Envelope/soap:Body/samlp:ArtifactResponse";
	private static final String XPATH_STATUS = "/soap:Envelope/soap:Body/samlp:ArtifactResponse/samlp:Status";

	private static final String XPATH_RESPONSE = "/soap:Envelope/soap:Body/samlp:ArtifactResponse/samlp:Response";
	private static final String XPATH_RESPONSE_STATUS = "/soap:Envelope/soap:Body/samlp:ArtifactResponse/samlp:Response/samlp:Status";

	private static final String XPATH_RESPONSE_ASSERTION = "/soap:Envelope/soap:Body/samlp:ArtifactResponse/samlp:Response/saml:Assertion";
	private static final String XPATH_RESPONSE_ASSERTION_ISSUER = "/soap:Envelope/soap:Body/samlp:ArtifactResponse/samlp:Response/saml:Assertion/saml:Issuer";

	public Set<QName> getHeaders() {
		return new HashSet<QName>();
	}

	public boolean handleMessage(SOAPMessageContext soapMessageContext) {

		Boolean outbound = (Boolean) soapMessageContext
				.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);

		SOAPMessage soapMessage = soapMessageContext.getMessage();
		SOAPPart soapPart = soapMessage.getSOAPPart();

		if (outbound) {

			handleOutboundDocument(soapPart, soapMessageContext);
		} else {
			handleInboundDocument(soapPart);
		}

		return true;

	}

	private void handleOutboundDocument(SOAPPart soapPart,
			SOAPMessageContext soapMessageContext) {

		LOG.debug("handle outbound");

		// find optional IdP Identity for signing
		ServletContext servletContext = (ServletContext) soapMessageContext
				.get(MessageContext.SERVLET_CONTEXT);
		IdentityProviderConfiguration configuration = AbstractSAML2ProtocolService
				.getIdPConfiguration(servletContext);
		IdPIdentity idpIdentity = configuration.findIdentity();

		if (null != idpIdentity) {

			try {
				LOG.debug("IdP Identity found, singing...");

				// find assertion and sing
				if (null != Saml2Util.find(soapPart, XPATH_RESPONSE_ASSERTION)) {
					sign(soapPart, XPATH_RESPONSE_ASSERTION,
							XPATH_RESPONSE_ASSERTION_ISSUER, idpIdentity);
				}

				// find Response and sign
				if (null != Saml2Util.find(soapPart, XPATH_RESPONSE)) {
					sign(soapPart, XPATH_RESPONSE, XPATH_RESPONSE_STATUS,
							idpIdentity);

				}

				// find ArtifactResponse and sign
				sign(soapPart, XPATH_ARTIFACT_RESPONSE, XPATH_STATUS,
						idpIdentity);

			} catch (NoSuchAlgorithmException e) {
				throw createSOAPFaultException("Signing failed: "
						+ "NoSuchAlgorithmException: " + e.getMessage());
			} catch (InvalidAlgorithmParameterException e) {
				throw createSOAPFaultException("Signing failed: "
						+ "InvalidAlgorithmParameterException: "
						+ e.getMessage());
			} catch (MarshalException e) {
				throw createSOAPFaultException("Signing failed: "
						+ "MarshalException: " + e.getMessage());
			} catch (XMLSignatureException e) {
				throw createSOAPFaultException("Signing failed: "
						+ "XMLSignatureException: " + e.getMessage());
			}

		}
	}

	private void sign(SOAPPart soapPart, String elementXPath,
			String nextSiblingXPath, IdPIdentity idpIdentity)
			throws MarshalException, NoSuchAlgorithmException,
			XMLSignatureException, InvalidAlgorithmParameterException {

		// find ArtifactResponse and sign
		Element element = (Element) Saml2Util.find(soapPart, elementXPath);
		if (null == element) {
			throw new RuntimeException("Element not found: " + elementXPath);
		}
		Element nextSibling = (Element) Saml2Util.find(soapPart,
				nextSiblingXPath);
		if (null == nextSibling) {
			throw new RuntimeException("NextSibling not found: "
					+ nextSiblingXPath);
		}

		Saml2Util.signDocument(element, nextSibling,
				idpIdentity.getPrivateKeyEntry());
	}

	private void handleInboundDocument(SOAPPart soapPart) {

		LOG.debug("handle inbound");

		// find ArtifactResolve signature
		if (null != Saml2Util.find(soapPart, XPATH_ARTIFACT_RESOLVE_SIGNATURE)) {

			LOG.debug("validate ArtifactResolve signature");
			Element artifactResolveElement = (Element) Saml2Util.find(soapPart,
					XPATH_ARTIFACT_RESOLVE);

			ArtifactResolve artifactResolve = Saml2Util
					.unmarshall(artifactResolveElement);

			// validate signature
			try {
				Saml2Util.validateSignature(artifactResolve.getSignature());

			} catch (CertificateException e) {

				throw createSOAPFaultException("Error parsing certificates from XML"
						+ "signature");
			} catch (ValidationException e) {
				throw createSOAPFaultException("Validation failed on XML signature");
			}
		}
	}

	public boolean handleFault(SOAPMessageContext soapMessageContext) {
		return true;
	}

	public void close(MessageContext messageContext) {
		// empty
	}

	private SOAPFaultException createSOAPFaultException(String faultString) {

		SOAPFault soapFault;
		try {
			SOAPFactory soapFactory = SOAPFactory.newInstance();
			soapFault = soapFactory.createFault();
			soapFault.setFaultString(faultString);
		} catch (SOAPException e) {
			throw new RuntimeException("SOAP error");
		}

		return new SOAPFaultException(soapFault);
	}

}

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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.HashSet;
import java.util.Set;

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
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Response;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Element;

import be.fedict.eid.idp.common.saml2.Saml2Util;

/**
 * Client SOAP handler for the SAML v2.0 Artifact Binding Service.
 * <p/>
 * Used for optionally signing the SAML v2.0 Artifact Resolve request.
 * 
 * @author Wim Vandenhaute
 */
public class ArtifactServiceClientHandler implements
		SOAPHandler<SOAPMessageContext> {

	private static final Log LOG = LogFactory
			.getLog(ArtifactServiceClientHandler.class);

	private static final String XPATH_ARTIFACT_RESOLVE = "/soap:Envelope/soap:Body/samlp:ArtifactResolve";
	private static final String XPATH_ARTIFACT = "/soap:Envelope/soap:Body/samlp:ArtifactResolve/samlp:Artifact";

	private static final String XPATH_ARTIFACT_RESPONSE = "/soap:Envelope/soap:Body/samlp:ArtifactResponse";
	private static final String XPATH_ARTIFACT_RESPONSE_SIGNATURE = "/soap:Envelope/soap:Body/samlp:ArtifactResponse/ds:Signature";

	private static final String XPATH_RESPONSE = "/soap:Envelope/soap:Body/samlp:ArtifactResponse/samlp:Response";
	private static final String XPATH_RESPONSE_ASSERTION = "/soap:Envelope/soap:Body/samlp:ArtifactResponse/samlp:Response/saml:Assertion";

	private final KeyStore.PrivateKeyEntry spIdentity;
	private Response response;

	/**
	 * Main constructor.
	 * 
	 * @param spIdentity
	 *            optional SP Identity for signing outgoing artifact resolve
	 *            requests.
	 */
	public ArtifactServiceClientHandler(KeyStore.PrivateKeyEntry spIdentity) {
		this.spIdentity = spIdentity;
	}

	/**
	 * {@inheritDoc}
	 */
	public Set<QName> getHeaders() {
		return new HashSet<QName>();
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean handleMessage(SOAPMessageContext soapMessageContext) {

		Boolean outbound = (Boolean) soapMessageContext
				.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);

		SOAPMessage soapMessage = soapMessageContext.getMessage();
		SOAPPart soapPart = soapMessage.getSOAPPart();

		if (outbound) {

			handleOutboundDocument(soapPart);
		} else {
			handleInboundDocument(soapPart);
		}

		return true;

	}

	private void handleOutboundDocument(SOAPPart soapPart) {

		LOG.debug("handle outbound");

		// find ArtifactResolve and Artifact elements
		Element artifactResolve = (Element) Saml2Util.find(soapPart,
				XPATH_ARTIFACT_RESOLVE);
		if (null == artifactResolve) {
			throw new RuntimeException("No ArtifactResolve ?!");
		}
		Element artifact = (Element) Saml2Util.find(soapPart, XPATH_ARTIFACT);
		if (null == artifact) {
			throw new RuntimeException("No Artifact ?!");
		}

		// sign
		try {
			Saml2Util.signDocument(artifactResolve, artifact, this.spIdentity);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new RuntimeException(e);
		} catch (MarshalException e) {
			throw new RuntimeException(e);
		} catch (XMLSignatureException e) {
			throw new RuntimeException(e);
		}

	}

	private void handleInboundDocument(SOAPPart soapPart) {

		LOG.debug("handle inbound");

		// find and validate ArtifactResponse,Response,Assertion signature
		if (null != Saml2Util.find(soapPart, XPATH_ARTIFACT_RESPONSE_SIGNATURE)) {

			try {

				Element artifactResponseElement = (Element) Saml2Util.find(
						soapPart, XPATH_ARTIFACT_RESPONSE);
				ArtifactResponse artifactResponse = Saml2Util
						.unmarshall(artifactResponseElement);
				LOG.debug("validate ArtifactResponse signature");
				Saml2Util.validateSignature(artifactResponse.getSignature());

				Element responseElement = (Element) Saml2Util.find(soapPart,
						XPATH_RESPONSE);
				if (null != responseElement) {
					Response tempResponse = Saml2Util
							.unmarshall(responseElement);
					LOG.debug("validate Response signature");
					Saml2Util.validateSignature(tempResponse.getSignature());
				}

				Element assertionElement = (Element) Saml2Util.find(soapPart,
						XPATH_RESPONSE_ASSERTION);
				if (null != assertionElement) {
					Assertion assertion = Saml2Util
							.unmarshall(assertionElement);
					LOG.debug("validate Assertion signature");
					Saml2Util.validateSignature(assertion.getSignature());
				}

			} catch (CertificateException e) {

				throw createSOAPFaultException("Error parsing certificates from XML"
						+ "signature");
			} catch (ValidationException e) {
				throw createSOAPFaultException("Validation failed on XML signature");
			}
		}

		// fetch response
		Element responseElement = (Element) Saml2Util.find(soapPart,
				XPATH_RESPONSE);
		if (null != responseElement) {
			Saml2Util.unmarshall(responseElement);

			// to string and back again so we do not
			// run into problems trying to marshall
			String responseString = Saml2Util.domToString(responseElement,
					false);

			this.response = Saml2Util.unmarshall(Saml2Util.parseDocument(
					responseString).getDocumentElement());
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean handleFault(SOAPMessageContext soapMessageContext) {
		return true;
	}

	/**
	 * {@inheritDoc}
	 */
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

	/**
	 * We return the SAML v2.0 Response through the SOAP handler as JAXB will
	 * break XML Signatures when unmarshalling.
	 * 
	 * @return the validated SAML v2.0 Response.
	 */
	public Response getResponse() {
		return this.response;
	}
}

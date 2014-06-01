/*
 * eID Identity Provider Project.
 * Copyright (C) 2012 FedICT.
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

package be.fedict.eid.idp.protocol.ws_federation.sts;

import java.io.StringWriter;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import javax.annotation.Resource;
import javax.jws.HandlerChain;
import javax.jws.WebService;
import javax.servlet.ServletContext;
import javax.xml.bind.JAXBElement;
import javax.xml.namespace.QName;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.ws.BindingType;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.Init;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.Constants;
import org.apache.xpath.XPathAPI;
import org.joda.time.DateTime;
import org.joda.time.format.DateTimeFormatter;
import org.joda.time.format.ISODateTimeFormat;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import be.fedict.eid.idp.common.SamlAuthenticationPolicy;
import be.fedict.eid.idp.spi.IdentityProviderConfiguration;
import be.fedict.eid.idp.spi.IdentityProviderConfigurationFactory;
import be.fedict.eid.idp.wstrust.WSTrustConstants;
import be.fedict.eid.idp.wstrust.jaxb.wsaddr.EndpointReferenceType;
import be.fedict.eid.idp.wstrust.jaxb.wspolicy.AppliesTo;
import be.fedict.eid.idp.wstrust.jaxb.wstrust.ObjectFactory;
import be.fedict.eid.idp.wstrust.jaxb.wstrust.RequestSecurityTokenResponseCollectionType;
import be.fedict.eid.idp.wstrust.jaxb.wstrust.RequestSecurityTokenResponseType;
import be.fedict.eid.idp.wstrust.jaxb.wstrust.RequestSecurityTokenType;
import be.fedict.eid.idp.wstrust.jaxb.wstrust.StatusType;
import be.fedict.eid.idp.wstrust.jaxb.wstrust.ValidateTargetType;
import be.fedict.eid.idp.wstrust.jaxws.SecurityTokenServicePort;

/**
 * Implementation of WS-Trust STS token validation service. Via this web service
 * relying parties can validate the SAML assertions produced by the
 * WS-Federation web passive authentication protocol.
 * 
 * @author Frank Cornelis
 * 
 */
@WebService(endpointInterface = "be.fedict.eid.idp.wstrust.jaxws.SecurityTokenServicePort")
@BindingType("http://java.sun.com/xml/ns/jaxws/2003/05/soap/bindings/HTTP/")
@HandlerChain(file = "sts-ws-handlers.xml")
public class SecurityTokenServicePortImpl implements SecurityTokenServicePort {

	private static final Log LOG = LogFactory
			.getLog(SecurityTokenServicePortImpl.class);

	@Resource
	private WebServiceContext context;

	private final ObjectFactory objectFactory;

	public SecurityTokenServicePortImpl() {
		this.objectFactory = new ObjectFactory();
	}

	static {
		Init.init();
	}

	@Override
	public RequestSecurityTokenResponseCollectionType requestSecurityToken(
			RequestSecurityTokenType request) {
		List<Object> requestContent = request.getAny();
		String expectedAudience = null;
		for (Object requestObject : requestContent) {
			LOG.debug("request object type: "
					+ requestObject.getClass().getName());
			if (requestObject instanceof JAXBElement) {
				JAXBElement jaxbElement = (JAXBElement) requestObject;
				QName qname = jaxbElement.getName();
				if (WSTrustConstants.TOKEN_TYPE_QNAME.equals(qname)) {
					String tokenType = (String) jaxbElement.getValue();
					if (false == WSTrustConstants.STATUS_TOKEN_TYPE
							.equals(tokenType)) {
						throw new SecurityException(
								"invalid response token type: " + tokenType);
					}
				} else if (WSTrustConstants.REQUEST_TYPE_QNAME.equals(qname)) {
					String requestType = (String) jaxbElement.getValue();
					if (false == WSTrustConstants.VALIDATE_REQUEST_TYPE
							.equals(requestType)) {
						throw new SecurityException("invalid request type: "
								+ requestType);
					}
				} else if (WSTrustConstants.VALIDATE_TARGET_QNAME.equals(qname)) {
					ValidateTargetType validateTarget = (ValidateTargetType) jaxbElement
							.getValue();
					Object validateTargetObject = validateTarget.getAny();
					if (null == validateTargetObject) {
						throw new SecurityException(
								"missing ValidateTarget content");
					}
					LOG.debug("ValidateTarget content type: "
							+ validateTargetObject.getClass().getName());
					// TODO: verify content is indeed SecurityTokenReference
				}
			} else if (requestObject instanceof AppliesTo) {
				AppliesTo appliesTo = (AppliesTo) requestObject;
				LOG.debug("wsp:AppliesTo present");
				List<Object> appliesToContent = appliesTo.getAny();
				for (Object appliesToObject : appliesToContent) {
					LOG.debug("AppliesTo object type: "
							+ appliesToObject.getClass().getName());
					if (appliesToObject instanceof JAXBElement) {
						JAXBElement appliesToElement = (JAXBElement) appliesToObject;
						QName appliesToQName = appliesToElement.getName();
						if (WSTrustConstants.ENDPOINT_REFERENCE_QNAME
								.equals(appliesToQName)) {
							EndpointReferenceType endpointReference = (EndpointReferenceType) appliesToElement
									.getValue();
							expectedAudience = endpointReference.getAddress()
									.getValue();
						}
					}
				}
			}
		}
		Element tokenElement = WSSecuritySoapHandler.getToken(this.context);
		if (null == tokenElement) {
			throw new SecurityException("missing Token");
		}
		LOG.debug("token element: " + tokenElement.getLocalName());
		LOG.debug("expected audience: " + expectedAudience);

		ServletContext servletContext = (ServletContext) context
				.getMessageContext().get(MessageContext.SERVLET_CONTEXT);
		IdentityProviderConfiguration identityProviderConfiguration = IdentityProviderConfigurationFactory
				.getInstance(servletContext);

		boolean valid;
		String reason = null;
		try {
			validateToken(tokenElement, expectedAudience,
					identityProviderConfiguration);
			valid = true;
		} catch (Exception e) {
			LOG.error("error validating SAML token: " + e.getMessage(), e);
			valid = false;
			reason = e.getMessage();
		}

		RequestSecurityTokenResponseCollectionType responseCollection = this.objectFactory
				.createRequestSecurityTokenResponseCollectionType();

		List<RequestSecurityTokenResponseType> requestSecurityTokenResponses = responseCollection
				.getRequestSecurityTokenResponse();

		RequestSecurityTokenResponseType requestSecurityTokenResponse = this.objectFactory
				.createRequestSecurityTokenResponseType();
		requestSecurityTokenResponses.add(requestSecurityTokenResponse);

		List<Object> rstsContent = requestSecurityTokenResponse.getAny();

		rstsContent.add(this.objectFactory
				.createTokenType(WSTrustConstants.STATUS_TOKEN_TYPE));

		StatusType status = this.objectFactory.createStatusType();
		rstsContent.add(this.objectFactory.createStatus(status));
		if (valid) {
			status.setCode(WSTrustConstants.VALID_STATUS_CODE);
		} else {
			status.setCode(WSTrustConstants.INVALID_STATUS_CODE);
			status.setReason(reason);
		}

		return responseCollection;
	}

	private void validateToken(Element tokenElement, String expectedAudience,
			IdentityProviderConfiguration identityProviderConfiguration)
			throws Exception {
		List<X509Certificate> certificateChain = identityProviderConfiguration
				.getIdentityCertificateChain();
		if (certificateChain.isEmpty()) {
			throw new SecurityException(
					"no eID IdP service identity configured");
		}

		Element nsElement = tokenElement.getOwnerDocument().createElement(
				"nsElement");
		nsElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:ds",
				"http://www.w3.org/2000/09/xmldsig#");
		nsElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:saml2",
				"urn:oasis:names:tc:SAML:2.0:assertion");
		LOG.debug("token element: " + tokenElement.getLocalName());
		LOG.debug("token element namespace: " + tokenElement.getNamespaceURI());
		LOG.debug("token: " + toString(tokenElement));
		
		// fix for recent versions of Apache xmlsec.
		tokenElement.setIdAttribute("ID", true);
		
		Element signatureElement = (Element) XPathAPI.selectSingleNode(
				tokenElement, "ds:Signature", nsElement);
		if (null == signatureElement) {
			throw new SecurityException("missing XML signature");
		}

		XMLSignature xmlSignature = new XMLSignature(signatureElement, "");
		KeyInfo keyInfo = xmlSignature.getKeyInfo();
		X509Certificate actualCertificate = keyInfo.getX509Certificate();
		boolean signatureResult = xmlSignature
				.checkSignatureValue(actualCertificate);
		if (false == signatureResult) {
			throw new SecurityException("invalid XML signature");
		}
		LOG.debug("XML signature OK");

		X509Certificate serviceCertificate = certificateChain.get(0);
		if (false == Arrays.equals(serviceCertificate.getEncoded(),
				actualCertificate.getEncoded())) {
			throw new SecurityException(
					"SAML signing certificate different from eID IdP service identity");
		}
		LOG.debug("SAML signer OK");

		String actualIssuer = XPathAPI.selectSingleNode(tokenElement,
				"saml2:Issuer/text()", nsElement).getNodeValue();
		String serviceIssuer = identityProviderConfiguration.getDefaultIssuer();
		if (false == actualIssuer.equals(serviceIssuer)) {
			LOG.debug("actual issuer: " + actualIssuer);
			LOG.debug("service issuer: " + serviceIssuer);
			throw new SecurityException("wrong SAML issuer");
		}
		LOG.debug("SAML issuer OK");

		if (null != expectedAudience) {
			String audience = XPathAPI
					.selectSingleNode(
							tokenElement,
							"saml2:Conditions/saml2:AudienceRestriction/saml2:Audience/text()",
							nsElement).getNodeValue();
			if (false == expectedAudience.equals(audience)) {
				LOG.debug("expected audience: " + expectedAudience);
				LOG.debug("actual audience: " + audience);
				throw new SecurityException("incorrect SAML audience");
			}
			LOG.debug("SAML Audience OK");
		} else {
			LOG.warn("SAML audience restriction not checked");
		}

		String authnContextClassRef = XPathAPI
				.selectSingleNode(
						tokenElement,
						"saml2:AuthnStatement/saml2:AuthnContext/saml2:AuthnContextClassRef/text()",
						nsElement).getNodeValue();
		LOG.debug("AuthnContextClassRef: " + authnContextClassRef);
		SamlAuthenticationPolicy samlAuthenticationPolicy = SamlAuthenticationPolicy
				.getAuthenticationPolicy(authnContextClassRef);
		if (SamlAuthenticationPolicy.AUTHENTICATION != samlAuthenticationPolicy
				&& SamlAuthenticationPolicy.AUTHENTICATION_WITH_IDENTIFICATION != samlAuthenticationPolicy) {
			throw new SecurityException("wrong SAML authentication policy: "
					+ samlAuthenticationPolicy);
		}

		String notBeforeStr = XPathAPI.selectSingleNode(tokenElement,
				"saml2:Conditions/@NotBefore", nsElement).getNodeValue();
		String notOnOrAfterStr = XPathAPI.selectSingleNode(tokenElement,
				"saml2:Conditions/@NotOnOrAfter", nsElement).getNodeValue();
		DateTimeFormatter dateTimeFormatter = ISODateTimeFormat
				.dateTimeParser();
		DateTime notBefore = dateTimeFormatter.parseDateTime(notBeforeStr);
		DateTime notOnOrAfter = dateTimeFormatter
				.parseDateTime(notOnOrAfterStr);
		DateTime now = new DateTime();
		if (now.isBefore(notBefore)) {
			throw new SecurityException("SAML assertion in future");
		}
		if (now.isAfter(notOnOrAfter)) {
			throw new SecurityException("SAML assertion expired");
		}
		LOG.debug("SAML timestamp OK");
	}

	static String toString(Node dom) throws TransformerException {
		Source source = new DOMSource(dom);
		StringWriter stringWriter = new StringWriter();
		Result result = new StreamResult(stringWriter);
		TransformerFactory transformerFactory = TransformerFactory
				.newInstance();
		Transformer transformer = transformerFactory.newTransformer();
		transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
		transformer.transform(source, result);
		return stringWriter.getBuffer().toString();
	}
}

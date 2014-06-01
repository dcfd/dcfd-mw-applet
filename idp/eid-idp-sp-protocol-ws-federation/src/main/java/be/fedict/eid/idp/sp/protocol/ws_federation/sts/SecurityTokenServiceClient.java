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

package be.fedict.eid.idp.sp.protocol.ws_federation.sts;

import java.util.List;

import javax.xml.bind.JAXBElement;
import javax.xml.namespace.QName;
import javax.xml.ws.Binding;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.handler.Handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import be.fedict.eid.idp.wstrust.SecurityTokenServiceFactory;
import be.fedict.eid.idp.wstrust.WSTrustConstants;
import be.fedict.eid.idp.wstrust.jaxb.wsaddr.AttributedURIType;
import be.fedict.eid.idp.wstrust.jaxb.wsaddr.EndpointReferenceType;
import be.fedict.eid.idp.wstrust.jaxb.wspolicy.AppliesTo;
import be.fedict.eid.idp.wstrust.jaxb.wsse.KeyIdentifierType;
import be.fedict.eid.idp.wstrust.jaxb.wsse.SecurityTokenReferenceType;
import be.fedict.eid.idp.wstrust.jaxb.wstrust.ObjectFactory;
import be.fedict.eid.idp.wstrust.jaxb.wstrust.RequestSecurityTokenResponseCollectionType;
import be.fedict.eid.idp.wstrust.jaxb.wstrust.RequestSecurityTokenResponseType;
import be.fedict.eid.idp.wstrust.jaxb.wstrust.RequestSecurityTokenType;
import be.fedict.eid.idp.wstrust.jaxb.wstrust.StatusType;
import be.fedict.eid.idp.wstrust.jaxb.wstrust.ValidateTargetType;
import be.fedict.eid.idp.wstrust.jaxws.SecurityTokenService;
import be.fedict.eid.idp.wstrust.jaxws.SecurityTokenServicePort;

/**
 * WS-Trust STS client to validate SAML tokens via the eID IdP.
 * 
 * @author Frank Cornelis
 * 
 */
public class SecurityTokenServiceClient {

	private static final Log LOG = LogFactory
			.getLog(SecurityTokenServiceClient.class);

	public static final QName STATUS_QNAME = new QName(
			WSTrustConstants.WS_TRUST_NAMESPACE, "Status");

	private final SecurityTokenServicePort port;

	private final ObjectFactory objectFactory;

	private final be.fedict.eid.idp.wstrust.jaxb.wspolicy.ObjectFactory policyObjectFactory;

	private final be.fedict.eid.idp.wstrust.jaxb.wsaddr.ObjectFactory addrObjectFactory;

	private final be.fedict.eid.idp.wstrust.jaxb.wsse.ObjectFactory wsseObjectFactory;

	/**
	 * Main constructor.
	 * 
	 * @param location
	 *            the location of the STS service.
	 */
	public SecurityTokenServiceClient(String location) {
		SecurityTokenService securityTokenService = SecurityTokenServiceFactory
				.getInstance();

		this.port = securityTokenService.getSecurityTokenServicePort();
		BindingProvider bindingProvider = (BindingProvider) this.port;
		bindingProvider.getRequestContext().put(
				BindingProvider.ENDPOINT_ADDRESS_PROPERTY, location);

		Binding binding = bindingProvider.getBinding();
		List<Handler> handlerChain = binding.getHandlerChain();
		handlerChain.add(new WSSecuritySoapHandler());
		handlerChain.add(new LoggingSoapHandler());
		binding.setHandlerChain(handlerChain);

		this.objectFactory = new ObjectFactory();
		this.policyObjectFactory = new be.fedict.eid.idp.wstrust.jaxb.wspolicy.ObjectFactory();
		this.addrObjectFactory = new be.fedict.eid.idp.wstrust.jaxb.wsaddr.ObjectFactory();
		this.wsseObjectFactory = new be.fedict.eid.idp.wstrust.jaxb.wsse.ObjectFactory();
	}

	/**
	 * Validates the given SAML assertion via the eID IdP WS-Trust STS
	 * validation service.
	 * 
	 * @param samlAssertionElement
	 *            the SAML assertion DOM element to be validated.
	 * @see SecurityTokenServiceClient#validateToken(Element, String)
	 */
	public void validateToken(Element samlAssertionElement) {
		validateToken(samlAssertionElement, null);
	}

	/**
	 * Validates the given SAML assertion via the eID IdP WS-Trust STS
	 * validation service.
	 * 
	 * @param samlAssertionElement
	 *            the SAML assertion DOM element to be validated.
	 * @param expectedSAMLAudience
	 *            the optional (but recommended) expected value for SAML
	 *            Audience.
	 */
	public void validateToken(Element samlAssertionElement,
			String expectedSAMLAudience) {
		RequestSecurityTokenType request = this.objectFactory
				.createRequestSecurityTokenType();
		List<Object> requestContent = request.getAny();

		requestContent.add(this.objectFactory
				.createRequestType(WSTrustConstants.VALIDATE_REQUEST_TYPE));

		requestContent.add(this.objectFactory
				.createTokenType(WSTrustConstants.STATUS_TOKEN_TYPE));

		ValidateTargetType validateTarget = this.objectFactory
				.createValidateTargetType();
		requestContent.add(this.objectFactory
				.createValidateTarget(validateTarget));

		BindingProvider bindingProvider = (BindingProvider) this.port;
		WSSecuritySoapHandler.setAssertion(samlAssertionElement,
				bindingProvider);
		SecurityTokenReferenceType securityTokenReference = this.wsseObjectFactory
				.createSecurityTokenReferenceType();
		validateTarget.setAny(this.wsseObjectFactory
				.createSecurityTokenReference(securityTokenReference));
		securityTokenReference.getOtherAttributes().put(
				new QName(WSTrustConstants.WS_SECURITY_11_NAMESPACE,
						"TokenType"), WSTrustConstants.SAML2_WSSE11_TOKEN_TYPE);
		KeyIdentifierType keyIdentifier = this.wsseObjectFactory
				.createKeyIdentifierType();
		securityTokenReference.getAny().add(
				this.wsseObjectFactory.createKeyIdentifier(keyIdentifier));
		String samlAssertionId = samlAssertionElement.getAttribute("ID");
		LOG.debug("SAML assertion ID: " + samlAssertionId);
		keyIdentifier.setValue(samlAssertionId);
		keyIdentifier
				.getOtherAttributes()
				.put(new QName(WSTrustConstants.WS_SECURITY_NAMESPACE,
						"ValueType"),
						"http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLID");

		if (null != expectedSAMLAudience) {
			AppliesTo appliesTo = this.policyObjectFactory.createAppliesTo();
			requestContent.add(appliesTo);
			EndpointReferenceType endpointReference = this.addrObjectFactory
					.createEndpointReferenceType();
			appliesTo.getAny().add(
					this.addrObjectFactory
							.createEndpointReference(endpointReference));
			AttributedURIType address = this.addrObjectFactory
					.createAttributedURIType();
			endpointReference.setAddress(address);
			address.setValue(expectedSAMLAudience);
		}

		RequestSecurityTokenResponseCollectionType response = this.port
				.requestSecurityToken(request);

		if (null == response) {
			throw new SecurityException("missing RSTRC");
		}
		List<RequestSecurityTokenResponseType> responseList = response
				.getRequestSecurityTokenResponse();
		if (1 != responseList.size()) {
			throw new SecurityException("response list should contain 1 entry");
		}
		RequestSecurityTokenResponseType requestSecurityTokenResponse = responseList
				.get(0);
		List<Object> requestSecurityTokenResponseContent = requestSecurityTokenResponse
				.getAny();
		boolean hasStatus = false;
		for (Object requestSecurityTokenResponseObject : requestSecurityTokenResponseContent) {
			if (requestSecurityTokenResponseObject instanceof JAXBElement) {
				JAXBElement jaxbElement = (JAXBElement) requestSecurityTokenResponseObject;
				QName qname = jaxbElement.getName();
				if (WSTrustConstants.TOKEN_TYPE_QNAME.equals(qname)) {
					String tokenType = (String) jaxbElement.getValue();
					if (false == WSTrustConstants.STATUS_TOKEN_TYPE
							.equals(tokenType)) {
						throw new SecurityException(
								"invalid response token type: " + tokenType);
					}
				} else if (STATUS_QNAME.equals(qname)) {
					StatusType status = (StatusType) jaxbElement.getValue();
					String statusCode = status.getCode();
					if (false == WSTrustConstants.VALID_STATUS_CODE
							.equals(statusCode)) {
						String reason = status.getReason();
						throw new SecurityException("invalid token: " + reason);
					}
					hasStatus = true;
				}
			}
		}
		if (false == hasStatus) {
			throw new SecurityException("missing wst:Status");
		}
	}
}

/*
 * eID Identity Provider Project.
 * Copyright (C) 2010-2012 FedICT.
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

import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.namespace.QName;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPHeaderElement;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.ProtocolException;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.message.token.Timestamp;
import org.w3c.dom.Element;

import be.fedict.eid.idp.wstrust.WSTrustConstants;

/**
 * WS-Security JAX-WS SOAP handler implementing SAML Token Profile.
 * 
 * @author Frank Cornelis
 * 
 */
public class WSSecuritySoapHandler implements SOAPHandler<SOAPMessageContext> {

	private static final String ASSERTION_CONTEXT_ATTRIBUTE = WSSecuritySoapHandler.class
			.getName() + ".assertion";

	public boolean handleMessage(SOAPMessageContext context) {
		Boolean outboundProperty = (Boolean) context
				.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
		if (outboundProperty) {
			try {
				handleOutboundMessage(context);
			} catch (Exception e) {
				throw new ProtocolException("error: " + e.getMessage(), e);
			}
		} else {
			try {
				handleInboundMessage(context);
			} catch (Exception e) {
				throw new ProtocolException("error: " + e.getMessage(), e);
			}
		}
		return true;
	}

	private void handleInboundMessage(SOAPMessageContext context)
			throws WSSecurityException {
		SOAPMessage soapMessage = context.getMessage();
		SOAPPart soapPart = soapMessage.getSOAPPart();
		WSSecurityEngine secEngine = new WSSecurityEngine();
		List<WSSecurityEngineResult> results = secEngine.processSecurityHeader(
				soapPart, null, null, null);
		if (null == results) {
			throw new SecurityException("no WS-Security results");
		}

		Timestamp timestamp = null;
		for (WSSecurityEngineResult result : results) {
			Timestamp resultTimestamp = (Timestamp) result
					.get(WSSecurityEngineResult.TAG_TIMESTAMP);
			if (null != resultTimestamp) {
				timestamp = resultTimestamp;
			}
		}

		if (null == timestamp) {
			throw new SecurityException("no WS-Security timestamp");
		}
	}

	private void handleOutboundMessage(SOAPMessageContext context)
			throws SOAPException {
		SOAPMessage soapMessage = context.getMessage();
		SOAPPart soapPart = soapMessage.getSOAPPart();
		SOAPEnvelope soapEnvelope = soapPart.getEnvelope();
		SOAPHeader soapHeader = soapEnvelope.getHeader();
		if (null == soapHeader) {
			soapHeader = soapEnvelope.addHeader();
		}

		Element assertionElement = (Element) context
				.get(ASSERTION_CONTEXT_ATTRIBUTE);
		if (null == assertionElement) {
			return;
		}

		SOAPHeaderElement securityHeaderElement = soapHeader
				.addHeaderElement(new QName(
						WSTrustConstants.WS_SECURITY_NAMESPACE, "Security",
						"wsse"));
		securityHeaderElement.setMustUnderstand(true);
		securityHeaderElement.appendChild(soapPart.importNode(assertionElement,
				true));
	}

	public boolean handleFault(SOAPMessageContext context) {
		return true;
	}

	public void close(MessageContext context) {

	}

	public Set<QName> getHeaders() {
		Set<QName> headers = new HashSet<QName>();
		headers.add(new QName(WSTrustConstants.WS_SECURITY_NAMESPACE,
				"Security"));
		return headers;
	}

	public static void setAssertion(Element assertionElement,
			BindingProvider bindingProvider) {
		Map<String, Object> requestContext = bindingProvider
				.getRequestContext();
		requestContext.put(ASSERTION_CONTEXT_ATTRIBUTE, assertionElement);
	}
}

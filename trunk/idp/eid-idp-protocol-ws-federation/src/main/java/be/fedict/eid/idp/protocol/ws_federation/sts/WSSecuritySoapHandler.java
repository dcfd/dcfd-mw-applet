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

package be.fedict.eid.idp.protocol.ws_federation.sts;

import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import javax.xml.namespace.QName;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPHeaderElement;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;
import javax.xml.ws.ProtocolException;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.MessageContext.Scope;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecTimestamp;
import org.w3c.dom.Element;

import be.fedict.eid.idp.wstrust.WSTrustConstants;

/**
 * JAX-WS WS-Security SOAP Handler for WSS 1.1 SAML Token Profile token
 * extraction.
 * 
 * @author Frank Cornelis
 * 
 */
public class WSSecuritySoapHandler implements SOAPHandler<SOAPMessageContext> {

	private static final Log LOG = LogFactory
			.getLog(WSSecuritySoapHandler.class);

	private static final String SAML_TOKEN_CONTEXT_ATTRIBUTE = WSSecuritySoapHandler.class
			.getName() + ".samlToken";

	@Override
	public boolean handleMessage(SOAPMessageContext context) {
		Boolean outboundProperty = (Boolean) context
				.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
		if (true == outboundProperty.booleanValue()) {
			try {
				handleOutboundMessage(context);
			} catch (Exception e) {
				throw new ProtocolException(e);
			}
		} else {
			try {
				handleInboundMessage(context);
			} catch (Exception e) {
				throw new ProtocolException(e);
			}
		}
		return true;
	}

	private void handleInboundMessage(SOAPMessageContext context)
			throws SOAPException {
		SOAPMessage soapMessage = context.getMessage();
		SOAPPart soapPart = soapMessage.getSOAPPart();
		SOAPEnvelope soapEnvelope = soapPart.getEnvelope();
		SOAPHeader soapHeader = soapEnvelope.getHeader();
		if (null == soapHeader) {
			return;
		}
		Iterator<SOAPHeaderElement> headerIterator = soapHeader
				.examineAllHeaderElements();
		while (headerIterator.hasNext()) {
			SOAPHeaderElement soapHeaderElement = headerIterator.next();
			if (false == WSTrustConstants.WS_SECURITY_NAMESPACE
					.equals(soapHeaderElement.getNamespaceURI())) {
				continue;
			}
			if (false == "Security".equals(soapHeaderElement.getLocalName())) {
				continue;
			}
			Iterator<SOAPElement> securityElementIterator = soapHeaderElement
					.getChildElements();
			while (securityElementIterator.hasNext()) {
				SOAPElement securityElement = securityElementIterator.next();
				if (false == WSTrustConstants.SAML2_NAMESPACE
						.equals(securityElement.getNamespaceURI())) {
					continue;
				}
				if (false == "Assertion".equals(securityElement.getLocalName())) {
					continue;
				}
				LOG.debug("putting SAML token on JAX-WS context");
				context.put(SAML_TOKEN_CONTEXT_ATTRIBUTE, securityElement);
				context.setScope(SAML_TOKEN_CONTEXT_ATTRIBUTE,
						Scope.APPLICATION);
			}
		}
	}

	private void handleOutboundMessage(SOAPMessageContext context)
			throws SOAPException {
		SOAPMessage soapMessage = context.getMessage();
		SOAPPart soapPart = soapMessage.getSOAPPart();
		SOAPHeader soapHeader = soapMessage.getSOAPHeader();
		if (null == soapHeader) {
			SOAPEnvelope soapEnvelope = soapPart.getEnvelope();
			soapHeader = soapEnvelope.addHeader();
		}

		WSSecHeader wsSecHeader = new WSSecHeader();
		Element securityElement;
		try {
			securityElement = wsSecHeader.insertSecurityHeader(soapPart);
		} catch (WSSecurityException e) {
			throw new SOAPException("WS-Security error: " + e.getMessage(), e);
		}
		soapHeader.removeChild(securityElement);
		soapHeader.appendChild(securityElement);

		WSSecTimestamp wsSecTimeStamp = new WSSecTimestamp();
		wsSecTimeStamp.build(soapPart, wsSecHeader);
	}

	@Override
	public boolean handleFault(SOAPMessageContext context) {
		return true;
	}

	@Override
	public void close(MessageContext context) {

	}

	@Override
	public Set<QName> getHeaders() {
		Set<QName> headers = new HashSet<QName>();
		headers.add(new QName(WSTrustConstants.WS_SECURITY_NAMESPACE,
				"Security"));
		return headers;
	}

	public static Element getToken(WebServiceContext context) {
		MessageContext messageContext = context.getMessageContext();
		Element soapElement = (Element) messageContext
				.get(SAML_TOKEN_CONTEXT_ATTRIBUTE);
		return soapElement;
	}
}

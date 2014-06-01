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

package be.fedict.eid.idp.protocol.saml2.post;

import java.io.UnsupportedEncodingException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.Init;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.saml2.binding.encoding.BaseSAML2MessageEncoder;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.XMLHelper;
import org.w3c.dom.Element;

import be.fedict.eid.idp.protocol.saml2.HTTPOutTransport;

public class HTTPPostEncoder extends BaseSAML2MessageEncoder {

	private static final Log LOG = LogFactory.getLog(HTTPPostEncoder.class);

	static {
		Init.init();
	}

	@Override
	protected void doEncode(MessageContext messageContext)
			throws MessageEncodingException {
		LOG.debug("doEncode");

		if (!(messageContext instanceof SAMLMessageContext)) {
			LOG.error("Invalid message context type, this encoder only support SAMLMessageContext");
			throw new MessageEncodingException(
					"Invalid message context type, this encoder only support SAMLMessageContext");
		}
		SAMLMessageContext samlMessageContext = (SAMLMessageContext) messageContext;

		signMessage(samlMessageContext);

		if (!(messageContext.getOutboundMessageTransport() instanceof HTTPOutTransport)) {
			LOG.error("Invalid outbound message transport type, this encoder only support HTTPOutTransport");
			throw new MessageEncodingException(
					"Invalid outbound message transport type, this encoder only support HTTPOutTransport");
		}
		HTTPOutTransport httpOutTransport = (HTTPOutTransport) messageContext
				.getOutboundMessageTransport();

		SAMLObject outboundMessage = samlMessageContext
				.getOutboundSAMLMessage();
		if (outboundMessage == null) {
			throw new MessageEncodingException(
					"No outbound SAML message contained in message context");
		}

		Marshaller marshaller = Configuration.getMarshallerFactory()
				.getMarshaller(outboundMessage);
		try {
			marshaller.marshall(outboundMessage);
		} catch (MarshallingException e) {
			throw new MessageEncodingException(
					"Could not marshall the SAML response");
		}

		Element outboundMessageElement = outboundMessage.getDOM();
		if (null == outboundMessageElement) {
			throw new MessageEncodingException("could not get the DOM element");
		}

		String messageXML = XMLHelper.nodeToString(outboundMessageElement);
		String encodedMessage;
		try {
			encodedMessage = Base64.encodeBytes(messageXML.getBytes("UTF-8"),
					Base64.DONT_BREAK_LINES);
		} catch (UnsupportedEncodingException e) {
			throw new MessageEncodingException(e);
		}
		httpOutTransport.addParameter("SAMLResponse", encodedMessage);

		String relayState = samlMessageContext.getRelayState();
		if (null != relayState) {
			httpOutTransport.addParameter("RelayState", relayState);
		}
	}

	public String getBindingURI() {
		LOG.debug("getBindingURI");
		return null;
	}

	public boolean providesMessageConfidentiality(MessageContext messageContext)
			throws MessageEncodingException {
		LOG.debug("providesMessageConfidentiality");
		return false;
	}

	public boolean providesMessageIntegrity(MessageContext messageContext)
			throws MessageEncodingException {
		LOG.debug("providesMessageIntegrity");
		return false;
	}
}

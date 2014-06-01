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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.common.binding.SAMLMessageContext;
import org.opensaml.common.binding.artifact.SAMLArtifactMap;
import org.opensaml.ws.message.MessageContext;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HTTPTransportUtils;

import be.fedict.eid.idp.protocol.saml2.HTTPOutTransport;

public class HTTPArtifactEncoder extends
		org.opensaml.saml2.binding.encoding.HTTPArtifactEncoder {

	private static final Log LOG = LogFactory.getLog(HTTPArtifactEncoder.class);

	/**
	 * Constructor.
	 * 
	 * @param artifactMap
	 *            artifact map used to store artifact/message bindings
	 */
	public HTTPArtifactEncoder(SAMLArtifactMap artifactMap) {
		super(null, null, artifactMap);
	}

	@Override
	protected void doEncode(MessageContext messageContext)
			throws MessageEncodingException {

		LOG.debug("doEncode");

		if (!(messageContext instanceof SAMLMessageContext)) {
			String message = "Invalid message context type, "
					+ "this encoder only support SAMLMessageContext";
			LOG.error(message);
			throw new MessageEncodingException(message);
		}
		SAMLMessageContext samlMessageContext = (SAMLMessageContext) messageContext;

		signMessage(samlMessageContext);

		if (!(messageContext.getOutboundMessageTransport() instanceof HTTPOutTransport)) {
			String message = "Invalid outbound message transport type, "
					+ "this encoder only support HTTPOutTransport";
			LOG.error(message);
			throw new MessageEncodingException(message);
		}
		HTTPOutTransport httpOutTransport = (HTTPOutTransport) messageContext
				.getOutboundMessageTransport();

		SAMLMessageContext artifactContext = (SAMLMessageContext) messageContext;

		httpOutTransport.addParameter("SAMLart", buildArtifact(artifactContext)
				.base64Encode());

		String relayState = samlMessageContext.getRelayState();
		if (null != relayState) {
			httpOutTransport.addParameter("RelayState",
					HTTPTransportUtils.urlEncode(relayState));
		}
	}
}

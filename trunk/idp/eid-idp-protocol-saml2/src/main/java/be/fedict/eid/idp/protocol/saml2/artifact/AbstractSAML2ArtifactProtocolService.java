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

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;

import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.artifact.BasicSAMLArtifactMap;
import org.opensaml.common.binding.artifact.SAMLArtifactMap;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.util.storage.MapBasedStorageService;
import org.opensaml.ws.transport.OutTransport;

import be.fedict.eid.idp.protocol.saml2.AbstractSAML2ProtocolService;
import be.fedict.eid.idp.protocol.saml2.HTTPOutTransport;
import be.fedict.eid.idp.spi.IdentityProviderConfiguration;
import be.fedict.eid.idp.spi.ReturnResponse;

public abstract class AbstractSAML2ArtifactProtocolService extends
		AbstractSAML2ProtocolService {

	public static final String ARTIFACT_MAP_ATTRIBUTE = AbstractSAML2ArtifactProtocolService.class
			.getName() + "." + "ArtifactMap";

	@SuppressWarnings("unchecked")
	@Override
	protected ReturnResponse handleSamlResponse(HttpServletRequest request,
			String targetUrl, Response samlResponse, String relayState)
			throws Exception {

		ReturnResponse returnResponse = new ReturnResponse(targetUrl);

		HTTPArtifactEncoder messageEncoder = new HTTPArtifactEncoder(
				getArtifactMap(request.getSession().getServletContext()));
		BasicSAMLMessageContext messageContext = new BasicSAMLMessageContext();

		// used for construction of artifact by looking up IndexedEndpoint
		EntityDescriptor entityDescriptor = getEntityDescriptor(request);
		messageContext.setLocalEntityRoleMetadata(entityDescriptor
				.getRoleDescriptors().get(0));
		messageContext.setLocalEntityId(entityDescriptor.getEntityID());

		messageContext.setInboundMessageIssuer(getIssuer(request.getSession()));
		messageContext.setOutboundSAMLMessage(samlResponse);
		messageContext.setOutboundMessageIssuer(samlResponse.getIssuer()
				.getValue());
		messageContext.setRelayState(relayState);

		OutTransport outTransport = new HTTPOutTransport(returnResponse);
		messageContext.setOutboundMessageTransport(outTransport);

		messageEncoder.encode(messageContext);
		return returnResponse;
	}

	public static SAMLArtifactMap getArtifactMap(ServletContext context) {

		BasicSAMLArtifactMap artifactMap = (BasicSAMLArtifactMap) context
				.getAttribute(ARTIFACT_MAP_ATTRIBUTE);

		if (null == artifactMap) {

			IdentityProviderConfiguration configuration = getIdPConfiguration(context);

			int validity = 5;
			if (null != configuration.getResponseTokenValidity()
					&& configuration.getResponseTokenValidity() > 0) {
				validity = configuration.getResponseTokenValidity();
			}

			artifactMap = new BasicSAMLArtifactMap(
					new MapBasedStorageService<String, SAMLArtifactMap.SAMLArtifactMapEntry>(),
					validity * 60 * 1000);
			context.setAttribute(ARTIFACT_MAP_ATTRIBUTE, artifactMap);
		}
		return artifactMap;
	}

	protected abstract EntityDescriptor getEntityDescriptor(
			HttpServletRequest request);
}

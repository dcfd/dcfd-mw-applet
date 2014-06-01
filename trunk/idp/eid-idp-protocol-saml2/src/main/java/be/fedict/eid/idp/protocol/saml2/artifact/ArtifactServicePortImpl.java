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

import java.util.UUID;

import javax.annotation.Resource;
import javax.jws.HandlerChain;
import javax.jws.WebService;
import javax.servlet.ServletContext;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.binding.artifact.SAMLArtifactMap;
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;

import be.fedict.eid.idp.common.saml2.Saml2Util;
import be.fedict.eid.idp.saml2.ws.ArtifactServicePortType;
import be.fedict.eid.idp.saml2.ws.jaxb.ArtifactResolveType;
import be.fedict.eid.idp.saml2.ws.jaxb.ArtifactResponseType;

@WebService(endpointInterface = "be.fedict.eid.idp.saml2.ws.ArtifactServicePortType")
@HandlerChain(file = "ws-handlers.xml")
public class ArtifactServicePortImpl implements ArtifactServicePortType {

	private static final Log LOG = LogFactory
			.getLog(ArtifactServicePortImpl.class);

	@Resource
	private WebServiceContext context;

	public ArtifactResponseType resolve(ArtifactResolveType artifactResolveType) {

		LOG.debug("Resolve: " + artifactResolveType.getArtifact());

		ServletContext servletContext = (ServletContext) context
				.getMessageContext().get(MessageContext.SERVLET_CONTEXT);

		// construct successfull artifact response
		ArtifactResponse artifactResponse = getArtifactResponse(artifactResolveType
				.getID());

		// get SAML Artifact Map
		SAMLArtifactMap artifactMap = AbstractSAML2ArtifactProtocolService
				.getArtifactMap(servletContext);

		SAMLArtifactMap.SAMLArtifactMapEntry entry = artifactMap
				.get(artifactResolveType.getArtifact());

		// Add entry if found and remove from map
		if (null != entry) {

			// validate issuer with entry.issuer
			if (!entry.getRelyingPartyId().equals(
					artifactResolveType.getIssuer().getValue())) {
				String message = "ArtifactResolve Issuer ("
						+ artifactResolveType.getIssuer().getValue()
						+ ") does not match entry RP ID!";
				LOG.error(message + " (" + entry.getIssuerId() + ")");
				artifactResponse = getArtifactResponse(
						artifactResolveType.getID(),
						StatusCode.REQUEST_DENIED_URI, message);
			} else {

				LOG.debug("response found and added");
				artifactResponse.setMessage(entry.getSamlMessage());
				artifactMap.remove(artifactResolveType.getArtifact());
			}
		}

		return Saml2Util.toJAXB(artifactResponse, ArtifactResponseType.class);
	}

	private ArtifactResponse getArtifactResponse(String inResponseTo) {

		return getArtifactResponse(inResponseTo, StatusCode.SUCCESS_URI, null);
	}

	private ArtifactResponse getArtifactResponse(String inResponseTo,
			String statusCodeValue, String statusMessageValue) {

		ArtifactResponse artifactResponse = Saml2Util.buildXMLObject(
				ArtifactResponse.class, ArtifactResponse.DEFAULT_ELEMENT_NAME);
		DateTime issueInstant = new DateTime();
		artifactResponse.setIssueInstant(issueInstant);
		artifactResponse.setVersion(SAMLVersion.VERSION_20);
		artifactResponse.setID(UUID.randomUUID().toString());
		artifactResponse.setInResponseTo(inResponseTo);

		Status status = Saml2Util.buildXMLObject(Status.class,
				Status.DEFAULT_ELEMENT_NAME);
		artifactResponse.setStatus(status);
		StatusCode statusCode = Saml2Util.buildXMLObject(StatusCode.class,
				StatusCode.DEFAULT_ELEMENT_NAME);
		status.setStatusCode(statusCode);
		statusCode.setValue(statusCodeValue);
		if (null != statusMessageValue) {
			StatusMessage statusMessage = Saml2Util.buildXMLObject(
					StatusMessage.class, StatusMessage.DEFAULT_ELEMENT_NAME);
			statusMessage.setMessage(statusMessageValue);
			status.setStatusMessage(statusMessage);
		}

		return artifactResponse;
	}
}

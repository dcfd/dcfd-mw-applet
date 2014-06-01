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

import javax.servlet.http.HttpServletRequest;

import org.opensaml.saml2.core.Response;

import be.fedict.eid.idp.sp.protocol.saml2.AbstractAuthenticationResponseProcessor;
import be.fedict.eid.idp.sp.protocol.saml2.AuthenticationResponseProcessorException;
import be.fedict.eid.idp.sp.protocol.saml2.spi.AuthenticationResponseService;
import be.fedict.eid.idp.sp.protocol.saml2.spi.artifact.ArtifactAuthenticationResponseService;

/**
 * SAML v2.0 Authentication response processor for the HTTP Artifact binding.
 * 
 * @author Wim Vandenhaute
 */
public class AuthenticationResponseProcessor extends
		AbstractAuthenticationResponseProcessor {

	private final ArtifactAuthenticationResponseService service;

	/**
	 * Main Constructor
	 * 
	 * @param service
	 *            required {@link ArtifactAuthenticationResponseService} for
	 *            validation of certificate chain in returned SAML v2.0
	 *            Response. Required as the location of the eID IdP Artifact
	 *            Service is needed.
	 */
	public AuthenticationResponseProcessor(
			ArtifactAuthenticationResponseService service) {

		this.service = service;
	}

	/**
	 * Used the <tt>SAMLArt</tt> parameter in the HTTP Servlet Request and makes
	 * a call used the Artifact Web Service to resolve the SAML v2.0
	 * Authentication Response using the WS Client {@link ArtifactServiceClient}
	 * 
	 * @param request
	 *            HTTP Servlet Request
	 * @return the SAML v2.0 Authentication Response
	 * @throws AuthenticationResponseProcessorException
	 *             something went wrong trying to resolve the SAML v2.0
	 *             Authentication Response.
	 */
	@Override
	protected Response getSamlResponse(HttpServletRequest request)
			throws AuthenticationResponseProcessorException {

		String encodedArtifact = request.getParameter("SAMLart");
		if (null == encodedArtifact) {
			throw new AuthenticationResponseProcessorException(
					"No SAMLArt parameter found.");
		}
		LOG.debug("Encoded artifact: " + encodedArtifact);

		// construct client
		String location = this.service.getArtifactServiceLocation();
		LOG.debug("SAML2 Artifact Service: " + location);
		ArtifactServiceClient client = new ArtifactServiceClient(location,
				this.service.getServiceHostname(),
				this.service.getSPIdentity(), this.service.getIssuer());

		// client configuration
		client.setServicePublicKey(this.service.getServicePublicKey());
		client.setLogging(this.service.logSoapMessages());
		if (null != this.service.getProxyHost()) {
			client.setProxy(this.service.getProxyHost(),
					this.service.getProxyPort());
		} else {
			// disable previously set proxy
			client.setProxy(null, 0);
		}

		// resolve
		return client.resolve(encodedArtifact);
	}

	/**
	 * @return the required {@link ArtifactAuthenticationResponseService}.
	 */
	@Override
	protected AuthenticationResponseService getAuthenticationResponseService() {

		return this.service;
	}
}

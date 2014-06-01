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

package be.fedict.eid.idp.webapp;

import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Remove;
import javax.ejb.Stateful;

import org.jboss.ejb3.annotation.LocalBinding;
import org.jboss.seam.annotations.Destroy;
import org.jboss.seam.annotations.Factory;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.datamodel.DataModel;
import org.jboss.seam.log.Log;

import be.fedict.eid.idp.model.Constants;
import be.fedict.eid.idp.model.IdentityService;
import be.fedict.eid.idp.model.ProtocolServiceManager;
import be.fedict.eid.idp.spi.IdentityProviderProtocolService;
import be.fedict.eid.idp.spi.protocol.EndpointType;
import be.fedict.eid.idp.spi.protocol.IdentityProviderProtocolType;

@Stateful
@Name("idpProtocolService")
@LocalBinding(jndiBinding = Constants.IDP_JNDI_CONTEXT
		+ "webapp/ProtocolServiceBean")
public class ProtocolServiceBean implements ProtocolService {

	@Logger
	private Log log;

	@DataModel
	private List<ServiceEndpoint> idpProtocolServices;

	@DataModel
	private List<ServiceEndpoint> idpServiceEndpoints;

	@EJB
	private ProtocolServiceManager protocolServiceManager;

	@EJB
	private IdentityService identityService;

	@Override
	@Factory("idpProtocolServices")
	public void initProtocolServices() {
		this.log.debug("init idpProtocolServices");
		this.idpProtocolServices = new LinkedList<ServiceEndpoint>();

		for (IdentityProviderProtocolType protocolService : this.protocolServiceManager
				.getProtocolServices()) {
			this.idpProtocolServices.add(new ServiceEndpoint(protocolService
					.getName(), "/eid-idp"
					+ IdentityProviderProtocolService.PROTOCOL_ENDPOINT_PATH
					+ protocolService.getContextPath()));
		}
	}

	@Factory("idpServiceEndpoints")
	public void initServiceEndpoints() {
		this.log.debug("init idpServiceEndpoints");
		this.idpServiceEndpoints = new LinkedList<ServiceEndpoint>();

		for (IdentityProviderProtocolType protocolService : this.protocolServiceManager
				.getProtocolServices()) {

			for (EndpointType endpoint : protocolService.getEndpoints()
					.getEndpoint()) {
				this.idpServiceEndpoints.add(new ServiceEndpoint(endpoint
						.getName(), "/eid-idp"
						+ IdentityProviderProtocolService.ENDPOINT_CONTEXT_PATH
						+ endpoint.getContextPath()));
			}
		}
	}

	@Remove
	@Destroy
	public void destroy() {
		this.log.debug("destroy");
	}

	@Override
	public String getThumbprint() {

		String thumbprint = this.identityService.getIdentityFingerprint();
		if (null == thumbprint) {
			return "<No identity configured>";
		}
		return thumbprint;
	}

	@Override
	public String getIdentityCertificateChain() {
		List<X509Certificate> certChain = this.identityService
				.getIdentityCertificateChain();
		StringBuffer stringBuffer = new StringBuffer();
		for (X509Certificate cert : certChain) {
			stringBuffer.append(cert.toString());
		}
		return stringBuffer.toString();
	}
}

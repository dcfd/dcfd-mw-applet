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

package be.fedict.eid.idp.sp.openid;

import java.io.Serializable;
import java.security.cert.X509Certificate;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.idp.sp.protocol.openid.spi.AuthenticationRequestService;

public class OpenIDAuthenticationRequestServiceBean implements
		AuthenticationRequestService, Serializable {

	private static final Log LOG = LogFactory
			.getLog(OpenIDAuthenticationRequestServiceBean.class);
	private static final long serialVersionUID = 1185931387819658055L;

	private String idPEntryPoint;
	private String spResponseEndpoint;
	private String preferredLanguages;

	@Override
	public String getSPDestination() {

		LOG.debug("get SP destination: " + this.spResponseEndpoint);
		return this.spResponseEndpoint;
	}

	@Override
	public String getUserIdentifier() {

		LOG.debug("get User Identifier: " + this.idPEntryPoint);
		return this.idPEntryPoint;
	}

	@Override
	public X509Certificate getServerCertificate() {
		return null;
	}

	@Override
	public String getPreferredLanguages() {
		return this.preferredLanguages;
	}

	public String getIdPEntryPoint() {
		return idPEntryPoint;
	}

	public void setIdPEntryPoint(String idPEntryPoint) {
		this.idPEntryPoint = idPEntryPoint;
	}

	public String getSpResponseEndpoint() {
		return spResponseEndpoint;
	}

	public void setSpResponseEndpoint(String spResponseEndpoint) {
		this.spResponseEndpoint = spResponseEndpoint;
	}

	public void setPreferredLanguages(String preferredLanguages) {
		this.preferredLanguages = preferredLanguages;
	}
}

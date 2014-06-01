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

package be.fedict.eid.idp.sp.wsfed;

import java.io.Serializable;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.idp.sp.protocol.ws_federation.spi.AuthenticationRequestService;

public class WSFedAuthenticationRequestServiceBean implements
		AuthenticationRequestService, Serializable {

	private static final Log LOG = LogFactory
			.getLog(WSFedAuthenticationRequestServiceBean.class);
	private static final long serialVersionUID = 1185931387819658055L;

	private String idPEntryPoint;
	private String spResponseEndpoint;
	private String spRealm;

	@Override
	public String getSPDestination() {

		LOG.debug("get SP destination: " + this.spResponseEndpoint);
		return this.spResponseEndpoint;
	}

	@Override
	public String getIdPDestination() {

		LOG.debug("get IdP destionation: " + this.idPEntryPoint);
		return this.idPEntryPoint;
	}

	@Override
	public String getContext(Map<String, String[]> parameterMap) {
		return "some-context";
	}

	@Override
	public String getLanguage() {
		return "fr";
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

	@Override
	public String getSPRealm() {
		LOG.debug("get SP realm: " + this.spRealm);
		return this.spRealm;
	}

	public void setSPRealm(String spRealm) {
		LOG.debug("set SP realm: " + spRealm);
		this.spRealm = spRealm;
	}
}

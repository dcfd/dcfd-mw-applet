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

package be.fedict.eid.idp.sp.saml2;

import java.io.Serializable;
import java.security.KeyStore;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.idp.sp.PkiServlet;
import be.fedict.eid.idp.sp.protocol.saml2.spi.AuthenticationRequestService;

public class AuthenticationRequestServiceBean implements
		AuthenticationRequestService, Serializable {

	private static final Log LOG = LogFactory
			.getLog(AuthenticationRequestServiceBean.class);
	private static final long serialVersionUID = 1185931387819658055L;

	public static final String ISSUER = "TestSP";

	private String idPEntryPoint;
	private String spResponseEndpoint;

	@Override
	public String getIssuer() {

		LOG.debug("get issuer");
		return ISSUER;
	}

	@Override
	public String getSPDestination() {

		LOG.debug("get SP destination: " + this.spResponseEndpoint);
		return this.spResponseEndpoint;
	}

	@Override
	public String getIdPDestination() {

		LOG.debug("get IdP destination: " + this.idPEntryPoint);
		return this.idPEntryPoint;
	}

	@Override
	public String getRelayState(Map<String, String[]> parameterMap) {
		return null;
	}

	@Override
	public KeyStore.PrivateKeyEntry getSPIdentity() {

		LOG.debug("get SP Identity");
		try {
			KeyStore.PrivateKeyEntry pke = PkiServlet.getPrivateKeyEntry();
			LOG.debug("certificate: " + pke.getCertificate());
			return pke;
		} catch (Exception e) {
			LOG.error(e);
			return null;
		}
	}

	@Override
	public String getLanguage() {
		return "nl";
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
}

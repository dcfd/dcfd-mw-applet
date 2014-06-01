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

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.idp.sp.ConfigServlet;
import be.fedict.eid.idp.sp.StartupServletContextListener;

public class Saml2Bean {

	private static final Log LOG = LogFactory.getLog(Saml2Bean.class);

	private HttpServletRequest request;

	public void setIdPEntryPoint(String idPEntryPoint) {

		LOG.debug("set IdP Entry Point " + idPEntryPoint);

		StartupServletContextListener.getSaml2RequestBean().setIdPEntryPoint(
				ConfigServlet.getIdpBaseLocation(request) + "protocol/"
						+ idPEntryPoint);
	}

	public void setSpResponseEndpoint(String spResponseEndpoint) {

		LOG.debug("set SP Response Endpoint: " + spResponseEndpoint);

		StartupServletContextListener.getSaml2RequestBean()
				.setSpResponseEndpoint(
						this.request.getScheme() + "://"
								+ this.request.getServerName() + ":"
								+ this.request.getServerPort()
								+ this.request.getContextPath() + "/"
								+ spResponseEndpoint);
	}

	public void setArtifactServiceEndpoint(String notUsed) {

		LOG.debug("set SAML2 Artifact Service endpoint");

		StartupServletContextListener.getSaml2ResponseBean()
				.setArtifactServiceLocation(
						"https://" + this.request.getServerName() + ':'
								+ this.request.getServerPort()
								+ "/eid-idp/ws/saml2/artifact");
	}

	public HttpServletRequest getRequest() {
		return request;
	}

	public void setRequest(HttpServletRequest request) {
		this.request = request;
	}
}

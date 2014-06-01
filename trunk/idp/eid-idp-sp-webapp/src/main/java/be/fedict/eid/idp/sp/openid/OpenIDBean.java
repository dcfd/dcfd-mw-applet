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

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.idp.sp.ConfigServlet;
import be.fedict.eid.idp.sp.StartupServletContextListener;

public class OpenIDBean {

	private static final Log LOG = LogFactory.getLog(OpenIDBean.class);

	private HttpServletRequest request;

	public void setIdPEntryPoint(String idPEntryPoint) {

		LOG.debug("set IdP Entry Point " + idPEntryPoint);

		StartupServletContextListener.getOpenIDRequestBean().setIdPEntryPoint(
				ConfigServlet.getIdpBaseLocation(request) + "endpoints/"
						+ idPEntryPoint);

	}

	public void setSpResponseEndpoint(String spResponseEndpoint) {

		LOG.debug("set SP Response Endpoint: " + spResponseEndpoint);

		StartupServletContextListener.getOpenIDRequestBean()
				.setSpResponseEndpoint(
						this.request.getScheme() + "://"
								+ this.request.getServerName() + ":"
								+ this.request.getServerPort()
								+ this.request.getContextPath() + "/"
								+ spResponseEndpoint);
	}

	public void setPreferredLanguages(String preferredLanguages) {
		LOG.debug("set preferred languages: " + preferredLanguages);
		OpenIDAuthenticationRequestServiceBean requestServiceBean = StartupServletContextListener
				.getOpenIDRequestBean();
		if (preferredLanguages.isEmpty()) {
			requestServiceBean.setPreferredLanguages(null);
		} else {
			requestServiceBean.setPreferredLanguages(preferredLanguages);
		}
	}

	public HttpServletRequest getRequest() {
		return request;
	}

	public void setRequest(HttpServletRequest request) {
		this.request = request;
	}
}

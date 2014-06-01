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

package be.fedict.eid.idp.spi;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

public class IdentityProviderConfigurationFactory {

	public static final String IDENTITY_PROVIDER_CONFIGURATION_CONTEXT_ATTRIBUTE = IdentityProviderConfigurationFactory.class
			.getName() + ".IdentityProviderConfiguration";

	private IdentityProviderConfigurationFactory() {
		super();
	}

	public static IdentityProviderConfiguration getInstance(
			HttpServletRequest httpServletRequest) {
		HttpSession httpSession = httpServletRequest.getSession();
		ServletContext servletContext = httpSession.getServletContext();
		IdentityProviderConfiguration identityProviderConfiguration = getInstance(servletContext);
		return identityProviderConfiguration;
	}

	public static IdentityProviderConfiguration getInstance(
			ServletContext servletContext) {
		IdentityProviderConfiguration identityProviderConfiguration = (IdentityProviderConfiguration) servletContext
				.getAttribute(IDENTITY_PROVIDER_CONFIGURATION_CONTEXT_ATTRIBUTE);
		return identityProviderConfiguration;
	}
}

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

package be.fedict.eid.idp.sp.protocol.saml2.post;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;

import be.fedict.eid.idp.common.ServiceLocator;
import be.fedict.eid.idp.sp.protocol.saml2.AbstractAuthenticationResponseProcessor;
import be.fedict.eid.idp.sp.protocol.saml2.AbstractAuthenticationResponseServlet;
import be.fedict.eid.idp.sp.protocol.saml2.spi.AuthenticationResponseService;

/**
 * Processes the response of the SAML v2.0 protocol with HTTP Post binding.
 * <p/>
 * <p>
 * The following init-params are required:
 * </p>
 * <ul>
 * <li><tt>ResponseSessionAttribute</tt>: indicates the session attribute to
 * store the returned
 * {@link be.fedict.eid.idp.common.saml2.AuthenticationResponse} data object..</li>
 * <li><tt>RedirectPage</tt>: indicates the page where to redirect after
 * successfull authentication.</li>
 * </ul>
 * <p/>
 * <p>
 * The following init-params are optional:
 * </p>
 * <ul>
 * <li><tt>AuthenticationResponseService</tt>: indicates the JNDI location of
 * the {@link AuthenticationResponseService} that can be used optionally for
 * e.g. validation of the certificate chain in the response's signature.</li>
 * <li><tt>ErrorPage</tt>: indicates the page to be shown in case of errors.</li>
 * <li><tt>ErrorMessageSessionAttribute</tt>: indicates which session attribute
 * to use for reporting an error. This session attribute can be used on the
 * error page.</li>
 * </ul>
 * 
 * @author Wim Vandenhaute
 */
public class AuthenticationResponseServlet extends
		AbstractAuthenticationResponseServlet {

	private static final long serialVersionUID = 1L;

	private ServiceLocator<AuthenticationResponseService> serviceLocator;

	@Override
	protected void initialize(ServletConfig config) throws ServletException {

		this.serviceLocator = new ServiceLocator<AuthenticationResponseService>(
				"AuthenticationResponseService", config);
	}

	@Override
	protected AbstractAuthenticationResponseProcessor getAuthenticationResponseProcessor()
			throws ServletException {

		return new AuthenticationResponseProcessor(
				this.serviceLocator.locateService());
	}
}

/*
 * eID Identity Provider Project.
 * Copyright (C) 2011 FedICT.
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

package be.fedict.eid.idp.sp.protocol.openid.spi;

import java.security.cert.X509Certificate;

/**
 * OpenID SPI for authentication request services. Using an authentication
 * request service allows for run-time configuration of the OpenID
 * AuthenticationRequestServlet.
 * 
 * @author Wim Vandenhaute.
 */
public interface AuthenticationRequestService {

	/**
	 * Gives back the Service Provider destination endpoint that will handle the
	 * returned OpenID Response.
	 * 
	 * @return SP OpenID response handling location.
	 */
	String getSPDestination();

	/**
	 * Gives back the destination URL of the eID IdP OpenID protocol entry
	 * point.
	 * 
	 * @return eID IdP OpenID entry point
	 */
	String getUserIdentifier();

	/**
	 * Gives back the trusted TLS certifacte of the eID IdP Service.
	 * 
	 * @return the trusted eID IdP TLS certificate
	 */
	X509Certificate getServerCertificate();

	/**
	 * Optional comma-seperated list of preferred languages. Will be
	 * communicated and if available used by the eID IdP pages.
	 * 
	 * @return preferred languages or <code>null</code> if browser locale is ok.
	 */
	String getPreferredLanguages();
}

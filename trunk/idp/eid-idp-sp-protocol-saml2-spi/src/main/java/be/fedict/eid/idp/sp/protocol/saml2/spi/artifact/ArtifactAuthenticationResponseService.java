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

package be.fedict.eid.idp.sp.protocol.saml2.spi.artifact;

import java.security.KeyStore;
import java.security.PublicKey;

import be.fedict.eid.idp.sp.protocol.saml2.spi.AuthenticationResponseService;

/**
 * SPI for authentication response services for SAML v2.0 HTTP Artifact Binding.
 * 
 * @author Wim Vandenhaute.
 */
public interface ArtifactAuthenticationResponseService extends
		AuthenticationResponseService {

	/**
	 * Gives back the Issuer of the constructed SAML v2.0 ArtifactResolve
	 * request.
	 * 
	 * @return the ArtifactResolve request issuer.
	 */
	String getIssuer();

	/**
	 * Gives back the location of the eID IdP SAML v2.0 Artifact service.
	 * 
	 * @return eID IdP SAML v2.0 Artifact Service Location.
	 */
	String getArtifactServiceLocation();

	/**
	 * Whether or not SOAP messages should be logged.
	 * 
	 * @return log SOAP messages or not.
	 */
	boolean logSoapMessages();

	/**
	 * If set, unilateral TLS authentication will occur, verifying the server
	 * {@link java.security.cert.X509Certificate} against the specified
	 * {@link PublicKey}.
	 * <p/>
	 * Returning <code>null</code> will trust all.
	 * 
	 * @return the SSL {@link PublicKey}.
	 */
	PublicKey getServicePublicKey();

	/**
	 * If set, SSL hostname verification will be done against specified hostname
	 * for the WS call to the eID IdP Artifact Resolution Service. By default
	 * JAX-WS will validate the hostname against the SSL certificate's CN.
	 * Returning null will turn of this validation.
	 * 
	 * @return the SSL hostname or <code>null</code> if SSL hostname
	 *         verification needs to be switched off.
	 */
	String getServiceHostname();

	/**
	 * Optional Proxy Hostname. <code>null</code> if not needed.
	 * 
	 * @return the proxy hostname.
	 */
	String getProxyHost();

	/**
	 * Optional Proxy Port. <code>null</code> if not needed.
	 * 
	 * @return the proxy port.
	 */
	int getProxyPort();

	/**
	 * Gives back the optional Service Provider's identity to be used to sign
	 * outgoing SAML2 Artifact Resolve requests.
	 * 
	 * @return private key entry of the SP or <code>null</code> if no signing is
	 *         needed.
	 */
	KeyStore.PrivateKeyEntry getSPIdentity();
}

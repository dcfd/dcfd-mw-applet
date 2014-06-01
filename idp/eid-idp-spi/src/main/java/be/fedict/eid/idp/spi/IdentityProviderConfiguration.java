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

import java.security.cert.X509Certificate;
import java.util.List;

/**
 * Interface towards the configuration of the eID IdP.
 * 
 * @author Frank Cornelis
 */
public interface IdentityProviderConfiguration {

	/**
	 * Gives back the secret used to HMAC the user identifiers.
	 * 
	 * @return secret, or <code>null</code> if not set.
	 */
	byte[] getHmacSecret();

	/**
	 * @return the identity of this eID IdP system.
	 */
	IdPIdentity findIdentity();

	/**
	 * @return certificate chain of the eID IdP identity.
	 */
	List<X509Certificate> getIdentityCertificateChain();

	/**
	 * @return default issuer name of the eID IdP system, or <code>null</code>
	 *         if not set.
	 */
	String getDefaultIssuer();

	/**
	 * @param protocolId
	 *            protocol ID
	 * @return list of all configured eID IdP Attributes.
	 */
	List<AttributeConfig> getAttributes(String protocolId);

	/**
	 * @return validity time in minutes of the returned authentication response
	 *         token.
	 */
	Integer getResponseTokenValidity();
}

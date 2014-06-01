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

package be.fedict.eid.idp.model;

import java.util.List;

import javax.ejb.Local;

import be.fedict.eid.idp.model.exception.KeyStoreLoadException;
import be.fedict.eid.idp.spi.IdPIdentity;
import be.fedict.eid.idp.spi.IdentityProviderConfiguration;

@Local
public interface IdentityService extends IdentityProviderConfiguration {

	/**
	 * Reload the currently configured identity
	 * 
	 * @throws KeyStoreLoadException
	 *             failed to load keystore
	 */
	void reloadIdentity() throws KeyStoreLoadException;

	/**
	 * Sets specified identity as the active eID IdP Identity
	 * 
	 * @param name
	 *            name of the identity to become active
	 * @throws KeyStoreLoadException
	 *             failed to load the identity.
	 */
	void setActiveIdentity(String name) throws KeyStoreLoadException;

	/**
	 * Update/add an eID IdP Identity
	 * 
	 * @param idPIdentityConfig
	 *            the identity configuration
	 * @return the identity
	 * @throws KeyStoreLoadException
	 *             failed to load the identity.
	 */
	IdPIdentity setIdentity(IdPIdentityConfig idPIdentityConfig)
			throws KeyStoreLoadException;

	/**
	 * Test if specified IdP Identity configuration is valid.
	 * 
	 * @param idPIdentityConfig
	 *            the identity configuration
	 * @return the identity
	 * @throws KeyStoreLoadException
	 *             failed to load the identity.
	 */
	IdPIdentity loadIdentity(IdPIdentityConfig idPIdentityConfig)
			throws KeyStoreLoadException;

	/**
	 * @return the currently active eID IdP Identity config or <code>null</code>
	 *         if none is active
	 */
	IdPIdentityConfig findIdentityConfig();

	/**
	 * @param name
	 *            identity's name
	 * @return the identity config or <code>null</code> if not found.
	 */
	IdPIdentityConfig findIdentityConfig(String name);

	/**
	 * Remove specified identity configuration
	 * 
	 * @param name
	 *            name of the identity config to be removed
	 */
	void removeIdentityConfig(String name);

	/**
	 * @return all configured identity names
	 */
	List<String> getIdentities();

	/**
	 * @return if the IdP's identity is configured or not.
	 */
	boolean isIdentityConfigured();

	/**
	 * @return digest of the active identity's certificate.
	 */
	String getIdentityFingerprint();

}

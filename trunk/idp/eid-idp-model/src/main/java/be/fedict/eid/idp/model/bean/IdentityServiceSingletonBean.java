/*
 * eID Identity Provider Project.
 * Copyright (C) 2010-2012 FedICT.
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

package be.fedict.eid.idp.model.bean;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.List;

import javax.ejb.EJB;
import javax.ejb.EJBException;
import javax.ejb.Singleton;
import javax.ejb.Startup;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import sun.security.pkcs11.SunPKCS11;
import be.fedict.eid.idp.model.ConfigProperty;
import be.fedict.eid.idp.model.Configuration;
import be.fedict.eid.idp.model.IdPIdentityConfig;
import be.fedict.eid.idp.model.KeyStoreType;
import be.fedict.eid.idp.model.exception.KeyStoreLoadException;
import be.fedict.eid.idp.spi.IdPIdentity;

@Singleton
@Startup
public class IdentityServiceSingletonBean {

	private static final Log LOG = LogFactory
			.getLog(IdentityServiceSingletonBean.class);

	private IdPIdentity identity;
	private IdPIdentityConfig identityConfig;

	@EJB
	private Configuration configuration;

	/**
	 * @return if an active identity is configured
	 */
	public boolean isIdentityConfigured() {
		return null != this.configuration.getValue(
				ConfigProperty.ACTIVE_IDENTITY, String.class);
	}

	/**
	 * @return list of all identity configurations's names
	 */
	public List<String> getIdentities() {

		return this.configuration.getIndexes(ConfigProperty.KEY_STORE_TYPE);
	}

	/**
	 * Set new active identity
	 * 
	 * @param name
	 *            new active identity's name
	 * @throws KeyStoreLoadException
	 *             failed to load keystore
	 */
	public void setActiveIdentity(String name) throws KeyStoreLoadException {

		LOG.debug("set active identity: " + name);
		IdPIdentityConfig idPIdentityConfig = findIdentityConfig(name);

		if (null == idPIdentityConfig) {
			throw new KeyStoreLoadException("Identity config \"" + name
					+ "\" not found!");
		}

		this.configuration.setValue(ConfigProperty.ACTIVE_IDENTITY, name);

		this.identity = loadIdentity(idPIdentityConfig);
		this.identityConfig = idPIdentityConfig;
		LOG.debug("private key entry reloaded");
	}

	/**
	 * Reload current active identity
	 * 
	 * @throws KeyStoreLoadException
	 *             failed to load keystore
	 */
	public void reloadIdentity() throws KeyStoreLoadException {

		IdPIdentityConfig idPIdentityConfig = findIdentityConfig(findActiveIdentityName());

		this.identity = loadIdentity(idPIdentityConfig);
		this.identityConfig = idPIdentityConfig;
		LOG.debug("private key entry reloaded");
	}

	/**
	 * Load identity keystore with specified name
	 * 
	 * @param name
	 *            identity name
	 * @return IdP identity
	 * @throws KeyStoreLoadException
	 *             failed to load keystore
	 */
	public IdPIdentity loadIdentity(String name) throws KeyStoreLoadException {

		IdPIdentityConfig idPIdentityConfig = findIdentityConfig(name);
		return loadIdentity(idPIdentityConfig);
	}

	/**
	 * Load identity keystore
	 * 
	 * @param idPIdentityConfig
	 *            identity configuration
	 * @return private key entry of identity
	 * @throws KeyStoreLoadException
	 *             failed to load keystore
	 */
	public IdPIdentity loadIdentity(IdPIdentityConfig idPIdentityConfig)
			throws KeyStoreLoadException {

		try {

			if (null == idPIdentityConfig) {
				throw new KeyStoreLoadException("Identity config is empty!");
			}

			FileInputStream keyStoreInputStream = null;
			if (idPIdentityConfig.getKeyStoreType().equals(KeyStoreType.PKCS11)) {
				Security.addProvider(new SunPKCS11(idPIdentityConfig
						.getKeyStorePath()));
			} else {
				try {
					keyStoreInputStream = new FileInputStream(
							idPIdentityConfig.getKeyStorePath());
				} catch (FileNotFoundException e) {
					throw new KeyStoreLoadException(
							"Can't load keystore from config-specified location: "
									+ idPIdentityConfig.getKeyStorePath(), e);
				}
			}

			// load keystore
			KeyStore keyStore = KeyStore.getInstance(idPIdentityConfig
					.getKeyStoreType().getJavaKeyStoreType());
			char[] password;
			if (null != idPIdentityConfig.getKeyStorePassword()
					&& !idPIdentityConfig.getKeyStorePassword().isEmpty()) {
				password = idPIdentityConfig.getKeyStorePassword()
						.toCharArray();
			} else {
				password = null;
			}
			keyStore.load(keyStoreInputStream, password);

			// find entry alias
			Enumeration<String> aliases = keyStore.aliases();
			if (!aliases.hasMoreElements()) {
				throw new KeyStoreLoadException("no keystore aliases present");
			}

			String alias;
			if (null != idPIdentityConfig.getKeyEntryAlias()
					&& !idPIdentityConfig.getKeyEntryAlias().trim().isEmpty()) {
				boolean found = false;
				while (aliases.hasMoreElements()) {
					if (aliases.nextElement().equals(
							idPIdentityConfig.getKeyEntryAlias())) {
						found = true;
						break;
					}
				}
				if (!found) {
					throw new KeyStoreLoadException(
							"no keystore entry with alias \""
									+ idPIdentityConfig.getKeyEntryAlias()
									+ "\"");
				}
				alias = idPIdentityConfig.getKeyEntryAlias();
			} else {
				alias = aliases.nextElement();
			}
			LOG.debug("keystore alias: " + alias);

			// get keystore entry
			char[] entryPassword;
			if (null != idPIdentityConfig.getKeyEntryPassword()
					&& !idPIdentityConfig.getKeyEntryPassword().isEmpty()) {
				entryPassword = idPIdentityConfig.getKeyEntryPassword()
						.toCharArray();
			} else {
				entryPassword = null;
			}

			KeyStore.Entry entry = keyStore.getEntry(alias,
					new KeyStore.PasswordProtection(entryPassword));
			if (!(entry instanceof PrivateKeyEntry)) {
				throw new KeyStoreLoadException("private key entry expected");
			}
			return new IdPIdentity(idPIdentityConfig.getName(),
					(PrivateKeyEntry) entry);
		} catch (KeyStoreException e) {
			throw new KeyStoreLoadException(e);
		} catch (CertificateException e) {
			throw new KeyStoreLoadException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new KeyStoreLoadException(e);
		} catch (UnrecoverableEntryException e) {
			throw new KeyStoreLoadException(e);
		} catch (IOException e) {
			throw new KeyStoreLoadException(e);
		}
	}

	/**
	 * @return current IdP Identity or <code>null</code> if none.
	 */
	public IdPIdentity findIdentity() {

		IdPIdentityConfig databaseIdentityConfig = findIdentityConfig();

		if (null != databaseIdentityConfig) {
			if (!databaseIdentityConfig.equals(this.identityConfig)) {
				try {
					this.identity = loadIdentity(databaseIdentityConfig);
				} catch (KeyStoreLoadException e) {
					throw new RuntimeException(e);
				}
				this.identityConfig = databaseIdentityConfig;
			}
		}
		return this.identity;
	}

	/**
	 * @return current identity's configuration or <codE>null</code> if none.
	 */
	public IdPIdentityConfig findIdentityConfig() {

		String activeIdentity = findActiveIdentityName();
		if (null == activeIdentity) {
			return null;
		}
		IdPIdentityConfig idPIdentityConfig = findIdentityConfig(activeIdentity);
		if (null == idPIdentityConfig) {
			throw new EJBException("Identity config " + activeIdentity
					+ " not found!");
		}
		return idPIdentityConfig;
	}

	/**
	 * @param name
	 *            identity name
	 * @return identity config or <code>null</code> if not found.
	 */
	public IdPIdentityConfig findIdentityConfig(String name) {

		KeyStoreType keyStoreType = this.configuration.getValue(
				ConfigProperty.KEY_STORE_TYPE, name, KeyStoreType.class);
		if (null == keyStoreType) {
			return null;
		}
		String keyStorePath = this.configuration.getValue(
				ConfigProperty.KEY_STORE_PATH, name, String.class);
		String keyStoreSecret = this.configuration.getValue(
				ConfigProperty.KEY_STORE_SECRET, name, String.class);
		String keyEntrySecret = this.configuration.getValue(
				ConfigProperty.KEY_ENTRY_SECRET, name, String.class);
		String keyEntryAlias = this.configuration.getValue(
				ConfigProperty.KEY_ENTRY_ALIAS, name, String.class);

		IdPIdentityConfig idPIdentityConfig = new IdPIdentityConfig(name,
				keyStoreType, keyStorePath, keyStoreSecret, keyEntrySecret,
				keyEntryAlias);

		String activeIdentity = findActiveIdentityName();
		if (null != activeIdentity) {
			idPIdentityConfig.setActive(idPIdentityConfig.getName().equals(
					activeIdentity));
		}

		return idPIdentityConfig;
	}

	private String findActiveIdentityName() {

		return this.configuration.getValue(ConfigProperty.ACTIVE_IDENTITY,
				String.class);
	}

	/**
	 * Add/update identity from specified configuration
	 * 
	 * @param idPIdentityConfig
	 *            identity configuration
	 * @return IdP Identity
	 * @throws KeyStoreLoadException
	 *             failed to load keystore
	 */
	public IdPIdentity setIdentity(IdPIdentityConfig idPIdentityConfig)
			throws KeyStoreLoadException {

		LOG.debug("set identity: " + idPIdentityConfig.getName());

		this.configuration.setValue(ConfigProperty.KEY_STORE_TYPE,
				idPIdentityConfig.getName(),
				idPIdentityConfig.getKeyStoreType());
		this.configuration.setValue(ConfigProperty.KEY_STORE_PATH,
				idPIdentityConfig.getName(),
				idPIdentityConfig.getKeyStorePath());
		this.configuration.setValue(ConfigProperty.KEY_STORE_SECRET,
				idPIdentityConfig.getName(),
				idPIdentityConfig.getKeyStorePassword());
		this.configuration.setValue(ConfigProperty.KEY_ENTRY_SECRET,
				idPIdentityConfig.getName(),
				idPIdentityConfig.getKeyEntryPassword());
		if (null != idPIdentityConfig.getKeyEntryAlias()) {
			this.configuration.setValue(ConfigProperty.KEY_ENTRY_ALIAS,
					idPIdentityConfig.getName(),
					idPIdentityConfig.getKeyEntryAlias());
		}

		return loadIdentity(idPIdentityConfig.getName());
	}

	/**
	 * Remove identity configuration
	 * 
	 * @param name
	 *            name of identity config to remove
	 */
	public void removeIdentityConfig(String name) {

		LOG.debug("remove identity: " + name);

		String activeIdentity = findActiveIdentityName();
		if (null != activeIdentity && activeIdentity.equals(name)) {
			this.configuration.removeValue(ConfigProperty.ACTIVE_IDENTITY);
			this.identity = null;
		}

		this.configuration.removeValue(ConfigProperty.KEY_STORE_TYPE, name);
		this.configuration.removeValue(ConfigProperty.KEY_STORE_PATH, name);
		this.configuration.removeValue(ConfigProperty.KEY_STORE_SECRET, name);
		this.configuration.removeValue(ConfigProperty.KEY_ENTRY_SECRET, name);
		this.configuration.removeValue(ConfigProperty.KEY_ENTRY_ALIAS, name);
	}
}

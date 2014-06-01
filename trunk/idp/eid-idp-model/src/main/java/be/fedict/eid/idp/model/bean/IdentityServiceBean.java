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

package be.fedict.eid.idp.model.bean;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Stateless;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.codec.digest.DigestUtils;

import be.fedict.eid.idp.entity.AttributeEntity;
import be.fedict.eid.idp.model.AttributeService;
import be.fedict.eid.idp.model.ConfigProperty;
import be.fedict.eid.idp.model.Configuration;
import be.fedict.eid.idp.model.IdPIdentityConfig;
import be.fedict.eid.idp.model.IdentityService;
import be.fedict.eid.idp.model.exception.KeyStoreLoadException;
import be.fedict.eid.idp.spi.AttributeConfig;
import be.fedict.eid.idp.spi.IdPIdentity;

@Stateless
public class IdentityServiceBean implements IdentityService {

	@EJB
	private IdentityServiceSingletonBean identityServiceSingletonBean;

	@EJB
	private Configuration configuration;

	@EJB
	private AttributeService attributeService;

	/**
	 * {@inheritDoc}
	 */
	public byte[] getHmacSecret() {

		String secretValue = this.configuration.getValue(
				ConfigProperty.HMAC_SECRET, String.class);
		if (null == secretValue || secretValue.trim().isEmpty()) {
			return null;
		}
		try {
			return Hex.decodeHex(secretValue.toCharArray());
		} catch (DecoderException e) {
			throw new RuntimeException("HEX decoder error: " + e.getMessage(),
					e);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public void reloadIdentity() throws KeyStoreLoadException {

		this.identityServiceSingletonBean.reloadIdentity();
	}

	/**
	 * {@inheritDoc}
	 */
	public void setActiveIdentity(String name) throws KeyStoreLoadException {

		this.identityServiceSingletonBean.setActiveIdentity(name);
	}

	/**
	 * {@inheritDoc}
	 */
	public boolean isIdentityConfigured() {

		return this.identityServiceSingletonBean.isIdentityConfigured();
	}

	/**
	 * {@inheritDoc}
	 */
	public List<String> getIdentities() {

		return this.identityServiceSingletonBean.getIdentities();
	}

	/**
	 * {@inheritDoc}
	 */
	public IdPIdentity findIdentity() {
		return this.identityServiceSingletonBean.findIdentity();
	}

	/**
	 * {@inheritDoc}
	 */
	public IdPIdentity setIdentity(IdPIdentityConfig idPIdentityConfig)
			throws KeyStoreLoadException {

		return this.identityServiceSingletonBean.setIdentity(idPIdentityConfig);
	}

	@Override
	public IdPIdentity loadIdentity(IdPIdentityConfig idPIdentityConfig)
			throws KeyStoreLoadException {

		return this.identityServiceSingletonBean
				.loadIdentity(idPIdentityConfig);
	}

	/**
	 * {@inheritDoc}
	 */
	public IdPIdentityConfig findIdentityConfig() {

		return this.identityServiceSingletonBean.findIdentityConfig();
	}

	/**
	 * {@inheritDoc}
	 */
	public IdPIdentityConfig findIdentityConfig(String name) {

		return this.identityServiceSingletonBean.findIdentityConfig(name);
	}

	/**
	 * {@inheritDoc}
	 */
	public void removeIdentityConfig(String name) {

		this.identityServiceSingletonBean.removeIdentityConfig(name);
	}

	/**
	 * {@inheritDoc}
	 */
	public List<X509Certificate> getIdentityCertificateChain() {

		IdPIdentity identity = findIdentity();
		List<X509Certificate> identityCertificateChain = new LinkedList<X509Certificate>();
		if (null == identity) {
			return identityCertificateChain;
		}
		Certificate[] certificateChain = identity.getPrivateKeyEntry()
				.getCertificateChain();
		if (null == certificateChain) {
			return identityCertificateChain;
		}
		for (Certificate certificate : certificateChain) {
			identityCertificateChain.add((X509Certificate) certificate);
		}
		return identityCertificateChain;
	}

	@Override
	public String getDefaultIssuer() {
		String issuerName = this.configuration.getValue(ConfigProperty.ISSUER,
				String.class);
		if (null == issuerName || issuerName.trim().isEmpty()) {
			issuerName = "Default";
		}
		return issuerName;
	}

	@Override
	public List<AttributeConfig> getAttributes(String protocolId) {

		List<AttributeConfig> attributes = new LinkedList<AttributeConfig>();
		for (AttributeEntity attribute : this.attributeService.listAttributes()) {

			attributes.add(new AttributeConfig(attribute.getName(), attribute
					.getDescription(), this.attributeService.getUri(protocolId,
					attribute.getUri())));
		}
		return attributes;
	}

	@Override
	public Integer getResponseTokenValidity() {

		return this.configuration.getValue(ConfigProperty.TOKEN_VALIDITY,
				Integer.class);
	}

	/**
	 * {@inheritDoc}
	 */
	public String getIdentityFingerprint() {
		IdPIdentity identity = findIdentity();
		if (null == identity) {
			return null;
		}
		X509Certificate certificate = (X509Certificate) identity
				.getPrivateKeyEntry().getCertificate();
		if (null == certificate) {
			return null;
		}
		String fingerprint;
		try {
			fingerprint = DigestUtils.shaHex(certificate.getEncoded());
		} catch (CertificateEncodingException e) {
			return null;
		}
		return fingerprint;
	}

}

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

import java.io.Serializable;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.crypto.SecretKey;
import javax.ejb.EJBException;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.idp.common.SamlAuthenticationPolicy;
import be.fedict.eid.idp.sp.ConfigServlet;
import be.fedict.eid.idp.sp.PkiServlet;
import be.fedict.eid.idp.sp.SPBean;
import be.fedict.eid.idp.sp.protocol.saml2.spi.artifact.ArtifactAuthenticationResponseService;

public class AuthenticationResponseServiceBean implements
		ArtifactAuthenticationResponseService, Serializable {

	private static final Log LOG = LogFactory
			.getLog(AuthenticationResponseServiceBean.class);
	private static final long serialVersionUID = 8779248652700835953L;

	private String artifactServiceLocation;

	@Override
	public boolean requiresResponseSignature() {
		return null != ConfigServlet.getIdpIdentity()
				&& !ConfigServlet.getIdpIdentity().trim().isEmpty();
	}

	@Override
	public void validateServiceCertificate(
			SamlAuthenticationPolicy authenticationPolicy,
			List<X509Certificate> certificateChain) throws SecurityException {

		LOG.debug("validate saml response policy="
				+ authenticationPolicy.getUri() + " cert.chain.size="
				+ certificateChain.size());

		String idpIdentity = ConfigServlet.getIdpIdentity();

		if (null != idpIdentity && !idpIdentity.trim().isEmpty()) {
			LOG.debug("validate IdP Identity with " + idpIdentity);

			String fingerprint;
			try {
				fingerprint = DigestUtils.shaHex(certificateChain.get(0)
						.getEncoded());
			} catch (CertificateEncodingException e) {
				throw new SecurityException(e);
			}

			if (!fingerprint.equals(idpIdentity)) {
				throw new EJBException("IdP Identity "
						+ "thumbprint mismatch: got: " + fingerprint
						+ " expected: " + idpIdentity);
			}
		}
	}

	@Override
	public int getMaximumTimeOffset() {
		return 5;
	}

	@Override
	public SecretKey getAttributeSecretKey() {

		if (ConfigServlet.isEncrypt()) {
			return SPBean.aes128SecretKey;
		} else {
			return null;
		}
	}

	@Override
	public PrivateKey getAttributePrivateKey() {

		if (ConfigServlet.isUseKeK()) {
			try {
				return PkiServlet.getPrivateKeyEntry().getPrivateKey();
			} catch (Exception e) {
				throw new RuntimeException(e);
			}
		} else {
			return null;
		}

	}

	@Override
	public String getIssuer() {
		return AuthenticationRequestServiceBean.ISSUER;
	}

	@Override
	public String getArtifactServiceLocation() {

		return this.artifactServiceLocation;
	}

	@Override
	public boolean logSoapMessages() {
		return true;
	}

	@Override
	public PublicKey getServicePublicKey() {
		return null;
	}

	@Override
	public String getServiceHostname() {
		return null;
	}

	@Override
	public String getProxyHost() {
		return null;
	}

	@Override
	public int getProxyPort() {
		return 0;
	}

	@Override
	public KeyStore.PrivateKeyEntry getSPIdentity() {

		try {
			return PkiServlet.getPrivateKeyEntry();
		} catch (Exception e) {
			LOG.error(e);
			return null;
		}
	}

	public void setArtifactServiceLocation(String artifactServiceLocation) {

		this.artifactServiceLocation = artifactServiceLocation;
	}
}

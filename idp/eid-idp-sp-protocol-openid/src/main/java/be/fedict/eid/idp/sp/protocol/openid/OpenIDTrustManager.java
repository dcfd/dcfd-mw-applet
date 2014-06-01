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

package be.fedict.eid.idp.sp.protocol.openid;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * OpenID Trust Manager to install to override the default set of trusted SSL
 * certificates. Used by {@link OpenIDSSLSocketFactory}.
 * 
 * @author Frank Cornelis
 */
public class OpenIDTrustManager implements X509TrustManager {

	private static final Log LOG = LogFactory.getLog(OpenIDTrustManager.class);

	private final X509Certificate serverCertificate;

	private X509TrustManager defaultTrustManager;

	/**
	 * Allows all server certificates.
	 */
	public OpenIDTrustManager() {
		this.serverCertificate = null;
		this.defaultTrustManager = null;
	}

	/**
	 * Trust only the given server certificate, and the default trusted server
	 * certificates.
	 * 
	 * @param serverCertificate
	 *            SSL certificate to trust
	 * @throws NoSuchAlgorithmException
	 *             could not get an SSLContext instance
	 * @throws KeyStoreException
	 *             failed to intialize the {@link OpenIDTrustManager}
	 */
	public OpenIDTrustManager(X509Certificate serverCertificate)
			throws NoSuchAlgorithmException, KeyStoreException {
		this.serverCertificate = serverCertificate;
		String algorithm = TrustManagerFactory.getDefaultAlgorithm();
		TrustManagerFactory trustManagerFactory = TrustManagerFactory
				.getInstance(algorithm);
		trustManagerFactory.init((KeyStore) null);
		TrustManager[] trustManagers = trustManagerFactory.getTrustManagers();
		for (TrustManager trustManager : trustManagers) {
			if (trustManager instanceof X509TrustManager) {
				this.defaultTrustManager = (X509TrustManager) trustManager;
				break;
			}
		}
		if (null == this.defaultTrustManager) {
			throw new IllegalStateException(
					"no default X509 trust manager found");
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public void checkClientTrusted(X509Certificate[] chain, String authType)
			throws CertificateException {
		LOG.error("checkClientTrusted");
		if (null != this.defaultTrustManager) {
			this.defaultTrustManager.checkClientTrusted(chain, authType);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public void checkServerTrusted(X509Certificate[] chain, String authType)
			throws CertificateException {
		LOG.debug("check server trusted");
		LOG.debug("auth type: " + authType);
		if (null == this.serverCertificate) {
			LOG.debug("trusting all server certificates");
			return;
		}
		if (!this.serverCertificate.equals(chain[0])) {
			throw new CertificateException("untrusted server certificate");
		}
	}

	/**
	 * {@inheritDoc}
	 */
	public X509Certificate[] getAcceptedIssuers() {
		LOG.error("getAcceptedIssuers");
		if (null == this.defaultTrustManager) {
			return null;
		}
		return this.defaultTrustManager.getAcceptedIssuers();
	}
}

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

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * OpenID SSL Socket Factory for installing a specified SSL TrustManager.
 * 
 * @author Frank Cornelis
 */
public class OpenIDSSLSocketFactory extends SSLSocketFactory {

	private static final Log LOG = LogFactory
			.getLog(OpenIDSSLSocketFactory.class);

	private final SSLContext sslContext;

	/**
	 * Trusts all server certificates.
	 * 
	 * @throws NoSuchAlgorithmException
	 *             could not get an SSLContext instance
	 * @throws KeyManagementException
	 *             failed to initialize the SSLContext
	 */
	public OpenIDSSLSocketFactory() throws NoSuchAlgorithmException,
			KeyManagementException {
		this.sslContext = SSLContext.getInstance("SSL");
		TrustManager trustManager = new OpenIDTrustManager();
		TrustManager[] trustManagers = { trustManager };
		this.sslContext.init(null, trustManagers, null);
	}

	/**
	 * Trust only the given server certificate, and the default trusted server
	 * certificates.
	 * 
	 * @param serverCertificate
	 *            SSL certificate to trust
	 * @throws NoSuchAlgorithmException
	 *             could not get an SSLContext instance
	 * @throws KeyManagementException
	 *             failed to initialize the SSLContext
	 * @throws KeyStoreException
	 *             failed to intialize the {@link OpenIDTrustManager}
	 */
	public OpenIDSSLSocketFactory(X509Certificate serverCertificate)
			throws NoSuchAlgorithmException, KeyManagementException,
			KeyStoreException {
		this.sslContext = SSLContext.getInstance("SSL");
		TrustManager trustManager = new OpenIDTrustManager(serverCertificate);
		TrustManager[] trustManagers = { trustManager };
		this.sslContext.init(null, trustManagers, null);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Socket createSocket() throws IOException {
		return this.sslContext.getSocketFactory().createSocket();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Socket createSocket(String host, int port, InetAddress clientHost,
			int clientPort) throws IOException {
		return this.sslContext.getSocketFactory().createSocket(host, port,
				clientHost, clientPort);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Socket createSocket(String host, int port) throws IOException {
		return this.sslContext.getSocketFactory().createSocket(host, port);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Socket createSocket(Socket socket, String host, int port,
			boolean autoClose) throws IOException {
		return this.sslContext.getSocketFactory().createSocket(socket, host,
				port, autoClose);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String[] getDefaultCipherSuites() {
		return this.sslContext.getSocketFactory().getDefaultCipherSuites();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public String[] getSupportedCipherSuites() {
		return this.sslContext.getSocketFactory().getSupportedCipherSuites();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Socket createSocket(InetAddress host, int port) throws IOException {
		return this.sslContext.getSocketFactory().createSocket(host, port);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Socket createSocket(InetAddress address, int port,
			InetAddress localAddress, int localPort) throws IOException {
		return this.sslContext.getSocketFactory().createSocket(address, port,
				localAddress, localPort);
	}

	/**
	 * Install the OpenID SSL Socket Factory. Trusts the given server
	 * certificate and all default trusted server certificates.
	 * 
	 * @param serverCertificate
	 *            SSL Certificate to trust
	 * @throws NoSuchAlgorithmException
	 *             could not get an SSLContext instance
	 * @throws KeyManagementException
	 *             failed to initialize the SSLContext
	 * @throws KeyStoreException
	 *             failed to intialize the {@link OpenIDTrustManager}
	 */
	public static void install(X509Certificate serverCertificate)
			throws KeyManagementException, NoSuchAlgorithmException,
			KeyStoreException {
		SSLSocketFactory sslSocketFactory = HttpsURLConnection
				.getDefaultSSLSocketFactory();
		if (!(sslSocketFactory instanceof OpenIDSSLSocketFactory)) {
			LOG.debug("installing OpenID SSL Socket Factory...");
			OpenIDSSLSocketFactory openIDSSLSocketFactory = new OpenIDSSLSocketFactory(
					serverCertificate);
			HttpsURLConnection
					.setDefaultSSLSocketFactory(openIDSSLSocketFactory);
		} else {
			LOG.debug("OpenID SSL Socket Factory already installed.");
		}
	}

	/**
	 * Installs the OpenID SSL Socket Factory. Trusts all server certificates.
	 * For testing purposes only!
	 * 
	 * @throws NoSuchAlgorithmException
	 *             could not get an SSLContext instance
	 * @throws KeyManagementException
	 *             failed to initialize the SSLContext
	 */
	public static void installAllTrusted() throws KeyManagementException,
			NoSuchAlgorithmException {
		SSLSocketFactory sslSocketFactory = HttpsURLConnection
				.getDefaultSSLSocketFactory();
		if (!(sslSocketFactory instanceof OpenIDSSLSocketFactory)) {
			LOG.debug("installing OpenID SSL Socket Factory...");
			OpenIDSSLSocketFactory openIDSSLSocketFactory = new OpenIDSSLSocketFactory();
			HttpsURLConnection
					.setDefaultSSLSocketFactory(openIDSSLSocketFactory);
			System.setProperty("java.protocol.handler.pkgs", "javax.net.ssl");
			HttpsURLConnection
					.setDefaultHostnameVerifier(org.apache.http.conn.ssl.SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
		} else {
			LOG.debug("OpenID SSL Socket Factory already installed.");
		}
	}
}

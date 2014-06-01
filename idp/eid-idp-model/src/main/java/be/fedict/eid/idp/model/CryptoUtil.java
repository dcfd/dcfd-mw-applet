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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.bouncycastle.openssl.PEMReader;

import be.fedict.eid.idp.entity.SecretKeyAlgorithm;
import be.fedict.eid.idp.model.exception.KeyLoadException;

/**
 * Some PKI/encryption utility methods
 * 
 * @author Wim Vandenhaute
 */
public abstract class CryptoUtil {

	public static X509Certificate getCertificate(byte[] certificateBytes)
			throws CertificateException {

		CertificateFactory certificateFactory = CertificateFactory
				.getInstance("X.509");
		return (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(certificateBytes));
	}

	public static PrivateKey getPrivateFromPem(byte[] keyBytes)
			throws KeyLoadException {

		Object pemObject = readPemObject(keyBytes);
		if (null != pemObject) {

		} else {
			return null;
		}

		if (!(pemObject instanceof KeyPair)) {
			throw new KeyLoadException("Invalid key format");
		}

		return ((KeyPair) pemObject).getPrivate();
	}

	public static PublicKey getPublicFromPem(byte[] keyBytes)
			throws KeyLoadException {

		Object pemObject = readPemObject(keyBytes);
		if (null != pemObject) {

		} else {
			return null;
		}

		if (!(pemObject instanceof PublicKey)) {
			throw new KeyLoadException("Invalid key format");
		}

		return ((PublicKey) pemObject);
	}

	private static Object readPemObject(byte[] keypairBytes)
			throws KeyLoadException {

		try {
			PEMReader pemReader = new PEMReader(new InputStreamReader(
					new ByteArrayInputStream(keypairBytes)));

			Object object = pemReader.readObject();
			pemReader.close();

			if (null == object) {
				return null;
			}

			return object;
		} catch (IOException e) {
			throw new KeyLoadException(e);
		}
	}

	public static PrivateKey getPrivate(byte[] keyBytes)
			throws KeyLoadException {

		// try DSA
		try {
			KeyFactory dsaKeyFactory = KeyFactory.getInstance("DSA");
			PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
					keyBytes);
			try {
				return dsaKeyFactory.generatePrivate(privateKeySpec);
			} catch (InvalidKeySpecException e) {
				// try RSA
				KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
				try {
					return rsaKeyFactory.generatePrivate(privateKeySpec);
				} catch (InvalidKeySpecException e1) {
					throw new KeyLoadException(e);
				}

			}
		} catch (NoSuchAlgorithmException e) {
			throw new KeyLoadException(e);
		}
	}

	public static Mac getMac(String encodedHmacSecret) throws DecoderException,
			InvalidKeyException {

		return getMac(Hex.decodeHex(encodedHmacSecret.toCharArray()));
	}

	public static Mac getMac(byte[] hmacSecret) throws InvalidKeyException {

		SecretKey macKey = new SecretKeySpec(hmacSecret, "HmacSHA1");
		Mac mac;
		try {
			mac = Mac.getInstance(macKey.getAlgorithm());
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException("HMAC algo not available: "
					+ e.getMessage());
		}
		mac.init(macKey);
		return mac;
	}

	public static SecretKey getSecretKey(SecretKeyAlgorithm secretKeyAlgorithm,
			String encodedSecretKey) throws DecoderException {

		byte[] secretKeyBytes = Hex.decodeHex(encodedSecretKey.toCharArray());

		String algorithm = null;
		switch (secretKeyAlgorithm) {

		case NONE:
			return null;
		case AES_128:
			algorithm = "AES";
			break;
		}

		return new SecretKeySpec(secretKeyBytes, algorithm);
	}

	public static PublicKey getPublicKey(byte[] publicKeyBytes)
			throws KeyLoadException {

		try {
			X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
					publicKeyBytes);
			KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
			return rsaKeyFactory.generatePublic(publicKeySpec);

		} catch (InvalidKeySpecException e) {
			throw new KeyLoadException(e);
		} catch (NoSuchAlgorithmException e) {
			throw new RuntimeException(e);
		}
	}
}

/*
 * eID Identity Provider Project.
 * Copyright (C) 2013 FedICT.
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

package be.fedict.eid.idp.protocol.openid;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Date;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;
import org.openid4java.association.Association;
import org.openid4java.association.AssociationException;
import org.openid4java.server.ServerAssociationStore;

/**
 * An implementation of a {@link ServerAssociationStore} that is completely
 * stateless. The state is kept within the handle itself. We protect the handle
 * via AES. The handle is a concatenation of IV and encrypted association data.
 * <p/>
 * Optionally you can also provide an HMAC secret key. This gives you an
 * additional message integrity verification.
 * 
 * @author Frank Cornelis
 * 
 */
public class StatelessServerAssociationStore implements ServerAssociationStore {

	private final static String CIPHER_ALGO = "AES/CBC/PKCS5Padding";

	private final SecretKeySpec secretKeySpec;

	private final SecretKeySpec macSecretKeySpec;

	private final SecureRandom secureRandom;

	public StatelessServerAssociationStore(SecretKeySpec secretKeySpec) {
		this(secretKeySpec, null);
	}

	/**
	 * Main constructor.
	 * 
	 * @param secretKeySpec
	 *            the AES secret key to protect the handle (confidentiality).
	 * @param macSecretKeySpec
	 *            the MAC secret key to protect the handle (integrity).
	 */
	public StatelessServerAssociationStore(SecretKeySpec secretKeySpec,
			SecretKeySpec macSecretKeySpec) {
		int length = secretKeySpec.getEncoded().length;
		if (length != 16 && length != 24 && length != 32) {
			throw new IllegalArgumentException(
					"secret key should be 16/24/32 bytes");
		}
		this.secretKeySpec = secretKeySpec;
		this.macSecretKeySpec = macSecretKeySpec;
		this.secureRandom = new SecureRandom();
		this.secureRandom.setSeed(System.currentTimeMillis());
	}

	public Association generate(String type, int expiryIn)
			throws AssociationException {
		String tmpHandle = "";
		Association tmpAssociation = Association.generate(type, tmpHandle,
				expiryIn);

		try {
			return setHandle(tmpAssociation);
		} catch (Exception e) {
			throw new AssociationException("error creating association: "
					+ e.getMessage(), e);
		}
	}

	public Association load(String handle) {
		try {
			return loadFromHandle(handle);
		} catch (Exception e) {
			throw new RuntimeException("error loading association: "
					+ e.getMessage(), e);
		}
	}

	public void remove(String handle) {
		/*
		 * Nothing needs to be removed as we're operating stateless.
		 */
		this.secureRandom.setSeed(System.currentTimeMillis());
	}

	private Association setHandle(Association association)
			throws AssociationException, IOException, NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException,
			IllegalBlockSizeException, BadPaddingException,
			InvalidAlgorithmParameterException, NoSuchProviderException {
		ByteArrayOutputStream encodedAssociation = new ByteArrayOutputStream();
		String type = association.getType();
		if (type == Association.TYPE_HMAC_SHA1) {
			encodedAssociation.write(1);
		} else if (type == Association.TYPE_HMAC_SHA256) {
			encodedAssociation.write(2);
		} else {
			throw new AssociationException("unknown type: " + type);
		}
		SecretKey macKey = association.getMacKey();
		byte[] macKeyBytes = macKey.getEncoded();
		encodedAssociation.write(macKeyBytes);
		Date expiry = association.getExpiry();
		Long time = expiry.getTime();
		DataOutputStream dos = new DataOutputStream(encodedAssociation);
		dos.writeLong(time);
		dos.flush();
		Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
		byte[] iv = new byte[16];
		this.secureRandom.nextBytes(iv);
		IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
		cipher.init(Cipher.ENCRYPT_MODE, this.secretKeySpec, ivParameterSpec);
		byte[] handleValue = cipher.doFinal(encodedAssociation.toByteArray());
		ByteArrayOutputStream result = new ByteArrayOutputStream();
		result.write(iv);
		result.write(handleValue);
		if (null != this.macSecretKeySpec) {
			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(this.macSecretKeySpec);
			byte[] toBeSigned = result.toByteArray();
			byte[] signature = mac.doFinal(toBeSigned);
			result = new ByteArrayOutputStream();
			result.write(signature);
			result.write(iv);
			result.write(handleValue);
		}
		String handle = Base64.encodeBase64URLSafeString(result.toByteArray());
		this.secureRandom.setSeed(result.toByteArray());
		if (handle.getBytes().length > 255) {
			throw new AssociationException("handle size > 255");
		}
		if (type == Association.TYPE_HMAC_SHA1) {
			return Association.createHmacSha1(handle, macKeyBytes, expiry);
		} else if (type == Association.TYPE_HMAC_SHA256) {
			return Association.createHmacSha256(handle, macKeyBytes, expiry);
		}
		throw new AssociationException("unknown type: " + type);
	}

	private Association loadFromHandle(String handle)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, IOException,
			InvalidAlgorithmParameterException {
		byte[] encodedHandle = Base64.decodeBase64(handle);
		if (null != this.macSecretKeySpec) {
			byte[] signature = new byte[32];
			System.arraycopy(encodedHandle, 0, signature, 0, 32);
			byte[] toBeSigned = new byte[encodedHandle.length - 32];
			System.arraycopy(encodedHandle, 32, toBeSigned, 0,
					encodedHandle.length - 32);
			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(this.macSecretKeySpec);
			byte[] actualSignature = mac.doFinal(toBeSigned);
			if (false == Arrays.equals(actualSignature, signature)) {
				return null;
			}
			encodedHandle = toBeSigned;
		}
		byte[] iv = new byte[16];
		System.arraycopy(encodedHandle, 0, iv, 0, iv.length);
		byte[] encodedData = Arrays.copyOfRange(encodedHandle, 16,
				encodedHandle.length);
		Cipher cipher = Cipher.getInstance(CIPHER_ALGO);
		IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
		cipher.init(Cipher.DECRYPT_MODE, this.secretKeySpec, ivParameterSpec);
		byte[] associationBytes = cipher.doFinal(encodedData);
		ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(
				associationBytes);
		int typeByte = byteArrayInputStream.read();
		if (typeByte == 1) {
			byte[] macKeyBytes = new byte[160 / 8];
			byteArrayInputStream.read(macKeyBytes);
			DataInputStream dataInputStream = new DataInputStream(
					byteArrayInputStream);
			long exp = dataInputStream.readLong();
			Date expDate = new Date(exp);
			return Association.createHmacSha1(handle, macKeyBytes, expDate);
		} else if (typeByte == 2) {
			byte[] macKeyBytes = new byte[256 / 8];
			byteArrayInputStream.read(macKeyBytes);
			DataInputStream dataInputStream = new DataInputStream(
					byteArrayInputStream);
			long exp = dataInputStream.readLong();
			Date expDate = new Date(exp);
			return Association.createHmacSha256(handle, macKeyBytes, expDate);
		} else {
			return null;
		}
	}
}

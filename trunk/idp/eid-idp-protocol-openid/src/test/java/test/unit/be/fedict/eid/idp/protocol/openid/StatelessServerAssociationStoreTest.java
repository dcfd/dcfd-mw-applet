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

package test.unit.be.fedict.eid.idp.protocol.openid;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.junit.Test;
import org.openid4java.association.Association;

import be.fedict.eid.idp.protocol.openid.StatelessServerAssociationStore;

public class StatelessServerAssociationStoreTest {

	private static final Log LOG = LogFactory
			.getLog(StatelessServerAssociationStoreTest.class);

	@Test
	public void testSecretKeySize() throws Exception {
		SecretKeySpec secretKeySpec = new SecretKeySpec(new byte[4], "AES");
		try {
			new StatelessServerAssociationStore(secretKeySpec);
			fail();
		} catch (IllegalArgumentException e) {
			// expected
		}
	}

	@Test
	public void testAssociationGeneration() throws Exception {
		SecretKeySpec secretKeySpec = new SecretKeySpec(new byte[16], "AES");
		StatelessServerAssociationStore testedInstance = new StatelessServerAssociationStore(
				secretKeySpec);

		Association association = testedInstance.generate(
				Association.TYPE_HMAC_SHA1, 1000);
		LOG.debug("handle size: " + association.getHandle().length());

		Association loadedAssociation = testedInstance.load(association
				.getHandle());

		assertNotNull(loadedAssociation);

		assertEquals(association.getHandle(), loadedAssociation.getHandle());
		assertEquals(association.getExpiry(), loadedAssociation.getExpiry());
		assertEquals(association.getType(), loadedAssociation.getType());
		assertArrayEquals(association.getMacKey().getEncoded(),
				loadedAssociation.getMacKey().getEncoded());
	}

	@Test
	public void testAssociationGeneration256() throws Exception {
		SecretKeySpec secretKeySpec = new SecretKeySpec(new byte[16], "AES");
		StatelessServerAssociationStore testedInstance = new StatelessServerAssociationStore(
				secretKeySpec);

		Association association = testedInstance.generate(
				Association.TYPE_HMAC_SHA256, 1000);
		LOG.debug("handle size: " + association.getHandle().length());

		Association loadedAssociation = testedInstance.load(association
				.getHandle());
		assertNotNull(loadedAssociation);

		assertEquals(association.getHandle(), loadedAssociation.getHandle());
		assertEquals(association.getExpiry(), loadedAssociation.getExpiry());
		assertEquals(association.getType(), loadedAssociation.getType());
		assertArrayEquals(association.getMacKey().getEncoded(),
				loadedAssociation.getMacKey().getEncoded());
	}

	// @Test
	// requires Java Cryptography Extension (JCE) Unlimited Strength
	// Jurisdiction Policy Files
	public void testAssociationGenerationAES256() throws Exception {
		SecretKeySpec secretKeySpec = new SecretKeySpec(new byte[32], "AES");
		StatelessServerAssociationStore testedInstance = new StatelessServerAssociationStore(
				secretKeySpec);

		Association association = testedInstance.generate(
				Association.TYPE_HMAC_SHA1, 1000);
		LOG.debug("handle size: " + association.getHandle().length());

		Association loadedAssociation = testedInstance.load(association
				.getHandle());

		assertNotNull(loadedAssociation);

		assertEquals(association.getHandle(), loadedAssociation.getHandle());
		assertEquals(association.getExpiry(), loadedAssociation.getExpiry());
		assertEquals(association.getType(), loadedAssociation.getType());
		assertArrayEquals(association.getMacKey().getEncoded(),
				loadedAssociation.getMacKey().getEncoded());
	}

	@Test
	public void testAssociationGenerationWithHMAC() throws Exception {
		SecretKeySpec secretKeySpec = new SecretKeySpec(new byte[16], "AES");
		SecretKeySpec macSecretKeySpec = new SecretKeySpec(new byte[16],
				"HmacSHA256");
		StatelessServerAssociationStore testedInstance = new StatelessServerAssociationStore(
				secretKeySpec, macSecretKeySpec);

		Association association = testedInstance.generate(
				Association.TYPE_HMAC_SHA1, 1000);
		LOG.debug("handle size: " + association.getHandle().length());

		Association loadedAssociation = testedInstance.load(association
				.getHandle());

		assertNotNull(loadedAssociation);

		assertEquals(association.getHandle(), loadedAssociation.getHandle());
		assertEquals(association.getExpiry(), loadedAssociation.getExpiry());
		assertEquals(association.getType(), loadedAssociation.getType());
		assertArrayEquals(association.getMacKey().getEncoded(),
				loadedAssociation.getMacKey().getEncoded());
	}

	@Test
	public void testAssociation256GenerationWithHMAC() throws Exception {
		SecretKeySpec secretKeySpec = new SecretKeySpec(new byte[16], "AES");
		SecretKeySpec macSecretKeySpec = new SecretKeySpec(new byte[16],
				"HmacSHA256");
		StatelessServerAssociationStore testedInstance = new StatelessServerAssociationStore(
				secretKeySpec, macSecretKeySpec);

		Association association = testedInstance.generate(
				Association.TYPE_HMAC_SHA256, 1000);
		LOG.debug("handle size: " + association.getHandle().length());

		Association loadedAssociation = testedInstance.load(association
				.getHandle());

		assertNotNull(loadedAssociation);

		assertEquals(association.getHandle(), loadedAssociation.getHandle());
		assertEquals(association.getExpiry(), loadedAssociation.getExpiry());
		assertEquals(association.getType(), loadedAssociation.getType());
		assertArrayEquals(association.getMacKey().getEncoded(),
				loadedAssociation.getMacKey().getEncoded());
	}
}

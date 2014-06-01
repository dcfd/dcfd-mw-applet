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

package test.unit.be.fedict.eid.idp.protocol.saml2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.HashMap;
import java.util.UUID;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.Init;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.joda.time.DateTime;
import org.junit.BeforeClass;
import org.junit.Test;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLObject;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.EncryptedAttribute;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.saml2.encryption.Encrypter;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.encryption.EncryptedKey;
import org.opensaml.xml.encryption.EncryptionConstants;
import org.opensaml.xml.encryption.EncryptionException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.util.DatatypeHelper;
import org.opensaml.xml.util.XMLConstants;
import org.w3c.dom.Attr;
import org.w3c.dom.Element;

import be.fedict.eid.idp.common.SamlAuthenticationPolicy;
import be.fedict.eid.idp.common.saml2.Saml2Util;

public class SAML2Test {

	private static final Log LOG = LogFactory.getLog(SAML2Test.class);

	@BeforeClass
	public static void before() {
		Security.addProvider(new BouncyCastleProvider());
		// Init.init();
	}

	@Test
	public void testAttributEncryptionSymmetric() throws Exception {

		// Setup
		String algorithm = EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128;

		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		kgen.init(128);
		SecretKey key = kgen.generateKey();

		Encrypter encrypter = Saml2Util.getEncrypter(algorithm, key);

		// Operate: encrypt
		EncryptedAttribute encTarget;
		XMLObject encObject = null;
		try {
			encObject = encrypter.encrypt(getAttribute());
		} catch (EncryptionException e) {
			fail("Object encryption failed: " + e);
		}

		// Verify
		LOG.debug(Saml2Util.domToString(Saml2Util.marshall(encObject), true));

		assertNotNull("Encrypted object was null", encObject);
		assertTrue("Encrypted object was not an instance of the expected type",
				encObject instanceof EncryptedAttribute);
		encTarget = (EncryptedAttribute) encObject;

		assertEquals("Type attribute", EncryptionConstants.TYPE_ELEMENT,
				encTarget.getEncryptedData().getType());
		assertEquals("Algorithm attribute", algorithm, encTarget
				.getEncryptedData().getEncryptionMethod().getAlgorithm());
		assertNotNull("KeyInfo", encTarget.getEncryptedData().getKeyInfo());

		assertEquals("Number of EncryptedKeys", 0, encTarget.getEncryptedData()
				.getKeyInfo().getEncryptedKeys().size());

		assertFalse("EncryptedData ID attribute was empty",
				DatatypeHelper.isEmpty(encTarget.getEncryptedData().getID()));

		// Setup
		Decrypter decrypter = Saml2Util.getDecrypter(key);

		// Operate: decrypt
		SAMLObject decryptedTarget = null;
		try {
			decryptedTarget = decrypter.decrypt(encTarget);
		} catch (DecryptionException e) {
			fail("Error on decryption of encrypted SAML 2 type to element: "
					+ e);
		}

		// Verify
		assertNotNull("Decrypted target was null", decryptedTarget);
		assertTrue("Decrypted target was not the expected type",
				decryptedTarget instanceof Attribute);
		LOG.debug(Saml2Util.domToString(Saml2Util.marshall(decryptedTarget),
				true));
	}

	@Test
	public void testAttributEncryptionAsymmetric() throws Exception {

		// Setup
		KeyPair keyPair = generateKeyPair();
		Encrypter encrypter = Saml2Util.getEncrypter(null, null,
				keyPair.getPublic());

		// Operate: encrypt
		EncryptedAttribute encTarget;
		XMLObject encObject = null;
		try {
			encObject = encrypter.encrypt(getAttribute());
		} catch (EncryptionException e) {
			fail("Object encryption failed: " + e);
		}

		// Verify
		LOG.debug(Saml2Util.domToString(Saml2Util.marshall(encObject), true));

		assertNotNull("Encrypted object was null", encObject);
		assertTrue("Encrypted object was not an instance of the expected type",
				encObject instanceof EncryptedAttribute);
		encTarget = (EncryptedAttribute) encObject;

		assertEquals("Type attribute", EncryptionConstants.TYPE_ELEMENT,
				encTarget.getEncryptedData().getType());
		assertEquals("Algorithm attribute",
				EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128, encTarget
						.getEncryptedData().getEncryptionMethod()
						.getAlgorithm());
		assertNotNull("KeyInfo", encTarget.getEncryptedData().getKeyInfo());
		assertEquals(1, encTarget.getEncryptedData().getKeyInfo()
				.getRetrievalMethods().size());
		assertEquals(XMLConstants.XMLENC_NS
				+ EncryptedKey.DEFAULT_ELEMENT_LOCAL_NAME, encTarget
				.getEncryptedData().getKeyInfo().getRetrievalMethods().get(0)
				.getType());

		assertEquals("Number of EncryptedKeys", 1, encTarget.getEncryptedKeys()
				.size());
		assertEquals(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSA15, encTarget
				.getEncryptedKeys().get(0).getEncryptionMethod().getAlgorithm());

		assertFalse("EncryptedData ID attribute was empty",
				DatatypeHelper.isEmpty(encTarget.getEncryptedData().getID()));

		// Setup
		Decrypter decrypter = Saml2Util.getDecrypter(keyPair.getPrivate());

		// Operate: decrypt
		SAMLObject decryptedTarget = null;
		try {
			decryptedTarget = decrypter.decrypt(encTarget);
		} catch (DecryptionException e) {
			fail("Error on decryption of encrypted SAML 2 type to element: "
					+ e);
		}

		// Verify
		assertNotNull("Decrypted target was null", decryptedTarget);
		assertTrue("Decrypted target was not the expected type",
				decryptedTarget instanceof Attribute);
		LOG.debug(Saml2Util.domToString(Saml2Util.marshall(decryptedTarget),
				true));
	}

	@Test
	public void testAttributEncryptionAsymmetric2() throws Exception {

		// Setup
		String algorithm = EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128;

		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		kgen.init(128);
		SecretKey key = kgen.generateKey();

		KeyPair keyPair = generateKeyPair();
		Encrypter encrypter = Saml2Util.getEncrypter(algorithm, key,
				keyPair.getPublic());

		// Operate: encrypt
		EncryptedAttribute encTarget;
		XMLObject encObject = null;
		try {
			encObject = encrypter.encrypt(getAttribute());
		} catch (EncryptionException e) {
			fail("Object encryption failed: " + e);
		}

		// Verify
		LOG.debug(Saml2Util.domToString(Saml2Util.marshall(encObject), true));

		assertNotNull("Encrypted object was null", encObject);
		assertTrue("Encrypted object was not an instance of the expected type",
				encObject instanceof EncryptedAttribute);
		encTarget = (EncryptedAttribute) encObject;

		assertEquals("Type attribute", EncryptionConstants.TYPE_ELEMENT,
				encTarget.getEncryptedData().getType());
		assertEquals("Algorithm attribute", algorithm, encTarget
				.getEncryptedData().getEncryptionMethod().getAlgorithm());
		assertNotNull("KeyInfo", encTarget.getEncryptedData().getKeyInfo());
		assertEquals(1, encTarget.getEncryptedData().getKeyInfo()
				.getRetrievalMethods().size());
		assertEquals(XMLConstants.XMLENC_NS
				+ EncryptedKey.DEFAULT_ELEMENT_LOCAL_NAME, encTarget
				.getEncryptedData().getKeyInfo().getRetrievalMethods().get(0)
				.getType());

		assertEquals("Number of EncryptedKeys", 1, encTarget.getEncryptedKeys()
				.size());
		assertEquals(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSA15, encTarget
				.getEncryptedKeys().get(0).getEncryptionMethod().getAlgorithm());

		assertFalse("EncryptedData ID attribute was empty",
				DatatypeHelper.isEmpty(encTarget.getEncryptedData().getID()));

		// Setup
		Decrypter decrypter = Saml2Util.getDecrypter(keyPair.getPrivate());

		// Operate: decrypt
		SAMLObject decryptedTarget = null;
		try {
			decryptedTarget = decrypter.decrypt(encTarget);
		} catch (DecryptionException e) {
			fail("Error on decryption of encrypted SAML 2 type to element: "
					+ e);
		}

		// Verify
		assertNotNull("Decrypted target was null", decryptedTarget);
		assertTrue("Decrypted target was not the expected type",
				decryptedTarget instanceof Attribute);
		LOG.debug(Saml2Util.domToString(Saml2Util.marshall(decryptedTarget),
				true));
	}

	private Attribute getAttribute() {

		Attribute attribute = Saml2Util.buildXMLObject(Attribute.class,
				Attribute.DEFAULT_ELEMENT_NAME);
		attribute.setName("test-attribute-name");

		XMLObjectBuilder<XSString> builder = Configuration.getBuilderFactory()
				.getBuilder(XSString.TYPE_NAME);
		XSString xmlAttributeValue = builder.buildObject(
				AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
		xmlAttributeValue.setValue("test-value");
		attribute.getAttributeValues().add(xmlAttributeValue);
		return attribute;
	}

	@Test
	public void testAssertionSigning() throws Exception {

		// Setup
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);

		KeyPair rootKeyPair = generateKeyPair();
		X509Certificate rootCertificate = generateSelfSignedCertificate(
				rootKeyPair, "CN=TestRoot", notBefore, notAfter);

		KeyPair endKeyPair = generateKeyPair();
		X509Certificate endCertificate = generateCertificate(
				endKeyPair.getPublic(), "CN=Test", notBefore, notAfter,
				rootCertificate, rootKeyPair.getPrivate());

		Certificate[] certChain = { endCertificate, rootCertificate };

		KeyStore.PrivateKeyEntry idpIdentity = new KeyStore.PrivateKeyEntry(
				endKeyPair.getPrivate(), certChain);

		// Operate: sign
		Assertion assertion = Saml2Util.getAssertion("test-issuer",
				"test-in-response-to", "test-audience", "test-recipient", 5,
				new DateTime(), SamlAuthenticationPolicy.AUTHENTICATION, UUID
						.randomUUID().toString(),
				new HashMap<String, be.fedict.eid.idp.common.Attribute>(),
				null, null);
		Assertion signedAssertion = (Assertion) Saml2Util.sign(assertion,
				idpIdentity);

		// Verify
		String result = Saml2Util.domToString(
				Saml2Util.marshall(signedAssertion), true);
		LOG.debug("DOM signed assertion: " + result);
		String result2 = Saml2Util.domToString(Saml2Util.marshall(assertion),
				true);
		LOG.debug("signed assertion: " + result2);
		assertEquals(result, result2);

		// Fix for recent Apache Xmlsec libraries.
		Element signedAssertionElement = (Element) signedAssertion.getDOM();
		String assertionId = assertion.getID();
		Element locatedElement = signedAssertionElement.getOwnerDocument()
				.getElementById(assertionId);
		LOG.debug("element located by ID: " + (null != locatedElement));

		Attr attr = signedAssertionElement.getAttributeNode("ID");
		signedAssertionElement.setIdAttributeNode(attr, true);
		signedAssertion.setDOM(signedAssertionElement);

		// Operate: validate
		Saml2Util.validateSignature(signedAssertion.getSignature());
	}

	@Test
	public void testGetAlgorithm() throws Exception {

		KeyGenerator kgen = KeyGenerator.getInstance("AES");
		kgen.init(128);
		SecretKey key = kgen.generateKey();
		LOG.debug("Algorithm AES-128: " + key.getAlgorithm());

	}

	private KeyPair generateKeyPair() throws Exception {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		SecureRandom random = new SecureRandom();
		keyPairGenerator.initialize(new RSAKeyGenParameterSpec(1024,
				RSAKeyGenParameterSpec.F4), random);
		return keyPairGenerator.generateKeyPair();
	}

	private SubjectKeyIdentifier createSubjectKeyId(PublicKey publicKey)
			throws IOException {
		ByteArrayInputStream bais = new ByteArrayInputStream(
				publicKey.getEncoded());
		SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
				(ASN1Sequence) new ASN1InputStream(bais).readObject());
		return new SubjectKeyIdentifier(info);
	}

	private AuthorityKeyIdentifier createAuthorityKeyId(PublicKey publicKey)
			throws IOException {

		ByteArrayInputStream bais = new ByteArrayInputStream(
				publicKey.getEncoded());
		SubjectPublicKeyInfo info = new SubjectPublicKeyInfo(
				(ASN1Sequence) new ASN1InputStream(bais).readObject());

		return new AuthorityKeyIdentifier(info);
	}

	private X509Certificate generateSelfSignedCertificate(KeyPair keyPair,
			String subjectDn, DateTime notBefore, DateTime notAfter)
			throws Exception {

		return generateCertificate(keyPair.getPublic(), subjectDn, notBefore,
				notAfter, null, keyPair.getPrivate());
	}

	private X509Certificate generateCertificate(PublicKey subjectPublicKey,
			String subjectDn, DateTime notBefore, DateTime notAfter,
			X509Certificate issuerCertificate, PrivateKey issuerPrivateKey)
			throws Exception {

		X509V3CertificateGenerator certificateGenerator = new X509V3CertificateGenerator();
		certificateGenerator.reset();
		certificateGenerator.setPublicKey(subjectPublicKey);
		certificateGenerator.setSignatureAlgorithm("SHA1WithRSAEncryption");
		certificateGenerator.setNotBefore(notBefore.toDate());
		certificateGenerator.setNotAfter(notAfter.toDate());

		X509Principal issuerDN;
		if (null != issuerCertificate) {
			issuerDN = new X509Principal(issuerCertificate
					.getSubjectX500Principal().toString());
		} else {
			issuerDN = new X509Principal(subjectDn);
		}
		certificateGenerator.setIssuerDN(issuerDN);
		certificateGenerator.setSubjectDN(new X509Principal(subjectDn));
		certificateGenerator.setSerialNumber(new BigInteger(128,
				new SecureRandom()));

		certificateGenerator.addExtension(X509Extensions.SubjectKeyIdentifier,
				false, createSubjectKeyId(subjectPublicKey));

		PublicKey issuerPublicKey;
		if (null != issuerCertificate) {
			issuerPublicKey = issuerCertificate.getPublicKey();
		} else {
			issuerPublicKey = subjectPublicKey;
		}
		certificateGenerator.addExtension(
				X509Extensions.AuthorityKeyIdentifier, false,
				createAuthorityKeyId(issuerPublicKey));

		X509Certificate certificate;
		certificate = certificateGenerator.generate(issuerPrivateKey);

		/*
		 * Next certificate factory trick is needed to make sure that the
		 * certificate delivered to the caller is provided by the default
		 * security provider instead of BouncyCastle. If we don't do this trick
		 * we might run into trouble when trying to use the CertPath validator.
		 */
		CertificateFactory certificateFactory = CertificateFactory
				.getInstance("X.509");
		certificate = (X509Certificate) certificateFactory
				.generateCertificate(new ByteArrayInputStream(certificate
						.getEncoded()));
		return certificate;
	}
}
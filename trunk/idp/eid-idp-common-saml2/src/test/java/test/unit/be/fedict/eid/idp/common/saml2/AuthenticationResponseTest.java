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

package test.unit.be.fedict.eid.idp.common.saml2;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
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
import java.util.List;
import java.util.Map;
import java.util.UUID;

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
import org.opensaml.saml2.core.Assertion;

import be.fedict.eid.idp.common.Attribute;
import be.fedict.eid.idp.common.AttributeType;
import be.fedict.eid.idp.common.SamlAuthenticationPolicy;
import be.fedict.eid.idp.common.saml2.AuthenticationResponse;
import be.fedict.eid.idp.common.saml2.Saml2Util;

public class AuthenticationResponseTest {

	@BeforeClass
	public static void before() {
		Security.addProvider(new BouncyCastleProvider());
	}

	/*
	 * Unit test for serialization/deserialization check on
	 * AuthenticationResponse and validation of Assertion's signature
	 * afterwards.
	 */
	@Test
	public void testAssertion() throws Exception {

		// Setup
		KeyPair keyPair = generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = generateSelfSignedCertificate(keyPair,
				"CN=Test", notBefore, notAfter);

		KeyStore.PrivateKeyEntry privateKeyEntry = new KeyStore.PrivateKeyEntry(
				keyPair.getPrivate(), new Certificate[] { certificate });

		String userId = UUID.randomUUID().toString();
		String attributeName = "urn:test:attribute";
		Attribute attribute = new Attribute(attributeName,
				AttributeType.STRING, UUID.randomUUID().toString());
		Map<String, Attribute> attributes = new HashMap<String, Attribute>();
		attributes.put(attributeName, attribute);

		String issuerName = "test-issuer";

		String requestIssuer = "request-issuer";
		String requestId = UUID.randomUUID().toString();
		String recipient = "http://www.testsp.com/saml";

		Assertion assertion = Saml2Util.getAssertion(issuerName, requestId,
				requestIssuer, recipient, 5, new DateTime(),
				SamlAuthenticationPolicy.IDENTIFICATION, userId, attributes,
				null, null);

		// Operate: sign assertion
		Saml2Util.sign(assertion, privateKeyEntry);

		// Verify
		List<X509Certificate> certChain = Saml2Util.validateSignature(assertion
				.getSignature());
		assertNotNull(certChain);
		assertEquals(1, certChain.size());

		// Operate: validate assertion
		AuthenticationResponse authenticationResponse = Saml2Util
				.validateAssertion(assertion, new DateTime(), 5, requestIssuer,
						recipient, requestId, null, null);

		// Verify
		assertNotNull(authenticationResponse);
		assertNotNull(authenticationResponse.getAssertion());

		// Operate: serialize AuthenticationResponse
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		ObjectOutputStream oos = new ObjectOutputStream(out);
		oos.writeObject(authenticationResponse);
		oos.close();

		// Operate: deserialize AuthenticationResponse
		byte[] input = out.toByteArray();
		InputStream in = new ByteArrayInputStream(input);
		ObjectInputStream ois = new ObjectInputStream(in);
		Object o = ois.readObject();
		AuthenticationResponse copy = (AuthenticationResponse) o;

		// Verify
		assertNotNull(copy);
		Assertion assertionCopy = copy.getAssertion();
		assertNotNull(assertionCopy);
		Saml2Util.validateSignature(assertionCopy.getSignature());
		AuthenticationResponse authenticationResponseCopy = Saml2Util
				.validateAssertion(assertionCopy, new DateTime(), 5,
						requestIssuer, recipient, requestId, null, null);
		assertEquals(authenticationResponse.getEncodedAssertion(),
				authenticationResponseCopy.getEncodedAssertion());
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

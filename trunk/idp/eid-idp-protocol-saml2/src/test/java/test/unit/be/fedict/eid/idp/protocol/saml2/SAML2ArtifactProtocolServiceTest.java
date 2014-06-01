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
import static org.junit.Assert.assertNotNull;

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
import java.util.Collections;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.easymock.EasyMock;
import org.joda.time.DateTime;
import org.junit.BeforeClass;
import org.junit.Test;

import be.fedict.eid.applet.service.Gender;
import be.fedict.eid.applet.service.Identity;
import be.fedict.eid.idp.common.Attribute;
import be.fedict.eid.idp.protocol.saml2.AbstractSAML2ProtocolService;
import be.fedict.eid.idp.protocol.saml2.artifact.AbstractSAML2ArtifactProtocolService;
import be.fedict.eid.idp.protocol.saml2.artifact.SAML2ProtocolServiceAuthIdent;
import be.fedict.eid.idp.spi.IdPIdentity;
import be.fedict.eid.idp.spi.IdentityProviderConfiguration;
import be.fedict.eid.idp.spi.NameValuePair;
import be.fedict.eid.idp.spi.ReturnResponse;

public class SAML2ArtifactProtocolServiceTest {

	private static final Log LOG = LogFactory
			.getLog(SAML2ArtifactProtocolServiceTest.class);

	@BeforeClass
	public static void before() {
		Security.addProvider(new BouncyCastleProvider());
	}

	@Test
	public void testHandleReturnResponse() throws Exception {

		// setup
		SAML2ProtocolServiceAuthIdent saml2ProtocolService = new SAML2ProtocolServiceAuthIdent();

		String userId = UUID.randomUUID().toString();
		String givenName = "test-given-name";
		String surName = "test-sur-name";
		Identity identity = new Identity();
		identity.name = surName;
		identity.firstName = givenName;
		identity.gender = Gender.MALE;
		identity.dateOfBirth = new GregorianCalendar();
		identity.nationality = "BELG";
		identity.placeOfBirth = "Gent";
		HttpSession mockHttpSession = EasyMock.createMock(HttpSession.class);
		HttpServletRequest mockHttpServletRequest = EasyMock
				.createMock(HttpServletRequest.class);
		HttpServletResponse mockHttpServletResponse = EasyMock
				.createMock(HttpServletResponse.class);
		ServletContext mockServletContext = EasyMock
				.createMock(ServletContext.class);

		KeyPair keyPair = generateKeyPair();
		DateTime notBefore = new DateTime();
		DateTime notAfter = notBefore.plusMonths(1);
		X509Certificate certificate = generateSelfSignedCertificate(keyPair,
				"CN=Test", notBefore, notAfter);

		IdPIdentity idpIdentity = new IdPIdentity("test",
				new KeyStore.PrivateKeyEntry(keyPair.getPrivate(),
						new Certificate[] { certificate }));

		IdentityProviderConfiguration mockConfiguration = EasyMock
				.createMock(IdentityProviderConfiguration.class);

		// expectations
		mockServletContext.setAttribute(
				AbstractSAML2ProtocolService.IDP_CONFIG_CONTEXT_ATTRIBUTE,
				mockConfiguration);
		EasyMock.expect(mockHttpSession.getServletContext())
				.andReturn(mockServletContext).times(3);
		EasyMock.expect(
				mockServletContext
						.getAttribute(AbstractSAML2ProtocolService.IDP_CONFIG_CONTEXT_ATTRIBUTE))
				.andReturn(mockConfiguration).times(3);
		EasyMock.expect(
				mockHttpSession
						.getAttribute(AbstractSAML2ProtocolService.TARGET_URL_SESSION_ATTRIBUTE))
				.andStubReturn("http://127.0.0.1");
		EasyMock.expect(
				mockHttpSession
						.getAttribute(AbstractSAML2ProtocolService.RELAY_STATE_SESSION_ATTRIBUTE))
				.andStubReturn("relay-state");
		EasyMock.expect(
				mockHttpSession
						.getAttribute(AbstractSAML2ProtocolService.IN_RESPONSE_TO_SESSION_ATTRIBUTE))
				.andStubReturn("a77a1c87-e590-47d7-a3e0-afea455ebc01");
		EasyMock.expect(
				mockHttpSession
						.getAttribute(AbstractSAML2ProtocolService.ISSUER_SESSION_ATTRIBUTE))
				.andStubReturn("Issuer");

		EasyMock.expect(mockConfiguration.getResponseTokenValidity())
				.andStubReturn(5);
		EasyMock.expect(mockConfiguration.findIdentity()).andStubReturn(
				idpIdentity);
		EasyMock.expect(mockConfiguration.getIdentityCertificateChain())
				.andStubReturn(Collections.singletonList(certificate));
		EasyMock.expect(mockConfiguration.getDefaultIssuer()).andStubReturn(
				"TestIssuer");

		EasyMock.expect(mockHttpServletRequest.getSession())
				.andReturn(mockHttpSession).times(3);
		EasyMock.expect(
				mockServletContext
						.getAttribute(AbstractSAML2ArtifactProtocolService.ARTIFACT_MAP_ATTRIBUTE))
				.andReturn(null);
		mockServletContext
				.setAttribute(
						EasyMock.matches(AbstractSAML2ArtifactProtocolService.ARTIFACT_MAP_ATTRIBUTE),
						EasyMock.anyObject());
		EasyMock.expect(mockHttpServletRequest.getServerName())
				.andReturn("127.0.0.1").times(2);
		EasyMock.expect(mockHttpServletRequest.getServerPort()).andReturn(8443)
				.times(3);
		EasyMock.expect(mockHttpServletRequest.getContextPath())
				.andReturn("/eid-idp").times(2);
		EasyMock.expect(
				mockHttpSession
						.getAttribute(AbstractSAML2ArtifactProtocolService.ISSUER_SESSION_ATTRIBUTE))
				.andReturn("SPIssuer");

		// prepare
		EasyMock.replay(mockHttpServletRequest, mockHttpSession,
				mockServletContext, mockConfiguration);

		// operate
		saml2ProtocolService.init(mockServletContext, mockConfiguration);
		ReturnResponse returnResponse = saml2ProtocolService
				.handleReturnResponse(mockHttpSession, userId,
						new HashMap<String, Attribute>(), null, null, null,
						mockHttpServletRequest, mockHttpServletResponse);

		// verify
		EasyMock.verify(mockHttpServletRequest, mockHttpSession,
				mockServletContext, mockConfiguration);
		assertNotNull(returnResponse);
		assertEquals("http://127.0.0.1", returnResponse.getActionUrl());
		List<NameValuePair> attributes = returnResponse.getAttributes();
		assertNotNull(attributes);
		NameValuePair relayStateAttribute = null;
		NameValuePair samlArtAttribute = null;
		for (NameValuePair attribute : attributes) {
			if ("RelayState".equals(attribute.getName())) {
				relayStateAttribute = attribute;
				continue;
			}
			if ("SAMLart".equals(attribute.getName())) {
				samlArtAttribute = attribute;
				continue;
			}
		}
		assertNotNull(relayStateAttribute);
		assertEquals("relay-state", relayStateAttribute.getValue());
		assertNotNull("no SAMLArt attribute", samlArtAttribute);
		String encodedSamlArt = samlArtAttribute.getValue();
		assertNotNull(encodedSamlArt);
		String samlArtifact = new String(Base64.decodeBase64(encodedSamlArt));
		LOG.debug("SAML Artifact: " + samlArtifact);
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
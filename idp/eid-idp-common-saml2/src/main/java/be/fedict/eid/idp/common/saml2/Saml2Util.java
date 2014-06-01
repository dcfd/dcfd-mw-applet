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

package be.fedict.eid.idp.common.saml2;

import java.io.IOException;
import java.io.OutputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.GregorianCalendar;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import javax.crypto.SecretKey;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.XMLSignContext;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Result;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xml.security.utils.Constants;
import org.apache.xpath.XPathAPI;
import org.joda.time.DateTime;
import org.joda.time.chrono.ISOChronology;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.EncryptedAttribute;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.OneTimeUse;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.saml2.encryption.Encrypter;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.NameIDFormat;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.ws.wstrust.KeyType;
import org.opensaml.ws.wstrust.RequestSecurityTokenResponse;
import org.opensaml.ws.wstrust.RequestSecurityTokenResponseCollection;
import org.opensaml.ws.wstrust.RequestType;
import org.opensaml.ws.wstrust.RequestedSecurityToken;
import org.opensaml.ws.wstrust.TokenType;
import org.opensaml.ws.wstrust.impl.KeyTypeBuilder;
import org.opensaml.ws.wstrust.impl.KeyTypeMarshaller;
import org.opensaml.ws.wstrust.impl.KeyTypeUnmarshaller;
import org.opensaml.ws.wstrust.impl.RequestSecurityTokenResponseBuilder;
import org.opensaml.ws.wstrust.impl.RequestSecurityTokenResponseCollectionBuilder;
import org.opensaml.ws.wstrust.impl.RequestSecurityTokenResponseCollectionMarshaller;
import org.opensaml.ws.wstrust.impl.RequestSecurityTokenResponseCollectionUnmarshaller;
import org.opensaml.ws.wstrust.impl.RequestSecurityTokenResponseMarshaller;
import org.opensaml.ws.wstrust.impl.RequestSecurityTokenResponseUnmarshaller;
import org.opensaml.ws.wstrust.impl.RequestTypeBuilder;
import org.opensaml.ws.wstrust.impl.RequestTypeMarshaller;
import org.opensaml.ws.wstrust.impl.RequestTypeUnmarshaller;
import org.opensaml.ws.wstrust.impl.RequestedSecurityTokenBuilder;
import org.opensaml.ws.wstrust.impl.RequestedSecurityTokenMarshaller;
import org.opensaml.ws.wstrust.impl.RequestedSecurityTokenUnmarshaller;
import org.opensaml.ws.wstrust.impl.TokenTypeBuilder;
import org.opensaml.ws.wstrust.impl.TokenTypeMarshaller;
import org.opensaml.ws.wstrust.impl.TokenTypeUnmarshaller;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.encryption.EncryptionConstants;
import org.opensaml.xml.encryption.EncryptionException;
import org.opensaml.xml.encryption.EncryptionParameters;
import org.opensaml.xml.encryption.KeyEncryptionParameters;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.schema.XSBase64Binary;
import org.opensaml.xml.schema.XSDateTime;
import org.opensaml.xml.schema.XSInteger;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.security.credential.BasicCredential;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoGenerator;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.opensaml.xml.signature.KeyInfo;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.Signer;
import org.opensaml.xml.signature.impl.SignatureBuilder;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Attr;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;

import be.fedict.eid.idp.common.SamlAuthenticationPolicy;

/**
 * Utility class for SAML v2.0
 * 
 * @author Wim Vandenhaute
 */
public abstract class Saml2Util {

	private static final Log LOG = LogFactory.getLog(Saml2Util.class);

	static {
		/*
		 * Next is because Sun loves to endorse crippled versions of Xerces.
		 */
		System.setProperty(
				"javax.xml.validation.SchemaFactory:http://www.w3.org/2001/XMLSchema",
				"org.apache.xerces.jaxp.validation.XMLSchemaFactory");
		try {
			DefaultBootstrap.bootstrap();

			// register WS-Trust elements needed in WS-Federation
			Configuration.registerObjectProvider(
					RequestSecurityTokenResponseCollection.ELEMENT_NAME,
					new RequestSecurityTokenResponseCollectionBuilder(),
					new RequestSecurityTokenResponseCollectionMarshaller(),
					new RequestSecurityTokenResponseCollectionUnmarshaller());

			Configuration.registerObjectProvider(
					RequestSecurityTokenResponse.ELEMENT_NAME,
					new RequestSecurityTokenResponseBuilder(),
					new RequestSecurityTokenResponseMarshaller(),
					new RequestSecurityTokenResponseUnmarshaller());

			Configuration.registerObjectProvider(TokenType.ELEMENT_NAME,
					new TokenTypeBuilder(), new TokenTypeMarshaller(),
					new TokenTypeUnmarshaller());

			Configuration.registerObjectProvider(RequestType.ELEMENT_NAME,
					new RequestTypeBuilder(), new RequestTypeMarshaller(),
					new RequestTypeUnmarshaller());

			Configuration.registerObjectProvider(KeyType.ELEMENT_NAME,
					new KeyTypeBuilder(), new KeyTypeMarshaller(),
					new KeyTypeUnmarshaller());

			Configuration.registerObjectProvider(
					RequestedSecurityToken.ELEMENT_NAME,
					new RequestedSecurityTokenBuilder(),
					new RequestedSecurityTokenMarshaller(),
					new RequestedSecurityTokenUnmarshaller());

		} catch (ConfigurationException e) {
			throw new RuntimeException(
					"could not bootstrap the OpenSAML2 library", e);
		}
	}

	/**
	 * Returns SAML v2.0 Metadata {@link EntityDescriptor} with 1
	 * {@link AssertionConsumerService} at specified location with specified
	 * binding.
	 * 
	 * @param entityId
	 *            entity ID (== response.issuer)
	 * @param location
	 *            location
	 * @param binding
	 *            SAML v2.0 Binding
	 * @param identity
	 *            optional identity, if present key descriptor will be added.
	 * @return the metadata entity descriptor
	 */
	public static EntityDescriptor getEntityDescriptor(String entityId,
			String location, String binding, KeyStore.PrivateKeyEntry identity) {

		// Add a descriptor for our node (the SAMLv2 Entity).
		EntityDescriptor entityDescriptor = Saml2Util.buildXMLObject(
				EntityDescriptor.class, EntityDescriptor.DEFAULT_ELEMENT_NAME);

		entityDescriptor.setEntityID(entityId);

		// signature
		if (null != identity) {
			// Add a signature to the entity descriptor.
			Signature signature = Saml2Util.buildXMLObject(Signature.class,
					Signature.DEFAULT_ELEMENT_NAME);
			entityDescriptor.setSignature(signature);

			signature
					.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

			// add certificate chain as keyinfo
			signature.setKeyInfo(getKeyInfo(identity));

			BasicX509Credential signingCredential = new BasicX509Credential();
			signingCredential.setPrivateKey(identity.getPrivateKey());
			signingCredential
					.setEntityCertificateChain(getCertificateChain(identity));
			signature.setSigningCredential(signingCredential);

			String algorithm = identity.getPrivateKey().getAlgorithm();
			if ("RSA".equals(algorithm)) {
				signature
						.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA);
			} else {
				signature
						.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_ECDSA_SHA1);
			}
		}

		// Add a descriptor for our identity services.
		IDPSSODescriptor idpssoDescriptor = Saml2Util.buildXMLObject(
				IDPSSODescriptor.class, IDPSSODescriptor.DEFAULT_ELEMENT_NAME);
		entityDescriptor.getRoleDescriptors().add(idpssoDescriptor);

		idpssoDescriptor.setWantAuthnRequestsSigned(false);
		idpssoDescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);

		// NameID Format
		NameIDFormat nameIDFormat = Saml2Util.buildXMLObject(
				NameIDFormat.class, NameIDFormat.DEFAULT_ELEMENT_NAME);
		nameIDFormat.setFormat(NameIDType.TRANSIENT);
		idpssoDescriptor.getNameIDFormats().add(nameIDFormat);

		// Key descriptor
		if (null != identity) {
			KeyDescriptor keyDescriptor = Saml2Util.buildXMLObject(
					KeyDescriptor.class, KeyDescriptor.DEFAULT_ELEMENT_NAME);
			keyDescriptor.setKeyInfo(getKeyInfo(identity));
			keyDescriptor.setUse(UsageType.SIGNING);
			idpssoDescriptor.getKeyDescriptors().add(keyDescriptor);
		}

		// SSO services
		SingleSignOnService ssoService = Saml2Util.buildXMLObject(
				SingleSignOnService.class,
				SingleSignOnService.DEFAULT_ELEMENT_NAME);
		idpssoDescriptor.getSingleSignOnServices().add(ssoService);

		ssoService.setBinding(binding);
		ssoService.setLocation(location);

		return entityDescriptor;
	}

	private static KeyInfo getKeyInfo(KeyStore.PrivateKeyEntry identity) {

		List<X509Certificate> certificateChain = getCertificateChain(identity);
		KeyInfo keyInfo = Saml2Util.buildXMLObject(KeyInfo.class,
				KeyInfo.DEFAULT_ELEMENT_NAME);
		try {
			for (X509Certificate certificate : certificateChain) {
				KeyInfoHelper.addCertificate(keyInfo, certificate);
			}
		} catch (CertificateEncodingException e) {
			throw new RuntimeException("opensaml2 certificate encoding error: "
					+ e.getMessage(), e);
		}
		return keyInfo;
	}

	/**
	 * Return the {@link X509Certificate} chain for specified identity
	 * 
	 * @param identity
	 *            identity to get chain from
	 * @return the certificate chain.
	 */
	public static List<X509Certificate> getCertificateChain(
			KeyStore.PrivateKeyEntry identity) {

		List<X509Certificate> certificateChain = new LinkedList<X509Certificate>();
		for (java.security.cert.Certificate certificate : identity
				.getCertificateChain()) {
			certificateChain.add((X509Certificate) certificate);
		}
		return certificateChain;
	}

	/**
	 * Constructs a bare SAML v2.0 {@link Response} with status Success.
	 * 
	 * @param inResponseTo
	 *            response inresponse to request.ID
	 * @param targetUrl
	 *            targetURL
	 * @param issuerName
	 *            issuer of the response
	 * @return SAML v2.0 Response
	 */
	public static Response getResponse(String inResponseTo, String targetUrl,
			String issuerName) {

		Response response = Saml2Util.buildXMLObject(Response.class,
				Response.DEFAULT_ELEMENT_NAME);
		DateTime issueInstant = new DateTime();
		response.setIssueInstant(issueInstant);
		response.setVersion(SAMLVersion.VERSION_20);
		response.setDestination(targetUrl);
		String samlResponseId = "saml-response-" + UUID.randomUUID().toString();
		response.setID(samlResponseId);
		response.setInResponseTo(inResponseTo);

		Issuer issuer = Saml2Util.buildXMLObject(Issuer.class,
				Issuer.DEFAULT_ELEMENT_NAME);
		issuer.setValue(issuerName);
		response.setIssuer(issuer);

		Status status = Saml2Util.buildXMLObject(Status.class,
				Status.DEFAULT_ELEMENT_NAME);
		response.setStatus(status);
		StatusCode statusCode = Saml2Util.buildXMLObject(StatusCode.class,
				StatusCode.DEFAULT_ELEMENT_NAME);
		status.setStatusCode(statusCode);
		statusCode.setValue(StatusCode.SUCCESS_URI);
		return response;
	}

	/**
	 * Construct an unsigned SAML v2.0 Assertion
	 * 
	 * @param issuerName
	 *            assertion issuer
	 * @param inResponseTo
	 *            optional inResponseTo
	 * @param audienceUri
	 *            audience in audience restriction
	 * @param recipient
	 *            recipient (SubjectConfirmationData.recipient)
	 * @param tokenValidity
	 *            valitity in minutes of the assertion
	 * @param issueInstant
	 *            time of issuance
	 * @param authenticationPolicy
	 *            authentication policy
	 * @param userId
	 *            user ID
	 * @param attributes
	 *            map of user's attributes
	 * @param secretKey
	 *            optional symmetric SecretKey used for encryption
	 * @param publicKey
	 *            optional RSA public key used for encryption
	 * @return the unsigned SAML v2.0 assertion.
	 */
	public static Assertion getAssertion(String issuerName,
			String inResponseTo, String audienceUri, String recipient,
			Integer tokenValidity, DateTime issueInstant,
			SamlAuthenticationPolicy authenticationPolicy, String userId,
			Map<String, be.fedict.eid.idp.common.Attribute> attributes,
			SecretKey secretKey, PublicKey publicKey) {

		int validity = 5;
		if (null != tokenValidity && tokenValidity > 0) {
			validity = tokenValidity;
		}

		Assertion assertion = buildXMLObject(Assertion.class,
				Assertion.DEFAULT_ELEMENT_NAME);
		assertion.setVersion(SAMLVersion.VERSION_20);
		String assertionId = "assertion-" + UUID.randomUUID().toString();
		assertion.setID(assertionId);
		assertion.setIssueInstant(issueInstant);

		// issuer
		Issuer issuer = buildXMLObject(Issuer.class,
				Issuer.DEFAULT_ELEMENT_NAME);
		assertion.setIssuer(issuer);
		issuer.setValue(issuerName);

		// conditions
		Conditions conditions = buildXMLObject(Conditions.class,
				Conditions.DEFAULT_ELEMENT_NAME);
		assertion.setConditions(conditions);
		DateTime notAfter = issueInstant.plusMinutes(validity);
		conditions.setNotBefore(issueInstant);
		conditions.setNotOnOrAfter(notAfter);

		if (null != inResponseTo) {
			conditions.getConditions().add(
					Saml2Util.buildXMLObject(OneTimeUse.class,
							OneTimeUse.DEFAULT_ELEMENT_NAME));
		}

		// audience restriction
		List<AudienceRestriction> audienceRestrictionList = conditions
				.getAudienceRestrictions();
		AudienceRestriction audienceRestriction = buildXMLObject(
				AudienceRestriction.class,
				AudienceRestriction.DEFAULT_ELEMENT_NAME);
		audienceRestrictionList.add(audienceRestriction);
		List<Audience> audiences = audienceRestriction.getAudiences();
		Audience audience = buildXMLObject(Audience.class,
				Audience.DEFAULT_ELEMENT_NAME);
		audiences.add(audience);
		audience.setAudienceURI(audienceUri);

		// subject
		Subject subject = buildXMLObject(Subject.class,
				Subject.DEFAULT_ELEMENT_NAME);
		assertion.setSubject(subject);
		NameID nameId = buildXMLObject(NameID.class,
				NameID.DEFAULT_ELEMENT_NAME);
		subject.setNameID(nameId);
		nameId.setValue(userId);

		// subject confirmation
		List<SubjectConfirmation> subjectConfirmations = subject
				.getSubjectConfirmations();
		SubjectConfirmation subjectConfirmation = buildXMLObject(
				SubjectConfirmation.class,
				SubjectConfirmation.DEFAULT_ELEMENT_NAME);
		subjectConfirmations.add(subjectConfirmation);
		subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
		if (null != inResponseTo) {
			SubjectConfirmationData subjectConfirmationData = buildXMLObject(
					SubjectConfirmationData.class,
					SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
			subjectConfirmation
					.setSubjectConfirmationData(subjectConfirmationData);
			subjectConfirmationData.setRecipient(recipient);
			subjectConfirmationData.setInResponseTo(inResponseTo);
			subjectConfirmationData.setNotBefore(issueInstant);
			subjectConfirmationData.setNotOnOrAfter(notAfter);
		}

		// authentication statement
		List<AuthnStatement> authnStatements = assertion.getAuthnStatements();
		AuthnStatement authnStatement = buildXMLObject(AuthnStatement.class,
				AuthnStatement.DEFAULT_ELEMENT_NAME);
		authnStatements.add(authnStatement);
		authnStatement.setAuthnInstant(issueInstant);
		AuthnContext authnContext = buildXMLObject(AuthnContext.class,
				AuthnContext.DEFAULT_ELEMENT_NAME);
		authnStatement.setAuthnContext(authnContext);

		AuthnContextClassRef authnContextClassRef = buildXMLObject(
				AuthnContextClassRef.class,
				AuthnContextClassRef.DEFAULT_ELEMENT_NAME);
		authnContextClassRef.setAuthnContextClassRef(authenticationPolicy
				.getUri());
		authnContext.setAuthnContextClassRef(authnContextClassRef);

		// attribute statement
		List<AttributeStatement> attributeStatements = assertion
				.getAttributeStatements();
		AttributeStatement attributeStatement = buildXMLObject(
				AttributeStatement.class,
				AttributeStatement.DEFAULT_ELEMENT_NAME);
		attributeStatements.add(attributeStatement);

		// get encryptor if needed
		Encrypter encrypter = getEncrypter(secretKey, publicKey);

		for (Map.Entry<String, be.fedict.eid.idp.common.Attribute> attributeEntry : attributes
				.entrySet()) {

			addAttribute(attributeEntry.getValue(), attributeStatement,
					encrypter);
		}

		return assertion;
	}

	private static Encrypter getEncrypter(SecretKey secretKey,
			PublicKey publicKey) {

		if (null != publicKey) {

			return getEncrypter(getAlgorithm(secretKey), secretKey, publicKey);

		} else if (null != secretKey) {

			return getEncrypter(getAlgorithm(secretKey), secretKey);

		} else {
			return null;
		}
	}

	private static String getAlgorithm(SecretKey secretKey) {

		if (null == secretKey) {
			return null;
		}

		if (secretKey.getAlgorithm().equals("AES")) {
			return EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128;
		} else {
			throw new RuntimeException("SecretKey algorithm: "
					+ secretKey.getAlgorithm() + " not supported.");
		}

	}

	private static void addAttribute(
			be.fedict.eid.idp.common.Attribute attribute,
			AttributeStatement attributeStatement, Encrypter encrypter) {

		Attribute samlAttribute;
		switch (attribute.getAttributeType()) {

		case STRING:
			samlAttribute = getAttribute(attribute.getUri(),
					(String) attribute.getValue());
			break;
		case INTEGER:
			samlAttribute = getAttribute(attribute.getUri(),
					(Integer) attribute.getValue());
			break;
		case DATE:
			samlAttribute = getAttribute(attribute.getUri(),
					(GregorianCalendar) attribute.getValue());
			break;
		case BINARY:
			samlAttribute = getAttribute(attribute.getUri(),
					(byte[]) attribute.getValue());
			break;
		default:
			throw new RuntimeException("Attribute " + attribute.getUri()
					+ " of type \"" + attribute.getAttributeType().getType()
					+ " not supported!");
		}

		if (attribute.isEncrypted()) {

			// encrypted
			if (null == encrypter) {
				throw new RuntimeException("Encrypted attribute "
						+ "needed but no encryption info was provided.");
			}

			if (null != attribute) {
				try {
					attributeStatement.getEncryptedAttributes().add(
							encrypter.encrypt(samlAttribute));
				} catch (EncryptionException e) {
					throw new RuntimeException(e);
				}
			}

		} else {

			if (null != attribute) {
				attributeStatement.getAttributes().add(samlAttribute);
			}
		}
	}

	@SuppressWarnings("unchecked")
	private static Attribute getAttribute(String attributeName,
			String attributeValue) {

		Attribute attribute = buildXMLObject(Attribute.class,
				Attribute.DEFAULT_ELEMENT_NAME);
		attribute.setName(attributeName);

		XMLObjectBuilder<XSString> builder = Configuration.getBuilderFactory()
				.getBuilder(XSString.TYPE_NAME);
		XSString xmlAttributeValue = builder.buildObject(
				AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
		xmlAttributeValue.setValue(attributeValue);
		attribute.getAttributeValues().add(xmlAttributeValue);
		return attribute;
	}

	@SuppressWarnings("unchecked")
	private static Attribute getAttribute(String attributeName,
			Integer attributeValue) {

		Attribute attribute = buildXMLObject(Attribute.class,
				Attribute.DEFAULT_ELEMENT_NAME);
		attribute.setName(attributeName);

		XMLObjectBuilder<XSInteger> builder = Configuration.getBuilderFactory()
				.getBuilder(XSInteger.TYPE_NAME);
		XSInteger xmlAttributeValue = builder.buildObject(
				AttributeValue.DEFAULT_ELEMENT_NAME, XSInteger.TYPE_NAME);
		xmlAttributeValue.setValue(attributeValue);
		attribute.getAttributeValues().add(xmlAttributeValue);
		return attribute;
	}

	@SuppressWarnings("unchecked")
	private static Attribute getAttribute(String attributeName,
			GregorianCalendar attributeValue) {

		Attribute attribute = buildXMLObject(Attribute.class,
				Attribute.DEFAULT_ELEMENT_NAME);
		attribute.setName(attributeName);

		XMLObjectBuilder<XSDateTime> builder = Configuration
				.getBuilderFactory().getBuilder(XSDateTime.TYPE_NAME);
		XSDateTime xmlAttributeValue = builder.buildObject(
				AttributeValue.DEFAULT_ELEMENT_NAME, XSDateTime.TYPE_NAME);

		// convert to Zulu timezone
		int day = attributeValue.get(Calendar.DAY_OF_MONTH);
		int month = attributeValue.get(Calendar.MONTH);
		int year = attributeValue.get(Calendar.YEAR);
		LOG.debug("day: " + day + " month: " + month + " year: " + year);
		DateTime zulu = new DateTime(year, month + 1, day, 0, 0, 0, 0,
				ISOChronology.getInstanceUTC());
		xmlAttributeValue.setValue(zulu);
		attribute.getAttributeValues().add(xmlAttributeValue);

		LOG.debug("XmlAttributeValue: " + xmlAttributeValue.getValue());

		return attribute;
	}

	@SuppressWarnings("unchecked")
	private static Attribute getAttribute(String attributeName,
			byte[] attributeValue) {

		Attribute attribute = buildXMLObject(Attribute.class,
				Attribute.DEFAULT_ELEMENT_NAME);
		attribute.setName(attributeName);

		XMLObjectBuilder<XSBase64Binary> builder = Configuration
				.getBuilderFactory().getBuilder(XSBase64Binary.TYPE_NAME);
		XSBase64Binary xmlAttributeValue = builder.buildObject(
				AttributeValue.DEFAULT_ELEMENT_NAME, XSBase64Binary.TYPE_NAME);
		xmlAttributeValue.setValue(Base64.encodeBytes(attributeValue));
		attribute.getAttributeValues().add(xmlAttributeValue);
		return attribute;
	}

	/**
	 * Returns a SAML v2.0 XML {@link Encrypter} for symmetric keys
	 * 
	 * @param algorithm
	 *            secret key algorithm
	 * @param secretKey
	 *            the symmetric secret key
	 * @return the encrypter
	 */
	public static Encrypter getEncrypter(String algorithm, SecretKey secretKey) {

		LOG.debug("get encrypter: secret.algo=" + algorithm);

		KeyInfo keyInfo = buildXMLObject(KeyInfo.class,
				KeyInfo.DEFAULT_ELEMENT_NAME);

		BasicCredential encryptionCredential = new BasicCredential();
		encryptionCredential.setSecretKey(secretKey);

		EncryptionParameters encParams = new EncryptionParameters();
		encParams.setKeyInfoGenerator(new StaticKeyInfoGenerator(keyInfo));
		encParams.setAlgorithm(algorithm);
		encParams.setEncryptionCredential(encryptionCredential);

		List<KeyEncryptionParameters> kekParamsList = new ArrayList<KeyEncryptionParameters>();

		return new Encrypter(encParams, kekParamsList);
	}

	/**
	 * Returns a SAML v2.0 XML {@link Decrypter} for symmetric keys
	 * 
	 * @param secretKey
	 *            the symmetric secret key
	 * @return the decrypter
	 */
	public static Decrypter getDecrypter(SecretKey secretKey) {

		BasicCredential encryptionCredential = new BasicCredential();
		encryptionCredential.setSecretKey(secretKey);

		KeyInfoCredentialResolver keyResolver = new StaticKeyInfoCredentialResolver(
				encryptionCredential);

		return new Decrypter(keyResolver, null, null);
	}

	/**
	 * Returns a SAML v2.0 XML {@link Encrypter} using symmetric keys
	 * transported using an asymmetric key.
	 * <p/>
	 * The symmetric key is auto-generated AES-128 if not specified
	 * 
	 * @param algorithm
	 *            secret key algorithm
	 * @param secretKey
	 *            the symmetric secret key or <code>null</code>
	 * @param kekPublic
	 *            the Key Encrypting RSA PublicKey
	 * @return the encrypter
	 */
	public static Encrypter getEncrypter(String algorithm, SecretKey secretKey,
			PublicKey kekPublic) {

		LOG.debug("get encrypter: secret.algo=" + algorithm + " public: "
				+ kekPublic);
		BasicCredential keyEncryptionCredential = new BasicCredential();
		keyEncryptionCredential.setPublicKey(kekPublic);

		EncryptionParameters encParams = new EncryptionParameters();
		encParams.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);
		if (null != secretKey) {

			BasicCredential encryptionCredential = new BasicCredential();
			encryptionCredential.setSecretKey(secretKey);

			KeyInfo keyInfo = buildXMLObject(KeyInfo.class,
					KeyInfo.DEFAULT_ELEMENT_NAME);

			encParams.setKeyInfoGenerator(new StaticKeyInfoGenerator(keyInfo));
			encParams.setAlgorithm(algorithm);
			encParams.setEncryptionCredential(encryptionCredential);
		}

		KeyEncryptionParameters kekParams = new KeyEncryptionParameters();
		kekParams.setEncryptionCredential(keyEncryptionCredential);
		kekParams.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSA15);
		KeyInfoGeneratorFactory kigf = Configuration
				.getGlobalSecurityConfiguration().getKeyInfoGeneratorManager()
				.getDefaultManager().getFactory(keyEncryptionCredential);
		kekParams.setKeyInfoGenerator(kigf.newInstance());

		Encrypter encrypter = new Encrypter(encParams, kekParams);
		encrypter.setKeyPlacement(Encrypter.KeyPlacement.PEER);

		return encrypter;
	}

	/**
	 * Returns a SAML v2.0 XML {@link Decrypter} for symmetric keys transported
	 * using an asymmetric key.
	 * 
	 * @param privateKey
	 *            the RSA private key
	 * @return the decrypter
	 */
	public static Decrypter getDecrypter(PrivateKey privateKey) {

		BasicCredential decryptCredential = new BasicCredential();
		decryptCredential.setPrivateKey(privateKey);

		StaticKeyInfoCredentialResolver skicr = new StaticKeyInfoCredentialResolver(
				decryptCredential);

		return new Decrypter(null, skicr,
				new EncryptedElementTypeEncryptedKeyResolver());

	}

	/**
	 * Validate specified SAML v2.0 Assertion.
	 * <p/>
	 * NOTE: validation of the XML Signature is not included!
	 * 
	 * @param assertion
	 *            the assertion to validate
	 * @param now
	 *            current time, for validation of conditions
	 * @param maxTimeOffset
	 *            maximum time offset for assertion's conditions
	 * @param audience
	 *            expected audience
	 * @param recipient
	 *            recipient
	 * @param requestId
	 *            optional request ID
	 * @param secretKey
	 *            optional symmetric secret if encryption was used
	 * @param privateKey
	 *            optional asymmetric private key if encryption was used
	 * @return {@link AuthenticationResponse} DO containing all available info
	 *         on the authenticated subject.
	 * @throws AssertionValidationException
	 *             validation failed for some reason
	 */
	public static AuthenticationResponse validateAssertion(Assertion assertion,
			DateTime now, int maxTimeOffset, String audience, String recipient,
			String requestId, SecretKey secretKey, PrivateKey privateKey)
			throws AssertionValidationException {

		LOG.debug("issuer: " + assertion.getIssuer().getValue());
		List<AuthnStatement> authnStatements = assertion.getAuthnStatements();
		if (authnStatements.isEmpty()) {
			throw new AssertionValidationException(
					"missing SAML authn statement");
		}

		// validate assertion conditions
		validateConditions(now, maxTimeOffset, assertion.getConditions(),
				requestId, audience);

		// validate authn statement
		AuthnStatement authnStatement = assertion.getAuthnStatements().get(0);
		DateTime authenticationTime = authnStatement.getAuthnInstant();
		AuthnContext authnContext = authnStatement.getAuthnContext();
		if (null == authnContext) {
			throw new AssertionValidationException("missing SAML authn context");
		}
		AuthnContextClassRef authnContextClassRef = authnContext
				.getAuthnContextClassRef();
		if (null == authnContextClassRef) {
			throw new AssertionValidationException(
					"missing SAML authn context ref");
		}

		// get authentication policy
		SamlAuthenticationPolicy authenticationPolicy = SamlAuthenticationPolicy
				.getAuthenticationPolicy(authnContextClassRef
						.getAuthnContextClassRef());

		Subject subject = assertion.getSubject();
		NameID nameId = subject.getNameID();

		// validate subject confirmation
		validateSubjectConfirmation(subject, requestId, recipient, now,
				maxTimeOffset);

		String identifier = nameId.getValue();
		Map<String, Object> attributeMap = new HashMap<String, Object>();

		List<AttributeStatement> attributeStatements = assertion
				.getAttributeStatements();
		if (!attributeStatements.isEmpty()) {

			AttributeStatement attributeStatement = attributeStatements.get(0);

			// normal attributes
			List<Attribute> attributes = attributeStatement.getAttributes();
			for (Attribute attribute : attributes) {

				processAttribute(attribute, attributeMap);
			}

			// encrypted attributes
			if (!attributeStatement.getEncryptedAttributes().isEmpty()) {

				Decrypter decrypter = getDecrypter(secretKey, privateKey);

				for (EncryptedAttribute encryptedAttribute : attributeStatement
						.getEncryptedAttributes()) {

					try {
						Attribute attribute = decrypter
								.decrypt(encryptedAttribute);
						LOG.debug("decrypted attribute: " + attribute.getName());
						processAttribute(attribute, attributeMap);

					} catch (DecryptionException e) {
						throw new AssertionValidationException(e);
					}
				}
			}

		}

		return new AuthenticationResponse(authenticationTime, identifier,
				authenticationPolicy, attributeMap, assertion);
	}

	private static void validateConditions(DateTime now, int maxTimeOffset,
			Conditions conditions, String requestId, String audienceUri)
			throws AssertionValidationException {

		// time validation
		validateTime(now, conditions.getNotBefore(),
				conditions.getNotOnOrAfter(), maxTimeOffset);

		// audience restriction
		if (conditions.getAudienceRestrictions().isEmpty()
				|| conditions.getAudienceRestrictions().size() != 1) {

			throw new AssertionValidationException(
					"Expect exactly 1 audience restriction but got "
							+ "0 or more");
		}
		AudienceRestriction audienceRestriction = conditions
				.getAudienceRestrictions().get(0);
		if (audienceRestriction.getAudiences().isEmpty()
				|| audienceRestriction.getAudiences().size() != 1) {

			throw new AssertionValidationException(
					"Expect exactly 1 audience but got 0 or more");
		}

		Audience audience = audienceRestriction.getAudiences().get(0);
		if (!audience.getAudienceURI().equals(audienceUri)) {
			LOG.debug("expected audience URI: " + audienceUri);
			LOG.debug("audience URI: " + audience.getAudienceURI());
			throw new AssertionValidationException(
					"AudienceURI does not match expected recipient");
		}

		// OneTimeUse
		if (null == conditions.getOneTimeUse() && null != requestId) {

			throw new AssertionValidationException(
					"Assertion is not one-time-use.");
		}
	}

	private static void validateSubjectConfirmation(Subject subject,
			String requestId, String recipient, DateTime now, int maxTimeOffset)
			throws AssertionValidationException {

		if (subject.getSubjectConfirmations().isEmpty()
				|| subject.getSubjectConfirmations().size() != 1) {

			throw new AssertionValidationException(
					"Expected exactly 1 SubjectConfirmation but got 0 or more");
		}
		SubjectConfirmation subjectConfirmation = subject
				.getSubjectConfirmations().get(0);

		// method
		if (!subjectConfirmation.getMethod().equals(
				SubjectConfirmation.METHOD_BEARER)) {

			throw new AssertionValidationException(
					"Subjectconfirmation method: "
							+ subjectConfirmation.getMethod()
							+ " is not supported.");
		}

		if (null != requestId) {
			SubjectConfirmationData subjectConfirmationData = subjectConfirmation
					.getSubjectConfirmationData();

			// InResponseTo
			if (!subjectConfirmationData.getInResponseTo().equals(requestId)) {

				throw new AssertionValidationException(
						"SubjectConfirmationData not belonging to "
								+ "AuthnRequest!");
			}

			// recipient
			if (!subjectConfirmationData.getRecipient().equals(recipient)) {

				throw new AssertionValidationException(
						"SubjectConfirmationData recipient does not "
								+ "match expected recipient");
			}

			// time validation
			validateTime(now, subjectConfirmationData.getNotBefore(),
					subjectConfirmationData.getNotOnOrAfter(), maxTimeOffset);
		}
	}

	private static void validateTime(DateTime now, DateTime notBefore,
			DateTime notOnOrAfter, int maxTimeOffset)
			throws AssertionValidationException {

		LOG.debug("now: " + now.toString());
		LOG.debug("notBefore: " + notBefore.toString());
		LOG.debug("notOnOrAfter : " + notOnOrAfter.toString());

		if (maxTimeOffset >= 0) {
			if (now.isBefore(notBefore)) {
				// time skew
				if (now.plusMinutes(maxTimeOffset).isBefore(notBefore)
						|| now.minusMinutes(maxTimeOffset)
								.isAfter(notOnOrAfter)) {
					throw new AssertionValidationException(
							"SAML2 assertion validation: invalid SAML message timeframe");
				}
			} else if (now.isBefore(notBefore) || now.isAfter(notOnOrAfter)) {
				throw new AssertionValidationException(
						"SAML2 assertion validation: invalid SAML message timeframe");
			}
		}
	}

	private static Decrypter getDecrypter(SecretKey secretKey,
			PrivateKey privateKey) throws AssertionValidationException {

		if (null == secretKey && null == privateKey) {
			throw new AssertionValidationException(
					"Encrypted attributes were returned but "
							+ "no decryption keys were specified.");
		}

		if (null != privateKey) {
			return Saml2Util.getDecrypter(privateKey);
		}

		return Saml2Util.getDecrypter(secretKey);
	}

	private static void processAttribute(Attribute attribute,
			Map<String, Object> attributeMap)
			throws AssertionValidationException {

		String attributeName = attribute.getName();

		if (attribute.getAttributeValues().get(0) instanceof XSString) {

			XSString attributeValue = (XSString) attribute.getAttributeValues()
					.get(0);
			attributeMap.put(attributeName, attributeValue.getValue());

		} else if (attribute.getAttributeValues().get(0) instanceof XSInteger) {

			XSInteger attributeValue = (XSInteger) attribute
					.getAttributeValues().get(0);
			attributeMap.put(attributeName, attributeValue.getValue());

		} else if (attribute.getAttributeValues().get(0) instanceof XSDateTime) {

			XSDateTime attributeValue = (XSDateTime) attribute
					.getAttributeValues().get(0);
			attributeMap.put(attributeName, attributeValue.getValue()
					.toDateTime(ISOChronology.getInstanceUTC()));

		} else if (attribute.getAttributeValues().get(0) instanceof XSBase64Binary) {

			XSBase64Binary attributeValue = (XSBase64Binary) attribute
					.getAttributeValues().get(0);
			attributeMap.put(attributeName,
					Base64.decode(attributeValue.getValue()));

		} else {
			throw new AssertionValidationException("Unsupported attribute of "
					+ "type: "
					+ attribute.getAttributeValues().get(0).getClass()
							.getName());
		}
	}

	/**
	 * Construct an opensaml SAML object of specified class type and element
	 * name
	 * 
	 * @param clazz
	 *            opensaml class type
	 * @param objectQName
	 *            QName
	 * @param <T>
	 *            opensaml object type
	 * @return opensaml object.
	 */
	public static <T extends XMLObject> T buildXMLObject(Class<T> clazz,
			QName objectQName) {

		@SuppressWarnings("unchecked")
		XMLObjectBuilder<T> builder = Configuration.getBuilderFactory()
				.getBuilder(objectQName);
		if (builder == null) {
			throw new RuntimeException(
					"Unable to retrieve builder for object QName "
							+ objectQName);
		}

		return builder.buildObject(objectQName);
	}

	/**
	 * Sign specified signable SAML object and return marshalled element.
	 * 
	 * @param xmlObject
	 *            opensaml XML object where object to be signed resides in, this
	 *            can be equal to the object to sign
	 * @param signableSAMLObject
	 *            opensaml object to sign
	 * @param privateKeyEntry
	 *            key entry used to sign
	 * @return marshalled, signed xml element.
	 */
	public static Element signAsElement(XMLObject xmlObject,
			SignableSAMLObject signableSAMLObject,
			KeyStore.PrivateKeyEntry privateKeyEntry) {

		XMLObject returnedXmlObject = sign(xmlObject, signableSAMLObject,
				privateKeyEntry);

		return marshall(returnedXmlObject);
	}

	/**
	 * Sign specified opensaml signable object with specifiied key entry.
	 * 
	 * @param signableSAMLObject
	 *            saml object to sign
	 * @param privateKeyEntry
	 *            key entry to sign with
	 * @return signed saml object
	 */
	public static XMLObject sign(SignableSAMLObject signableSAMLObject,
			KeyStore.PrivateKeyEntry privateKeyEntry) {

		return sign(signableSAMLObject, signableSAMLObject, privateKeyEntry);

	}

	private static XMLObject sign(XMLObject xmlObject,
			SignableSAMLObject signableSAMLObject,
			KeyStore.PrivateKeyEntry privateKeyEntry) {
		XMLObjectBuilderFactory builderFactory = Configuration
				.getBuilderFactory();
		SignatureBuilder signatureBuilder = (SignatureBuilder) builderFactory
				.getBuilder(Signature.DEFAULT_ELEMENT_NAME);
		Signature signature = signatureBuilder.buildObject();
		signature
				.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

		String algorithm = privateKeyEntry.getPrivateKey().getAlgorithm();
		if ("RSA".equals(algorithm)) {
			signature
					.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA);
		} else if ("DSA".equals(algorithm)) {
			signature
					.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_DSA);
		}

		List<X509Certificate> certificateChain = new LinkedList<X509Certificate>();
		for (java.security.cert.Certificate certificate : privateKeyEntry
				.getCertificateChain()) {
			certificateChain.add((X509Certificate) certificate);
		}

		// add certificate chain as keyinfo
		KeyInfo keyInfo = buildXMLObject(KeyInfo.class,
				KeyInfo.DEFAULT_ELEMENT_NAME);
		try {
			for (X509Certificate certificate : certificateChain) {
				KeyInfoHelper.addCertificate(keyInfo, certificate);
			}
		} catch (CertificateEncodingException e) {
			throw new RuntimeException("opensaml2 certificate encoding error: "
					+ e.getMessage(), e);
		}
		signature.setKeyInfo(keyInfo);

		BasicX509Credential signingCredential = new BasicX509Credential();
		signingCredential.setPrivateKey(privateKeyEntry.getPrivateKey());
		signingCredential.setEntityCertificateChain(certificateChain);

		// enable adding the cert.chain as KeyInfo
		X509KeyInfoGeneratorFactory factory = (X509KeyInfoGeneratorFactory) org.opensaml.xml.Configuration
				.getGlobalSecurityConfiguration().getKeyInfoGeneratorManager()
				.getDefaultManager().getFactory(signingCredential);
		factory.setEmitEntityCertificateChain(true);

		signature.setSigningCredential(signingCredential);
		signableSAMLObject.setSignature(signature);

		// Marshall so it has an XML representation.
		marshall(xmlObject);

		// Sign after marshaling so we can add a signature to the XML
		// representation.
		try {
			Signer.signObject(signature);
		} catch (SignatureException e) {
			throw new RuntimeException("opensaml2 signing error: "
					+ e.getMessage(), e);
		}
		return xmlObject;
	}

	/**
	 * Validate the specified opensaml XML Signature
	 * 
	 * @param signature
	 *            the XML signature
	 * @return list of {@link X509Certificate}'s in the XML signature
	 * @throws CertificateException
	 *             something went wrong extracting the certificates from the XML
	 *             Signature.
	 * @throws ValidationException
	 *             validation failed
	 */
	public static List<X509Certificate> validateSignature(Signature signature)
			throws CertificateException, ValidationException {

		List<X509Certificate> certChain = KeyInfoHelper
				.getCertificates(signature.getKeyInfo());

		SAMLSignatureProfileValidator pv = new SAMLSignatureProfileValidator();
		pv.validate(signature);
		BasicX509Credential credential = new BasicX509Credential();
		credential.setPublicKey(getEndCertificate(certChain).getPublicKey());
		SignatureValidator sigValidator = new SignatureValidator(credential);
		sigValidator.validate(signature);

		return certChain;
	}

	/**
	 * Get end {@link X509Certificate} from specified chain.
	 * 
	 * @param certChain
	 *            the {@link X509Certificate} chain.
	 * @return the end {@link X509Certificate}.
	 */
	public static X509Certificate getEndCertificate(
			List<X509Certificate> certChain) {

		if (certChain.size() == 1) {
			return certChain.get(0);
		}

		if (isSelfSigned(certChain.get(0))) {
			return certChain.get(certChain.size() - 1);
		} else {
			return certChain.get(0);
		}

	}

	private static boolean isSelfSigned(X509Certificate certificate) {

		return certificate.getIssuerX500Principal().equals(
				certificate.getSubjectX500Principal());
	}

	/**
	 * Marhsall the opensaml {@link XMLObject} to a DOM {@link Element}
	 * 
	 * @param xmlObject
	 *            the XML object
	 * @return marshalled DOM element
	 */
	public static Element marshall(XMLObject xmlObject) {

		MarshallerFactory marshallerFactory = Configuration
				.getMarshallerFactory();
		Marshaller marshaller = marshallerFactory.getMarshaller(xmlObject);

		try {
			return marshaller.marshall(xmlObject);
		} catch (MarshallingException e) {
			throw new RuntimeException("opensaml2 marshalling error: "
					+ e.getMessage(), e);
		}
	}

	/**
	 * Write the DOM {@link Document} to specified {@link OutputStream}
	 * 
	 * @param document
	 *            DOM document
	 * @param documentOutputStream
	 *            output stream
	 * @throws TransformerFactoryConfigurationError
	 *             transformer config error
	 * @throws TransformerException
	 *             transformer error
	 * @throws IOException
	 *             IO error
	 */
	public static void writeDocument(Document document,
			OutputStream documentOutputStream)
			throws TransformerFactoryConfigurationError, TransformerException,
			IOException {
		Result result = new StreamResult(documentOutputStream);
		Transformer xformer = TransformerFactory.newInstance().newTransformer();
		Source source = new DOMSource(document);
		xformer.transform(source, result);
	}

	/**
	 * Parses the given string to a DOM object.
	 * 
	 * @param documentString
	 *            the DOM as string
	 * @return the DOM
	 */
	public static Document parseDocument(String documentString) {

		try {
			DocumentBuilderFactory domFactory = DocumentBuilderFactory
					.newInstance();
			domFactory.setNamespaceAware(true);
			DocumentBuilder domBuilder = domFactory.newDocumentBuilder();
			StringReader stringReader = new StringReader(documentString);
			InputSource inputSource = new InputSource(stringReader);
			return domBuilder.parse(inputSource);
		} catch (IOException e) {
			throw new RuntimeException(e);
		} catch (SAXException e) {
			throw new RuntimeException(e);
		} catch (ParserConfigurationException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Convert specified DOM {@link Node} to a string representation
	 * 
	 * @param domNode
	 *            the DOM node
	 * @param indent
	 *            indent or not
	 * @return the string representation of the DOM node
	 */
	public static String domToString(Node domNode, boolean indent) {

		try {
			Source source = new DOMSource(domNode);
			StringWriter stringWriter = new StringWriter();
			Result result = new StreamResult(stringWriter);

			TransformerFactory transformerFactory = TransformerFactory
					.newInstance();
			Transformer transformer = transformerFactory.newTransformer();

			transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION,
					"yes");
			transformer.setOutputProperty(
					"{http://xml.apache.org/xslt}indent-amount", "4");
			transformer.setOutputProperty(OutputKeys.INDENT, indent ? "yes"
					: "no");
			transformer.transform(source, result);

			return stringWriter.toString();
		} catch (TransformerException e) {
			throw new RuntimeException(e);
		}
	}

	/**
	 * Convert specified opensaml {@link XMLObject} to specified JAXB type.
	 * 
	 * @param openSAMLObject
	 *            the opensaml XML object.
	 * @param wsType
	 *            the JAXB class
	 * @param <T>
	 *            the JAXB type
	 * @return JAXB representation of the opensaml xml object.
	 */
	@SuppressWarnings("unchecked")
	public static <T> T toJAXB(final XMLObject openSAMLObject, Class<T> wsType) {

		try {
			Element element = Configuration.getMarshallerFactory()
					.getMarshaller(openSAMLObject).marshall(openSAMLObject);

			return ((JAXBElement<T>) JAXBContext.newInstance(wsType)
					.createUnmarshaller().unmarshal(element)).getValue();
		} catch (MarshallingException e) {
			throw new RuntimeException(
					"Marshaling from OpenSAML object failed.", e);
		} catch (JAXBException e) {
			throw new RuntimeException("Unmarshaling to JAXB object failed.", e);
		}
	}

	/**
	 * Convert specified JAXB object to an opensaml XML object
	 * 
	 * @param wsObject
	 *            JAXB object
	 * @param wsType
	 *            JAXB class
	 * @param samlElementName
	 *            opensaml QName
	 * @param <F>
	 *            JAXB type
	 * @param <T>
	 *            opensaml type
	 * @return opensaml {@link XMLObject}
	 */
	@SuppressWarnings({ "unchecked" })
	public static <F, T extends XMLObject> T toSAML(final F wsObject,
			Class<F> wsType, QName samlElementName) {

		try {
			Document root = DocumentBuilderFactory.newInstance()
					.newDocumentBuilder().newDocument();
			JAXBContext
					.newInstance(wsType)
					.createMarshaller()
					.marshal(
							new JAXBElement<F>(samlElementName, wsType,
									wsObject), root);

			return (T) unmarshall(root.getDocumentElement());
		} catch (ParserConfigurationException e) {
			throw new RuntimeException("Default parser "
					+ "configuration failed.", e);
		} catch (JAXBException e) {
			throw new RuntimeException("Marshaling to OpenSAML "
					+ "object failed.", e);
		}
	}

	/**
	 * Unmarshall specified DOM {@link Element} to an opensaml {@link XMLObject}
	 * 
	 * @param xmlElement
	 *            DOM element
	 * @param <X>
	 *            opensaml type
	 * @return the opensaml object.
	 */
	@SuppressWarnings({ "unchecked" })
	public static <X extends XMLObject> X unmarshall(Element xmlElement) {

		UnmarshallerFactory unmarshallerFactory = Configuration
				.getUnmarshallerFactory();
		Unmarshaller unmarshaller = unmarshallerFactory
				.getUnmarshaller(xmlElement);

		try {
			return (X) unmarshaller.unmarshall(xmlElement);
		} catch (UnmarshallingException e) {
			throw new RuntimeException("opensaml2 unmarshalling " + "error: "
					+ e.getMessage(), e);
		}
	}

	/**
	 * Find {@link Node} specified with XPath expression in {@link Document}
	 * 
	 * @param document
	 *            document to search
	 * @param xpath
	 *            XPath to to be found Node
	 * @return Node or <code>null</code> if not found.
	 */
	public static Node find(Document document, String xpath) {

		try {
			return XPathAPI.selectSingleNode(document, xpath,
					getNSElement(document));
		} catch (TransformerException e) {
			throw new RuntimeException("XPath error: " + e.getMessage());
		}
	}

	private static Element getNSElement(Document document) {

		Element nsElement = document.createElement("nsElement");
		nsElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:soap",
				"http://schemas.xmlsoap.org/soap/envelope/");
		nsElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:ds",
				"http://www.w3.org/2000/09/xmldsig#");
		nsElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:samlp",
				"urn:oasis:names:tc:SAML:2.0:protocol");
		nsElement.setAttributeNS(Constants.NamespaceSpecNS, "xmlns:saml",
				"urn:oasis:names:tc:SAML:2.0:assertion");

		return nsElement;
	}

	/**
	 * Sign DOM document
	 * 
	 * @param documentElement
	 *            document to be signed
	 * @param nextSibling
	 *            next sibling in document, dsig is added before this one
	 * @param identity
	 *            Identity to sign with
	 * @throws NoSuchAlgorithmException
	 *             signing algorithm not found
	 * @throws InvalidAlgorithmParameterException
	 *             invalid signing algo param
	 * @throws MarshalException
	 *             error marshalling signature
	 * @throws XMLSignatureException
	 *             error during signing
	 */
	public static void signDocument(Element documentElement, Node nextSibling,
			KeyStore.PrivateKeyEntry identity) throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, MarshalException,
			XMLSignatureException {

		// get document ID
		String documentId = documentElement.getAttribute("ID");
		LOG.debug("document ID=" + documentId);

		// fix for recent versions of Apache xmlsec.
		documentElement.setIdAttribute("ID", true);

		XMLSignatureFactory signatureFactory = XMLSignatureFactory
				.getInstance("DOM");

		XMLSignContext signContext = new DOMSignContext(
				identity.getPrivateKey(), documentElement, nextSibling);
		signContext.putNamespacePrefix(
				javax.xml.crypto.dsig.XMLSignature.XMLNS, "ds");
		javax.xml.crypto.dsig.DigestMethod digestMethod = signatureFactory
				.newDigestMethod(javax.xml.crypto.dsig.DigestMethod.SHA1, null);

		List<javax.xml.crypto.dsig.Transform> transforms = new LinkedList<javax.xml.crypto.dsig.Transform>();
		transforms.add(signatureFactory.newTransform(
				javax.xml.crypto.dsig.Transform.ENVELOPED,
				(TransformParameterSpec) null));
		javax.xml.crypto.dsig.Transform exclusiveTransform = signatureFactory
				.newTransform(CanonicalizationMethod.EXCLUSIVE,
						(TransformParameterSpec) null);
		transforms.add(exclusiveTransform);

		Reference reference = signatureFactory.newReference("#" + documentId,
				digestMethod, transforms, null, null);

		SignatureMethod signatureMethod = signatureFactory.newSignatureMethod(
				SignatureMethod.RSA_SHA1, null);
		CanonicalizationMethod canonicalizationMethod = signatureFactory
				.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE,
						(C14NMethodParameterSpec) null);
		SignedInfo signedInfo = signatureFactory.newSignedInfo(
				canonicalizationMethod, signatureMethod,
				Collections.singletonList(reference));

		List<Object> keyInfoContent = new LinkedList<Object>();
		KeyInfoFactory keyInfoFactory = KeyInfoFactory.getInstance();
		List<Object> x509DataObjects = new LinkedList<Object>();

		for (X509Certificate certificate : Saml2Util
				.getCertificateChain(identity)) {
			x509DataObjects.add(certificate);
		}
		javax.xml.crypto.dsig.keyinfo.X509Data x509Data = keyInfoFactory
				.newX509Data(x509DataObjects);
		keyInfoContent.add(x509Data);
		javax.xml.crypto.dsig.keyinfo.KeyInfo keyInfo = keyInfoFactory
				.newKeyInfo(keyInfoContent);

		javax.xml.crypto.dsig.XMLSignature xmlSignature = signatureFactory
				.newXMLSignature(signedInfo, keyInfo);
		xmlSignature.sign(signContext);
	}

}

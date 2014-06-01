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

package be.fedict.eid.idp.protocol.ws_federation;

import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.UUID;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.JAXBException;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactoryConfigurationError;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.ws.wsaddressing.Address;
import org.opensaml.ws.wsaddressing.EndpointReference;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.XMLObjectBuilder;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.w3c.dom.Element;

import be.fedict.eid.idp.common.saml2.Saml2Util;
import be.fedict.eid.idp.protocol.ws_federation.wsfed.ClaimType;
import be.fedict.eid.idp.protocol.ws_federation.wsfed.ClaimTypeBuilder;
import be.fedict.eid.idp.protocol.ws_federation.wsfed.ClaimTypeMarshaller;
import be.fedict.eid.idp.protocol.ws_federation.wsfed.ClaimTypeUnmarshaller;
import be.fedict.eid.idp.protocol.ws_federation.wsfed.ClaimTypesOffered;
import be.fedict.eid.idp.protocol.ws_federation.wsfed.ClaimTypesOfferedBuilder;
import be.fedict.eid.idp.protocol.ws_federation.wsfed.ClaimTypesOfferedMarshaller;
import be.fedict.eid.idp.protocol.ws_federation.wsfed.ClaimTypesOfferedUnmarshaller;
import be.fedict.eid.idp.protocol.ws_federation.wsfed.Description;
import be.fedict.eid.idp.protocol.ws_federation.wsfed.DescriptionBuilder;
import be.fedict.eid.idp.protocol.ws_federation.wsfed.DescriptionMarshaller;
import be.fedict.eid.idp.protocol.ws_federation.wsfed.DescriptionUnmarshaller;
import be.fedict.eid.idp.protocol.ws_federation.wsfed.DisplayName;
import be.fedict.eid.idp.protocol.ws_federation.wsfed.DisplayNameBuilder;
import be.fedict.eid.idp.protocol.ws_federation.wsfed.DisplayNameMarshaller;
import be.fedict.eid.idp.protocol.ws_federation.wsfed.DisplayNameUnmarshaller;
import be.fedict.eid.idp.protocol.ws_federation.wsfed.PassiveRequestorEndpoint;
import be.fedict.eid.idp.protocol.ws_federation.wsfed.PassiveRequestorEndpointBuilder;
import be.fedict.eid.idp.protocol.ws_federation.wsfed.PassiveRequestorEndpointMarshaller;
import be.fedict.eid.idp.protocol.ws_federation.wsfed.PassiveRequestorEndpointUnmarshaller;
import be.fedict.eid.idp.protocol.ws_federation.wsfed.SecurityTokenService;
import be.fedict.eid.idp.protocol.ws_federation.wsfed.SecurityTokenServiceBuilder;
import be.fedict.eid.idp.protocol.ws_federation.wsfed.SecurityTokenServiceMarshaller;
import be.fedict.eid.idp.protocol.ws_federation.wsfed.SecurityTokenServiceUnmarshaller;
import be.fedict.eid.idp.spi.AttributeConfig;
import be.fedict.eid.idp.spi.IdPIdentity;
import be.fedict.eid.idp.spi.IdentityProviderConfiguration;
import be.fedict.eid.idp.spi.IdentityProviderConfigurationFactory;
import be.fedict.eid.idp.spi.IdentityProviderProtocolService;

public abstract class AbstractWSFederationMetadataHttpServlet extends
		HttpServlet {

	private static final long serialVersionUID = 1L;

	private static final Log LOG = LogFactory
			.getLog(AbstractWSFederationMetadataHttpServlet.class);

	static {
		/*
		 * Next is because Sun loves to endorse crippled versions of Xerces.
		 */
		System.setProperty(
				"javax.xml.validation.SchemaFactory:http://www.w3.org/2001/XMLSchema",
				"org.apache.xerces.jaxp.validation.XMLSchemaFactory");
		try {
			DefaultBootstrap.bootstrap();

			// register WS-Federation Metadata elements
			Configuration.registerObjectProvider(
					ClaimType.DEFAULT_ELEMENT_NAME, new ClaimTypeBuilder(),
					new ClaimTypeMarshaller(), new ClaimTypeUnmarshaller());

			Configuration.registerObjectProvider(
					ClaimTypesOffered.DEFAULT_ELEMENT_NAME,
					new ClaimTypesOfferedBuilder(),
					new ClaimTypesOfferedMarshaller(),
					new ClaimTypesOfferedUnmarshaller());

			Configuration.registerObjectProvider(
					Description.DEFAULT_ELEMENT_NAME, new DescriptionBuilder(),
					new DescriptionMarshaller(), new DescriptionUnmarshaller());

			Configuration.registerObjectProvider(
					DisplayName.DEFAULT_ELEMENT_NAME, new DisplayNameBuilder(),
					new DisplayNameMarshaller(), new DisplayNameUnmarshaller());

			Configuration.registerObjectProvider(
					PassiveRequestorEndpoint.DEFAULT_ELEMENT_NAME,
					new PassiveRequestorEndpointBuilder(),
					new PassiveRequestorEndpointMarshaller(),
					new PassiveRequestorEndpointUnmarshaller());

			Configuration.registerObjectProvider(
					SecurityTokenService.DEFAULT_ELEMENT_NAME,
					new SecurityTokenServiceBuilder(),
					new SecurityTokenServiceMarshaller(),
					new SecurityTokenServiceUnmarshaller());

			Configuration.registerObjectProvider(
					SecurityTokenService.TYPE_NAME,
					new SecurityTokenServiceBuilder(),
					new SecurityTokenServiceMarshaller(),
					new SecurityTokenServiceUnmarshaller());

		} catch (ConfigurationException e) {
			throw new RuntimeException(
					"could not bootstrap the OpenSAML2 library", e);
		}
	}

	@Override
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		LOG.debug("doGet");
		response.setContentType("application/samlmetadata+xml");

		IdentityProviderConfiguration configuration = IdentityProviderConfigurationFactory
				.getInstance(request);

		OutputStream outputStream = response.getOutputStream();
		try {
			writeMetadata(request, configuration, outputStream);
		} catch (Exception e) {
			throw new ServletException("error: " + e.getMessage(), e);
		}
	}

	private void writeMetadata(HttpServletRequest request,
			IdentityProviderConfiguration configuration,
			OutputStream outputStream) throws JAXBException, ServletException,
			ParserConfigurationException, CertificateEncodingException,
			TransformerFactoryConfigurationError, TransformerException,
			IOException, NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, MarshalException,
			XMLSignatureException {

		String location = getLocation(request);

		EntityDescriptor entityDescriptor = Saml2Util.buildXMLObject(
				EntityDescriptor.class, EntityDescriptor.DEFAULT_ELEMENT_NAME);
		entityDescriptor.setEntityID(location);
		entityDescriptor.setID("saml-metadata-" + UUID.randomUUID().toString());

		@SuppressWarnings("unchecked")
		XMLObjectBuilder<SecurityTokenService> builder = Configuration
				.getBuilderFactory().getBuilder(SecurityTokenService.TYPE_NAME);
		SecurityTokenService securityTokenService = builder.buildObject(
				RoleDescriptor.DEFAULT_ELEMENT_NAME,
				SecurityTokenService.TYPE_NAME);
		entityDescriptor.getRoleDescriptors().add(securityTokenService);

		securityTokenService
				.addSupportedProtocol("http://docs.oasis-open.org/wsfed/federation/200706");

		PassiveRequestorEndpoint passiveRequestorEndpoint = Saml2Util
				.buildXMLObject(PassiveRequestorEndpoint.class,
						PassiveRequestorEndpoint.DEFAULT_ELEMENT_NAME);
		securityTokenService.getPassiveRequestorEndpoints().add(
				passiveRequestorEndpoint);

		EndpointReference endpoint = Saml2Util.buildXMLObject(
				EndpointReference.class, EndpointReference.ELEMENT_NAME);
		passiveRequestorEndpoint.setEndpointReference(endpoint);

		Address address = Saml2Util.buildXMLObject(Address.class,
				Address.ELEMENT_NAME);
		endpoint.setAddress(address);
		address.setValue(location);

		IdPIdentity identity = configuration.findIdentity();
		try {
			if (null != identity) {

				KeyDescriptor keyDescriptor = Saml2Util
						.buildXMLObject(KeyDescriptor.class,
								KeyDescriptor.DEFAULT_ELEMENT_NAME);
				securityTokenService.getKeyDescriptors().add(keyDescriptor);
				keyDescriptor.setUse(UsageType.SIGNING);

				org.opensaml.xml.signature.KeyInfo keyInfo = Saml2Util
						.buildXMLObject(
								org.opensaml.xml.signature.KeyInfo.class,
								org.opensaml.xml.signature.KeyInfo.DEFAULT_ELEMENT_NAME);
				keyDescriptor.setKeyInfo(keyInfo);

				KeyInfoHelper.addCertificate(keyInfo,
						(X509Certificate) identity.getPrivateKeyEntry()
								.getCertificate());
			}
		} catch (CertificateEncodingException e) {
			throw new RuntimeException("opensaml2 certificate encoding error: "
					+ e.getMessage(), e);
		}

		// claims
		ClaimTypesOffered claimTypesOffered = Saml2Util
				.buildXMLObject(ClaimTypesOffered.class,
						ClaimTypesOffered.DEFAULT_ELEMENT_NAME);
		securityTokenService.setClaimTypesOffered(claimTypesOffered);

		List<ClaimType> claimTypes = claimTypesOffered.getClaimTypes();

		for (AttributeConfig attribute : configuration
				.getAttributes(AbstractWSFederationProtocolService.WS_FED_PROTOCOL_ID)) {
			addClaimType(attribute.getUri(), attribute.getName(),
					attribute.getDescription(), claimTypes);
		}

		Element element;
		if (null != identity) {

			LOG.debug("sign WS-Federation Metadata");
			element = Saml2Util.signAsElement(entityDescriptor,
					entityDescriptor, identity.getPrivateKeyEntry());
		} else {

			LOG.warn("WS-Federation Metadata NOT signed!");
			element = Saml2Util.marshall(entityDescriptor);
		}

		Saml2Util.writeDocument(element.getOwnerDocument(), outputStream);
	}

	private void addClaimType(String claimUri, String displayName,
			String description, List<ClaimType> claimTypes) {

		ClaimType claim = Saml2Util.buildXMLObject(ClaimType.class,
				ClaimType.DEFAULT_ELEMENT_NAME);
		claimTypes.add(claim);
		claim.setUri(claimUri);
		claim.setOptional(true);

		DisplayName claimDisplayName = Saml2Util.buildXMLObject(
				DisplayName.class, DisplayName.DEFAULT_ELEMENT_NAME);
		claimDisplayName.setValue(displayName);
		claim.setDisplayName(claimDisplayName);

		Description claimDescription = Saml2Util.buildXMLObject(
				Description.class, Description.DEFAULT_ELEMENT_NAME);
		claimDescription.setValue(description);
		claim.setDescription(claimDescription);
	}

	private String getLocation(HttpServletRequest request) {

		String location = "https://" + request.getServerName();
		if (request.getServerPort() != 443) {
			location += ":" + request.getServerPort();
		}
		location += request.getContextPath()
				+ IdentityProviderProtocolService.PROTOCOL_ENDPOINT_PATH + "/"
				+ getPath();
		LOG.debug("location: " + location);
		return location;
	}

	protected abstract String getPath();
}

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

package be.fedict.eid.idp.protocol.saml2;

import java.io.IOException;
import java.io.OutputStream;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.transform.TransformerException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.xml.ConfigurationException;
import org.w3c.dom.Element;

import be.fedict.eid.idp.common.saml2.Saml2Util;
import be.fedict.eid.idp.spi.IdPIdentity;
import be.fedict.eid.idp.spi.IdentityProviderConfiguration;
import be.fedict.eid.idp.spi.IdentityProviderConfigurationFactory;
import be.fedict.eid.idp.spi.IdentityProviderProtocolService;

public abstract class AbstractSAML2MetadataHttpServlet extends HttpServlet {

	private static final long serialVersionUID = 3945029803660891205L;

	private static final Log LOG = LogFactory
			.getLog(AbstractSAML2MetadataHttpServlet.class);

	static {
		/*
		 * Next is because Sun loves to endorse crippled versions of Xerces.
		 */
		System.setProperty(
				"javax.xml.validation.SchemaFactory:http://www.w3.org/2001/XMLSchema",
				"org.apache.xerces.jaxp.validation.XMLSchemaFactory");
		try {
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			throw new RuntimeException(
					"could not bootstrap the OpenSAML2 library", e);
		}
	}

	@Override
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		LOG.debug("doGet");
		response.setContentType("application/samlmetadata+xml; charset=UTF-8");

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
			OutputStream outputStream)

	throws ServletException, TransformerException, IOException {

		IdPIdentity identity = configuration.findIdentity();

		// Add a descriptor for our node (the SAMLv2 Entity).
		EntityDescriptor entityDescriptor = getEntityDescriptor(request,
				configuration);

		// Marshall & sign the entity descriptor.
		Element element;
		if (null != identity) {

			LOG.debug("sign SAML2 Metadata");
			element = Saml2Util.signAsElement(entityDescriptor,
					entityDescriptor, identity.getPrivateKeyEntry());
		} else {

			LOG.warn("SAML2 Metadata NOT signed!");
			element = Saml2Util.marshall(entityDescriptor);
		}

		Saml2Util.writeDocument(element.getOwnerDocument(), outputStream);
	}

	public EntityDescriptor getEntityDescriptor(HttpServletRequest request,
			IdentityProviderConfiguration configuration) {

		String location = getLocation(request);

		IdPIdentity identity = configuration.findIdentity();

		return Saml2Util.getEntityDescriptor(
				AbstractSAML2ProtocolService.getResponseIssuer(configuration),
				location, getBinding(),
				null != identity ? identity.getPrivateKeyEntry() : null);
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

	protected abstract String getBinding();
}

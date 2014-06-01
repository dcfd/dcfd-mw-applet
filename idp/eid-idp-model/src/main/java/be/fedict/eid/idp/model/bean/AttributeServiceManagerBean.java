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

package be.fedict.eid.idp.model.bean;

import java.io.IOException;
import java.net.URL;
import java.util.Enumeration;
import java.util.LinkedList;
import java.util.List;

import javax.ejb.Stateless;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.idp.model.AttributeServiceManager;
import be.fedict.eid.idp.spi.IdentityProviderAttributeService;
import be.fedict.eid.idp.spi.attribute.IdentityProviderAttributeType;
import be.fedict.eid.idp.spi.attribute.IdentityProviderAttributesType;
import be.fedict.eid.idp.spi.attribute.ObjectFactory;

@Stateless
public class AttributeServiceManagerBean implements AttributeServiceManager {

	private static final Log LOG = LogFactory
			.getLog(AttributeServiceManagerBean.class);

	@SuppressWarnings("unchecked")
	public List<IdentityProviderAttributeType> getAttributeServiceTypes() {

		List<IdentityProviderAttributeType> attributeServices = new LinkedList<IdentityProviderAttributeType>();
		ClassLoader classLoader = Thread.currentThread()
				.getContextClassLoader();
		Enumeration<URL> resources;
		try {
			resources = classLoader
					.getResources("META-INF/eid-idp-attribute.xml");
		} catch (IOException e) {
			LOG.error("I/O error: " + e.getMessage(), e);
			return attributeServices;
		}
		Unmarshaller unmarshaller;
		try {
			JAXBContext jaxbContext = JAXBContext
					.newInstance(ObjectFactory.class);
			unmarshaller = jaxbContext.createUnmarshaller();
		} catch (JAXBException e) {
			LOG.error("JAXB error: " + e.getMessage(), e);
			return attributeServices;
		}
		while (resources.hasMoreElements()) {
			URL resource = resources.nextElement();
			LOG.debug("resource URL: " + resource.toString());
			JAXBElement<IdentityProviderAttributesType> jaxbElement;
			try {
				jaxbElement = (JAXBElement<IdentityProviderAttributesType>) unmarshaller
						.unmarshal(resource);
			} catch (JAXBException e) {
				LOG.error("JAXB error: " + e.getMessage(), e);
				continue;
			}
			IdentityProviderAttributesType identityProviderAttributes = jaxbElement
					.getValue();
			for (IdentityProviderAttributeType identityProviderAttribute : identityProviderAttributes
					.getIdentityProviderAttribute()) {
				attributeServices.add(identityProviderAttribute);
			}
		}
		return attributeServices;
	}

	@Override
	public List<IdentityProviderAttributeService> getAttributeServices() {

		List<IdentityProviderAttributeService> attributeServices = new LinkedList<IdentityProviderAttributeService>();

		for (IdentityProviderAttributeType attributeServiceType : getAttributeServiceTypes()) {
			attributeServices.add(getAttributeService(attributeServiceType));
		}

		return attributeServices;
	}

	public IdentityProviderAttributeService getAttributeService(
			IdentityProviderAttributeType identityProviderAttribute) {

		ClassLoader classLoader = Thread.currentThread()
				.getContextClassLoader();
		LOG.debug("loading attribute service class: "
				+ identityProviderAttribute.getAttributeService());
		Class<?> attributeServiceClass;
		try {
			attributeServiceClass = classLoader
					.loadClass(identityProviderAttribute.getAttributeService());
		} catch (ClassNotFoundException e) {
			LOG.error("attribute service class not found: "
					+ identityProviderAttribute.getAttributeService(), e);
			return null;
		}
		if (!IdentityProviderAttributeService.class
				.isAssignableFrom(attributeServiceClass)) {
			LOG.error("illegal attribute service class: "
					+ identityProviderAttribute.getAttributeService());
			return null;
		}
		IdentityProviderAttributeService attributeService;
		try {
			attributeService = (IdentityProviderAttributeService) attributeServiceClass
					.newInstance();
		} catch (Exception e) {
			LOG.error(
					"could not init the attribute service object: "
							+ e.getMessage(), e);
			return null;
		}
		return attributeService;
	}
}

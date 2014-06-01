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

import be.fedict.eid.idp.model.ProtocolServiceManager;
import be.fedict.eid.idp.spi.IdentityProviderProtocolService;
import be.fedict.eid.idp.spi.protocol.IdentityProviderProtocolType;
import be.fedict.eid.idp.spi.protocol.IdentityProviderProtocolsType;
import be.fedict.eid.idp.spi.protocol.ObjectFactory;

@Stateless
public class ProtocolServiceManagerBean implements ProtocolServiceManager {

	private static final Log LOG = LogFactory
			.getLog(ProtocolServiceManagerBean.class);

	public IdentityProviderProtocolService findProtocolService(
			String contextPath) {
		LOG.debug("find protocol service for context path: " + contextPath);
		if (null == contextPath) {
			/*
			 * Can happen if we browse directly to ./eid-idp/protocol
			 */
			return null;
		}
		List<IdentityProviderProtocolType> protocolServices = getProtocolServices();
		for (IdentityProviderProtocolType protocol : protocolServices) {
			if (contextPath.equals(protocol.getContextPath())) {
				return getProtocolService(protocol);
			}
		}
		LOG.warn("no protocol service found for context path: " + contextPath);
		return null;
	}

	@SuppressWarnings("unchecked")
	public List<IdentityProviderProtocolType> getProtocolServices() {
		List<IdentityProviderProtocolType> protocolServices = new LinkedList<IdentityProviderProtocolType>();
		ClassLoader classLoader = Thread.currentThread()
				.getContextClassLoader();
		Enumeration<URL> resources;
		try {
			resources = classLoader
					.getResources("META-INF/eid-idp-protocol.xml");
		} catch (IOException e) {
			LOG.error("I/O error: " + e.getMessage(), e);
			return protocolServices;
		}
		Unmarshaller unmarshaller;
		try {
			JAXBContext jaxbContext = JAXBContext
					.newInstance(ObjectFactory.class);
			unmarshaller = jaxbContext.createUnmarshaller();
		} catch (JAXBException e) {
			LOG.error("JAXB error: " + e.getMessage(), e);
			return protocolServices;
		}
		while (resources.hasMoreElements()) {
			URL resource = resources.nextElement();
			LOG.debug("resource URL: " + resource.toString());
			JAXBElement<IdentityProviderProtocolsType> jaxbElement;
			try {
				jaxbElement = (JAXBElement<IdentityProviderProtocolsType>) unmarshaller
						.unmarshal(resource);
			} catch (JAXBException e) {
				LOG.error("JAXB error: " + e.getMessage(), e);
				continue;
			}
			IdentityProviderProtocolsType identityProviderProtocols = jaxbElement
					.getValue();
			for (IdentityProviderProtocolType identityProviderProtocol : identityProviderProtocols
					.getIdentityProviderProtocol()) {
				protocolServices.add(identityProviderProtocol);
			}
		}
		return protocolServices;
	}

	public IdentityProviderProtocolService getProtocolService(
			IdentityProviderProtocolType identityProviderProtocol) {
		ClassLoader classLoader = Thread.currentThread()
				.getContextClassLoader();
		LOG.debug("loading protocol service class: "
				+ identityProviderProtocol.getProtocolService());
		Class<?> protocolServiceClass;
		try {
			protocolServiceClass = classLoader
					.loadClass(identityProviderProtocol.getProtocolService());
		} catch (ClassNotFoundException e) {
			LOG.error("protocol service class not found: "
					+ identityProviderProtocol.getProtocolService(), e);
			return null;
		}
		if (!IdentityProviderProtocolService.class
				.isAssignableFrom(protocolServiceClass)) {
			LOG.error("illegal protocol service class: "
					+ identityProviderProtocol.getProtocolService());
			return null;
		}
		IdentityProviderProtocolService protocolService;
		try {
			protocolService = (IdentityProviderProtocolService) protocolServiceClass
					.newInstance();
		} catch (Exception e) {
			LOG.error(
					"could not init the protocol service object: "
							+ e.getMessage(), e);
			return null;
		}
		return protocolService;
	}
}

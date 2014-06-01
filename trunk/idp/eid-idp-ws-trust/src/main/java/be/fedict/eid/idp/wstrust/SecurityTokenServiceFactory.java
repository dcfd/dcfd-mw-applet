/*
 * eID Identity Provider Project.
 * Copyright (C) 2010-2012 FedICT.
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

package be.fedict.eid.idp.wstrust;

import java.net.URL;

import javax.xml.namespace.QName;

import be.fedict.eid.idp.wstrust.jaxws.SecurityTokenService;

public class SecurityTokenServiceFactory {

	public static final String WSDL_RESOURCE = "/ws-trust-1.3.wsdl";

	private SecurityTokenServiceFactory() {
		super();
	}

	public static SecurityTokenService getInstance() {
		URL wsdlLocation = SecurityTokenServiceFactory.class
				.getResource(WSDL_RESOURCE);
		if (null == wsdlLocation) {
			throw new RuntimeException("WSDL location not valid: "
					+ WSDL_RESOURCE);
		}
		QName serviceName = new QName(
				"http://docs.oasis-open.org/ws-sx/ws-trust/200512",
				"SecurityTokenService");
		return new SecurityTokenService(wsdlLocation, serviceName);
	}
}

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

package be.fedict.eid.idp.protocol.ws_federation.wsfed;

import javax.xml.namespace.QName;

import org.opensaml.ws.wstrust.WSTrustObject;
import org.opensaml.xml.schema.XSURI;

public interface Description extends XSURI, WSTrustObject {

	/**
	 * Element local name.
	 */
	public static final String DEFAULT_ELEMENT_LOCAL_NAME = "Description";

	/**
	 * Default element name.
	 */
	public static final QName DEFAULT_ELEMENT_NAME = new QName(
			WSFedConstants.WSFED_AUTH_NS, DEFAULT_ELEMENT_LOCAL_NAME,
			WSFedConstants.WSFED_AUTH_PREFIX);

	/**
	 * Local name of the XSI type.
	 */
	public static final String TYPE_LOCAL_NAME = "DescriptionType";

	/**
	 * QName of the XSI type.
	 */
	public static final QName TYPE_NAME = new QName(
			WSFedConstants.WSFED_AUTH_NS, TYPE_LOCAL_NAME,
			WSFedConstants.WSFED_AUTH_PREFIX);
}

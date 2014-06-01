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

import org.opensaml.common.impl.AbstractSAMLObjectMarshaller;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.MarshallingException;
import org.w3c.dom.Element;

public class ClaimTypeMarshaller extends AbstractSAMLObjectMarshaller {

	/**
	 * {@inheritDoc}
	 */
	protected void marshallAttributes(XMLObject samlObject, Element domElement)
			throws MarshallingException {

		ClaimType claimType = (ClaimType) samlObject;

		if (claimType.isOptionalXSBoolean() != null) {
			domElement.setAttributeNS(null, ClaimType.OPTIONAL_ATTRIB_NAME,
					claimType.isOptionalXSBoolean().toString());
		}

		if (claimType.getUri() != null) {
			domElement.setAttributeNS(null, ClaimType.URI_ATTRIB_NAME,
					claimType.getUri());
		}

		super.marshallAttributes(samlObject, domElement);
	}
}

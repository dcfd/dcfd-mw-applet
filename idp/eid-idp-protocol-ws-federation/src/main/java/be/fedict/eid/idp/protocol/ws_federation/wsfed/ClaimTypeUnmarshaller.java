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

import org.opensaml.common.impl.AbstractSAMLObjectUnmarshaller;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.schema.XSBooleanValue;
import org.w3c.dom.Attr;

public class ClaimTypeUnmarshaller extends AbstractSAMLObjectUnmarshaller {

	/**
	 * {@inheritDoc}
	 */
	protected void processAttribute(XMLObject samlObject, Attr attribute)
			throws UnmarshallingException {

		ClaimType claimType = (ClaimType) samlObject;

		if (attribute.getLocalName().equals(ClaimType.OPTIONAL_ATTRIB_NAME)) {
			claimType.setOptional(XSBooleanValue.valueOf(attribute.getValue()));
		} else if (attribute.getLocalName().equals(ClaimType.URI_ATTRIB_NAME)) {
			claimType.setUri(attribute.getValue());
		} else {
			super.processAttribute(samlObject, attribute);
		}
	}

	/**
	 * {@inheritDoc}
	 */
	protected void processChildElement(XMLObject parentSAMLObject,
			XMLObject childSAMLObject) throws UnmarshallingException {

		ClaimType claimType = (ClaimType) parentSAMLObject;

		if (childSAMLObject instanceof DisplayName) {
			claimType.setDisplayName((DisplayName) childSAMLObject);
		} else if (childSAMLObject instanceof Description) {
			claimType.setDescription((Description) childSAMLObject);
		} else {
			super.processChildElement(parentSAMLObject, childSAMLObject);
		}
	}
}

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

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.opensaml.common.impl.AbstractSAMLObject;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.util.IndexedXMLObjectChildrenList;

public class ClaimTypesOfferedImpl extends AbstractSAMLObject implements
		ClaimTypesOffered {

	private final IndexedXMLObjectChildrenList<ClaimType> claimTypes;

	/**
	 * Constructor.
	 * 
	 * @param namespaceURI
	 *            the namespace the element is in
	 * @param elementLocalName
	 *            the local name of the XML element this Object represents
	 * @param namespacePrefix
	 *            the prefix for the given namespace
	 */
	public ClaimTypesOfferedImpl(String namespaceURI, String elementLocalName,
			String namespacePrefix) {
		super(namespaceURI, elementLocalName, namespacePrefix);
		this.claimTypes = new IndexedXMLObjectChildrenList<ClaimType>(this);
	}

	public List<ClaimType> getClaimTypes() {
		return this.claimTypes;
	}

	public List<XMLObject> getOrderedChildren() {
		ArrayList<XMLObject> children = new ArrayList<XMLObject>();

		children.addAll(this.claimTypes);

		return Collections.unmodifiableList(children);
	}
}

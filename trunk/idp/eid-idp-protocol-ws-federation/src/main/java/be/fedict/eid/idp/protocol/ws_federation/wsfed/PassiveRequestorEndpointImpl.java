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

import org.opensaml.saml2.metadata.impl.EndpointImpl;
import org.opensaml.ws.wsaddressing.EndpointReference;
import org.opensaml.xml.XMLObject;

public class PassiveRequestorEndpointImpl extends EndpointImpl implements
		PassiveRequestorEndpoint {

	private EndpointReference endpointReference;

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
	public PassiveRequestorEndpointImpl(String namespaceURI,
			String elementLocalName, String namespacePrefix) {
		super(namespaceURI, elementLocalName, namespacePrefix);
	}

	public EndpointReference getEndpointReference() {
		return this.endpointReference;
	}

	public void setEndpointReference(EndpointReference endpointReference) {
		this.endpointReference = prepareForAssignment(this.endpointReference,
				endpointReference);
	}

	public List<XMLObject> getOrderedChildren() {
		ArrayList<XMLObject> children = new ArrayList<XMLObject>();

		if (super.getOrderedChildren() != null) {
			children.addAll(super.getOrderedChildren());
		}

		if (this.endpointReference != null) {
			children.add(this.endpointReference);
		}

		if (children.size() == 0) {
			return null;
		}

		return Collections.unmodifiableList(children);
	}
}

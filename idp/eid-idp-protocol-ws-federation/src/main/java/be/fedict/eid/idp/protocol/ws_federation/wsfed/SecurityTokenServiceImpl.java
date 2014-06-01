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

import javax.xml.namespace.QName;

import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.impl.RoleDescriptorImpl;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.util.XMLObjectChildrenList;

public class SecurityTokenServiceImpl extends RoleDescriptorImpl implements
		SecurityTokenService {

	private ClaimTypesOffered claimTypesOffered;
	private final XMLObjectChildrenList<PassiveRequestorEndpoint> passiveRequestorEndpoints;

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
	public SecurityTokenServiceImpl(String namespaceURI,
			String elementLocalName, String namespacePrefix) {
		super(namespaceURI, elementLocalName, namespacePrefix);
		this.passiveRequestorEndpoints = new XMLObjectChildrenList<PassiveRequestorEndpoint>(
				this);
	}

	public List<PassiveRequestorEndpoint> getPassiveRequestorEndpoints() {
		return this.passiveRequestorEndpoints;
	}

	public ClaimTypesOffered getClaimTypesOffered() {
		return this.claimTypesOffered;
	}

	public void setClaimTypesOffered(ClaimTypesOffered claimTypesOffered) {
		this.claimTypesOffered = prepareForAssignment(this.claimTypesOffered,
				claimTypesOffered);
	}

	public List<Endpoint> getEndpoints() {

		List<Endpoint> endpoints = new ArrayList<Endpoint>();
		endpoints.addAll(passiveRequestorEndpoints);
		return Collections.unmodifiableList(endpoints);
	}

	public List<Endpoint> getEndpoints(QName type) {

		if (type.equals(PassiveRequestorEndpoint.DEFAULT_ELEMENT_NAME)) {
			return Collections.unmodifiableList(new ArrayList<Endpoint>(
					this.passiveRequestorEndpoints));
		}

		return null;
	}

	public List<XMLObject> getOrderedChildren() {
		ArrayList<XMLObject> children = new ArrayList<XMLObject>();

		if (super.getOrderedChildren() != null) {
			children.addAll(super.getOrderedChildren());
		}

		if (this.claimTypesOffered != null) {
			children.add(this.claimTypesOffered);
		}

		children.addAll(this.passiveRequestorEndpoints);

		if (children.size() == 0) {
			return null;
		}

		return Collections.unmodifiableList(children);
	}

}

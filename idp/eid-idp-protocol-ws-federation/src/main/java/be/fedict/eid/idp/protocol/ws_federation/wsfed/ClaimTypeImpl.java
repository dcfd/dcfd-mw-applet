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
import org.opensaml.xml.schema.XSBooleanValue;

public class ClaimTypeImpl extends AbstractSAMLObject implements ClaimType {

	private DisplayName displayName;
	private Description description;
	private String uri;
	private XSBooleanValue optional;

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
	public ClaimTypeImpl(String namespaceURI, String elementLocalName,
			String namespacePrefix) {
		super(namespaceURI, elementLocalName, namespacePrefix);
	}

	public DisplayName getDisplayName() {
		return this.displayName;
	}

	public void setDisplayName(DisplayName displayName) {
		this.displayName = prepareForAssignment(this.displayName, displayName);
	}

	public Description getDescription() {
		return this.description;
	}

	public void setDescription(Description description) {
		this.description = prepareForAssignment(this.description, description);
	}

	public String getUri() {
		return this.uri;
	}

	public void setUri(String uri) {
		this.uri = prepareForAssignment(this.uri, uri);
	}

	public Boolean isOptional() {
		if (this.optional != null) {
			return optional.getValue();
		}

		return Boolean.FALSE;
	}

	public XSBooleanValue isOptionalXSBoolean() {
		return this.optional;
	}

	public void setOptional(Boolean optional) {
		if (optional != null) {
			this.optional = prepareForAssignment(this.optional,
					new XSBooleanValue(optional, false));
		} else {
			this.optional = prepareForAssignment(this.optional, null);
		}
	}

	public void setOptional(XSBooleanValue optional) {
		this.optional = prepareForAssignment(this.optional, optional);
	}

	public List<XMLObject> getOrderedChildren() {
		ArrayList<XMLObject> children = new ArrayList<XMLObject>();

		if (this.displayName != null) {
			children.add(this.displayName);
		}

		if (this.description != null) {
			children.add(this.description);
		}

		if (children.size() == 0) {
			return null;
		}

		return Collections.unmodifiableList(children);
	}
}

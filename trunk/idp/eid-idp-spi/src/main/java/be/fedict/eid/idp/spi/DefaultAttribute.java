/*
 * eID Digital Signature Service Project.
 * Copyright (C) 2010 FedICT.
 * Copyright (C) 2014 e-Contract.be BVBA.
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

package be.fedict.eid.idp.spi;

import be.fedict.eid.idp.common.AttributeType;

/**
 * Enumeration of all default eID Attributes.
 * 
 * @author Wim Vandenhaute
 * @author Frank Cornelis
 */
public enum DefaultAttribute {

	LAST_NAME("LastName", "Surname or family name of a Subject.",
			"be:fedict:eid:idp:lastname", AttributeType.STRING),

	FIRST_NAME("FirstName", "Preferred name or first name of a Subject.",
			"be:fedict:eid:idp:firstname", AttributeType.STRING),

	NAME("Name", "The name of the Subject.", "be:fedict:eid:idp:name",
			AttributeType.STRING),

	IDENTIFIER(
			"PPID",
			"A private personal identifier (PPID) that identifies the Subject to a Relying Party.",
			"be:fedict:eid:idp:identifier", AttributeType.STRING),

	ADDRESS("StreetAddress",
			"Street address component of a Subject's address information.",
			"be:fedict:eid:idp:address", AttributeType.STRING),

	LOCALITY(
			"Locality",
			"This attribute contains the name of a locality, such as a city, county or other geographic region.",
			"be:fedict:eid:idp:locality", AttributeType.STRING),

	POSTAL_CODE(
			"PostalCode",
			"The postal code attribute type specifies the postal code of the named object.",
			"be:fedict:eid:idp:postalcode", AttributeType.STRING),

	GENDER(
			"Gender",
			"Gender of a Subject that can have any of these exact string values � '0' (meaning unspecified), '1' (meaning Male) or '2' (meaning Female). Using these values allows them to be language neutral.",
			"be:fedict:eid:idp:gender", AttributeType.STRING),

	DATE_OF_BIRTH(
			"DateOfBirth",
			"The date of birth of a Subject in a form allowed by the xs:date data type.",
			"be:fedict:eid:idp:dob", AttributeType.DATE),

	NATIONALITY("Nationality", "The nationality of the named object.",
			"be:fedict:eid:idp:nationality", AttributeType.STRING),

	PLACE_OF_BIRTH("PlaceOfBirth", "The place of birth of the named object.",
			"be:fedict:eid:idp:pob", AttributeType.STRING),

	PHOTO("Photo", "Base64 encoded photo of the named object.",
			"be:fedict:eid:idp:photo", AttributeType.BINARY),

	CARD_NUMBER("CardNumber", "The eID card number.",
			"be:fedict:eid:idp:card-number", AttributeType.STRING),

	CARD_VALIDITY_BEGIN("CardValidityBegin", "The card validity begin.",
			"be:fedict:eid:idp:card-validity:begin", AttributeType.DATE),

	CARD_VALIDITY_END("CardValidityEnd", "The card validity end.",
			"be:fedict:eid:idp:card-validity:end", AttributeType.DATE),

	AUTHN_CERT("AuthenticationCertificate",
			"The eID authentication certificate.",
			"be:fedict:eid:idp:cert:authn", AttributeType.BINARY);

	private final String name;
	private final String description;
	private final String uri;
	private final AttributeType attributeType;

	private DefaultAttribute(String name, String description, String uri,
			AttributeType attributeType) {
		this.name = name;
		this.description = description;
		this.uri = uri;
		this.attributeType = attributeType;
	}

	public String getName() {
		return name;
	}

	public String getDescription() {
		return description;
	}

	public String getUri() {
		return this.uri;
	}

	public AttributeType getAttributeType() {
		return this.attributeType;
	}

	public static DefaultAttribute findDefaultAttribute(String uri) {

		for (DefaultAttribute defaultAttribute : values()) {
			if (defaultAttribute.getUri().equals(uri)) {
				return defaultAttribute;
			}
		}
		return null;
	}
}

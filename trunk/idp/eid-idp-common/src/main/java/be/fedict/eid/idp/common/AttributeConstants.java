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

package be.fedict.eid.idp.common;

/**
 * eID Default Attribute Constants. Used in a SAML2 assertion context.
 * <p/>
 * 
 * @author Wim Vandenhaute
 * @see <a href="http://docs.oasis-open.org/imi/identity/v1.0/identity.html">
 *      OASIS Identity Metasystem Interoperability Version 1.0</a>
 */
public abstract class AttributeConstants {

	// default attributes
	public static final String NAME_CLAIM_TYPE_URI = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";
	public static final String FIRST_NAME_CLAIM_TYPE_URI = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname";
	public static final String LAST_NAME_CLAIM_TYPE_URI = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname";

	// address attributes
	public static final String STREET_ADDRESS_CLAIM_TYPE_URI = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/streetaddress";
	public static final String LOCALITY_CLAIM_TYPE_URI = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/locality";
	public static final String POSTAL_CODE_CLAIM_TYPE_URI = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/postalcode";

	// identity attributes
	public static final String DATE_OF_BIRTH_CLAIM_TYPE_URI = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/dateofbirth";
	public static final String GENDER_CLAIM_TYPE_URI = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/gender";
	public static final String NATIONALITY_CLAIM_TYPE_URI = "be:fedict:eid:idp:nationality";
	public static final String PLACE_OF_BIRTH_CLAIM_TYPE_URI = "be:fedict:eid:idp:pob";

	// photo attribute
	public static final String PHOTO_CLAIM_TYPE_URI = "be:fedict:eid:idp:photo";

	// custom attributes
	public static final String COUNTRY_CLAIM_TYPE_URI = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/country";
	public static final String PPID_CLAIM_TYPE_URI = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/privatepersonalidentifier";

	// card attributes
	public static final String CARD_NUMBER_TYPE_URI = "be:fedict:eid:idp:card-number";
	public static final String CARD_VALIDITY_BEGIN_TYPE_URI = "be:fedict:eid:idp:card-validity:begin";
	public static final String CARD_VALIDITY_END_TYPE_URI = "be:fedict:eid:idp:card-validity:end";
}

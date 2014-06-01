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

package be.fedict.eid.idp.common.saml2;

import java.io.Serializable;
import java.util.Map;

import org.apache.commons.codec.binary.Base64;
import org.joda.time.DateTime;
import org.opensaml.saml2.core.Assertion;

import be.fedict.eid.idp.common.SamlAuthenticationPolicy;

/**
 * SAML2 Authentication Response DO containing all available information of the
 * authenticated subject.
 * 
 * @author Wim Vandenhaute
 */
public class AuthenticationResponse implements Serializable {

	private static final long serialVersionUID = 1L;

	private final DateTime authenticationTime;
	private final String identifier;
	private final SamlAuthenticationPolicy authenticationPolicy;
	private final Map<String, Object> attributeMap;

	private String relayState;

	private final String encodedAssertion;

	public AuthenticationResponse(DateTime authenticationTime,
			String identifier, SamlAuthenticationPolicy authenticationPolicy,
			Map<String, Object> attributeMap, Assertion assertion) {
		this.authenticationTime = authenticationTime;
		this.identifier = identifier;
		this.authenticationPolicy = authenticationPolicy;
		this.attributeMap = attributeMap;

		// marshall and encode assertion so it is serializble
		this.encodedAssertion = Base64.encodeBase64String(Saml2Util
				.domToString(Saml2Util.marshall(assertion), false).getBytes());
	}

	/**
	 * @return the identifier of the authenticated subject
	 */
	public String getIdentifier() {
		return identifier;
	}

	/**
	 * @return Map of available eID attribute of the authenticated subject
	 */
	public Map<String, Object> getAttributeMap() {
		return attributeMap;
	}

	/**
	 * @return optional RelayState passed along during authentication
	 */
	public String getRelayState() {
		return relayState;
	}

	public void setRelayState(String relayState) {
		this.relayState = relayState;
	}

	/**
	 * @return time of authentication
	 */
	public DateTime getAuthenticationTime() {
		return authenticationTime;
	}

	/**
	 * @return used SAML Authentication Policy
	 */
	public SamlAuthenticationPolicy getAuthenticationPolicy() {
		return authenticationPolicy;
	}

	/**
	 * @return the SAML v2.0 Assertion.
	 */
	public Assertion getAssertion() {
		return Saml2Util.unmarshall(Saml2Util.parseDocument(
				new String(Base64.decodeBase64(this.encodedAssertion)))
				.getDocumentElement());
	}

	/**
	 * @return the Base64 encoded marshalled assertion. ( serializable)
	 */
	public String getEncodedAssertion() {
		return encodedAssertion;
	}
}

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
 * Enumeration of the SAML v2.0 Authentication Policies.
 * 
 * @author Wim Vandenhaute
 */
public enum SamlAuthenticationPolicy {

	IDENTIFICATION("urn:be:fedict:eid:idp:Identification"), AUTHENTICATION(
			"urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI"), AUTHENTICATION_WITH_IDENTIFICATION(
			"urn:be:fedict:eid:idp:AuthenticationWithIdentification");

	private final String uri;

	SamlAuthenticationPolicy(String uri) {
		this.uri = uri;
	}

	public String getUri() {
		return this.uri;
	}

	public static SamlAuthenticationPolicy getAuthenticationPolicy(String uri) {

		for (SamlAuthenticationPolicy authenticationPolicy : SamlAuthenticationPolicy
				.values()) {
			if (authenticationPolicy.getUri().equals(uri)) {
				return authenticationPolicy;
			}
		}

		throw new RuntimeException("Unknown authentication policy: " + uri);
	}
}

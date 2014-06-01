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

package be.fedict.eid.idp.sp.protocol.openid;

import java.io.Serializable;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * OpenID Authentication Response DO.
 * <p/>
 * Contains the time of authentication, returned OpenID Identifier, list of
 * policies used and a Map containing all available attributes for the
 * authenticated subject.
 * 
 * @author Wim Vandenhaute
 */
public class OpenIDAuthenticationResponse implements Serializable {

	private static final long serialVersionUID = 1L;

	private final Date authenticationTime;
	private final String identifier;
	private final List<String> authenticationPolicies;
	private final Map<String, Object> attributeMap;

	public OpenIDAuthenticationResponse(Date authenticationTime,
			String identifier, List<String> authenticationPolicies,
			Map<String, Object> attributeMap) {
		this.authenticationTime = authenticationTime;
		this.identifier = identifier;
		this.authenticationPolicies = authenticationPolicies;
		this.attributeMap = attributeMap;
	}

	/**
	 * @return time of authentication
	 */
	public Date getAuthenticationTime() {
		return authenticationTime;
	}

	/**
	 * @return OpenID identifier for the authenticated subject
	 */
	public String getIdentifier() {
		return identifier;
	}

	/**
	 * @return map of available eID attributes for the authenticated subject.
	 */
	public Map<String, Object> getAttributeMap() {
		return attributeMap;
	}

	/**
	 * @return list of used authentication policies.
	 */
	public List<String> getAuthenticationPolicies() {
		return authenticationPolicies;
	}
}

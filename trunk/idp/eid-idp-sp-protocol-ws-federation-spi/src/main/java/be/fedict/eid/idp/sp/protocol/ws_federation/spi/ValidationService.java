/*
 * eID Identity Provider Project.
 * Copyright (C) 2011-2012 FedICT.
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

package be.fedict.eid.idp.sp.protocol.ws_federation.spi;

/**
 * Interface for validation service information.
 * 
 * @author Frank Cornelis
 * 
 */
public interface ValidationService {

	/**
	 * Gives back the location of the eID IdP STS validation service.
	 * 
	 * @return
	 */
	String getLocation();

	/**
	 * Gives back the expected SAML Audience restriction value.
	 * 
	 * @return <code>null</code> is not to be checked. This is not recommended.
	 */
	String getExpectedAudience();
}

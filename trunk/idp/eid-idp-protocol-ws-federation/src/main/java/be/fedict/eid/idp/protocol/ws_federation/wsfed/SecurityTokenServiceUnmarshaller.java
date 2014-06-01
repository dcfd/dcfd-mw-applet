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

import org.opensaml.saml2.metadata.impl.RoleDescriptorUnmarshaller;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.UnmarshallingException;

public class SecurityTokenServiceUnmarshaller extends
		RoleDescriptorUnmarshaller {

	/**
	 * {@inheritDoc}
	 */
	protected void processChildElement(XMLObject parentSAMLObject,
			XMLObject childSAMLObject) throws UnmarshallingException {

		SecurityTokenService securityTokenService = (SecurityTokenService) parentSAMLObject;

		if (childSAMLObject instanceof PassiveRequestorEndpoint) {
			securityTokenService.getPassiveRequestorEndpoints().add(
					(PassiveRequestorEndpoint) childSAMLObject);
		} else if (childSAMLObject instanceof ClaimTypesOffered) {
			securityTokenService
					.setClaimTypesOffered((ClaimTypesOffered) childSAMLObject);
		} else {
			super.processChildElement(parentSAMLObject, childSAMLObject);
		}
	}
}

/*
 * eID Identity Provider Project.
 * Copyright (C) 2011 FedICT.
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

import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.crypto.SecretKey;

import be.fedict.eid.idp.common.SamlAuthenticationPolicy;

/**
 * WS-Federation SPI for authentication response services.
 * 
 * @author Wim Vandenhaute.
 * @author Frank Cornelis
 */
public interface AuthenticationResponseService {

	/**
	 * Callback to the SAML v2.0 SDK whether the SP expects a response to be
	 * signed or not
	 * 
	 * @return true if expect a signed response.
	 */
	boolean requiresResponseSignature();

	/**
	 * Validation of the certificate chain in the SAML v2.0 assertion signature.
	 * 
	 * @param authenticationPolicy
	 *            SAML v2.0 authentication policy.
	 * @param certificateChain
	 *            the service certificate chain
	 * @throws SecurityException
	 *             in case the certificate is invalid/not accepted
	 */
	void validateServiceCertificate(
			SamlAuthenticationPolicy authenticationPolicy,
			List<X509Certificate> certificateChain) throws SecurityException;

	/**
	 * @return the maximum offset allowed on the SAML v2.0 assertion condition
	 *         fields. Specified in minutes. A negative value results in
	 *         skipping validation of the condition's time fields.
	 */
	int getMaximumTimeOffset();

	/**
	 * @return the optional symmetric {@link javax.crypto.SecretKey} used to
	 *         decrypt attributes if configured so. Return <code>null</code> if
	 *         not applicable.
	 */
	SecretKey getAttributeSecretKey();

	/**
	 * @return the optional asymmetric {@link java.security.PrivateKey} used to
	 *         decrypt attributes if configured so. Return <code>null</code> if
	 *         not applicable.
	 */
	PrivateKey getAttributePrivateKey();

	/**
	 * @return the information of the WS-Trust STS validation service. Return
	 *         <code>null</code> if not applicable.
	 */
	ValidationService getValidationService();
}

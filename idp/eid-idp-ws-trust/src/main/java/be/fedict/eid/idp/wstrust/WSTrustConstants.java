/*
 * eID Identity Provider Project.
 * Copyright (C) 2012 FedICT.
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

package be.fedict.eid.idp.wstrust;

import javax.xml.namespace.QName;

/**
 * WS-Trust constants.
 * 
 * @author Frank Cornelis
 * 
 */
public class WSTrustConstants {

	public static final String WS_TRUST_NAMESPACE = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";

	public static final String WS_POLICY_NAMESPACE = "http://schemas.xmlsoap.org/ws/2004/09/policy";

	public static final String WS_ADDR_NAMESPACE = "http://www.w3.org/2005/08/addressing";

	public static final String XMLDSIG_NAMESPACE = "http://www.w3.org/2000/09/xmldsig#";

	public static final String WS_SECURITY_NAMESPACE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";

	public static final String WS_SECURITY_11_NAMESPACE = "http://docs.oasis-open.org/wss/oasis-wss-wssecurity-secext-1.1.xsd";

	public static final String SAML2_NAMESPACE = "urn:oasis:names:tc:SAML:2.0:assertion";

	public static final String SAML2_WSSE11_TOKEN_TYPE = "http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV2.0";

	public static final QName ENDPOINT_REFERENCE_QNAME = new QName(
			WS_ADDR_NAMESPACE, "EndpointReference");

	public static final QName APPLIES_TO_QNAME = new QName(WS_POLICY_NAMESPACE,
			"AppliesTo");

	public static final QName TOKEN_TYPE_QNAME = new QName(WS_TRUST_NAMESPACE,
			"TokenType");

	public static final String STATUS_TOKEN_TYPE = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RSTR/Status";

	public static final String VALIDATE_REQUEST_TYPE = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Validate";

	public static final QName REQUEST_TYPE_QNAME = new QName(
			WS_TRUST_NAMESPACE, "RequestType");

	public static final QName VALIDATE_TARGET_QNAME = new QName(
			WS_TRUST_NAMESPACE, "ValidateTarget");

	public static final String VALID_STATUS_CODE = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/status/valid";

	public static final String INVALID_STATUS_CODE = "http://docs.oasis-open.org/ws-sx/ws-trust/200512/status/invalid";

	private WSTrustConstants() {
		super();
	}
}

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

package be.fedict.eid.idp.sp;

import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Map;

import javax.servlet.http.HttpSession;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.xml.validation.ValidationException;

import be.fedict.eid.idp.common.AttributeConstants;
import be.fedict.eid.idp.common.OpenIDAXConstants;
import be.fedict.eid.idp.common.saml2.AuthenticationResponse;
import be.fedict.eid.idp.common.saml2.Saml2Util;
import be.fedict.eid.idp.sp.protocol.openid.OpenIDAuthenticationResponse;

public class ResponseBean {

	private static final Log LOG = LogFactory.getLog(ResponseBean.class);

	private HttpSession session;
	private String identifier;
	private Map<String, Object> attributeMap;
	private String policy;

	public HttpSession getSession() {
		return this.session;
	}

	public void setSession(HttpSession session) {

		this.session = session;

		if (null != session.getAttribute("Response")) {

			Object responseObject = session.getAttribute("Response");
			if (responseObject instanceof AuthenticationResponse) {
				// saml2 (or WS-Federation...)
				AuthenticationResponse response = (AuthenticationResponse) responseObject;
				this.identifier = response.getIdentifier();
				this.attributeMap = response.getAttributeMap();
				this.policy = response.getAuthenticationPolicy().getUri();

				// validate assertion
				if (null != response.getAssertion().getSignature()) {
					try {
						Saml2Util.validateSignature(response.getAssertion()
								.getSignature());
					} catch (CertificateException e) {
						LOG.error(e);
					} catch (ValidationException e) {
						LOG.error(e);
					}
					LOG.debug("Valid assertion");
				}

			} else {
				// openid
				OpenIDAuthenticationResponse response = (OpenIDAuthenticationResponse) responseObject;
				this.identifier = response.getIdentifier();
				this.attributeMap = response.getAttributeMap();
				this.policy = Arrays.toString(response
						.getAuthenticationPolicies().toArray());
			}

			for (Map.Entry<String, Object> entry : this.attributeMap.entrySet()) {
				LOG.debug("attribute: " + entry.getKey() + " value="
						+ entry.getValue());
			}

			// get photo
			if (this.attributeMap
					.containsKey(AttributeConstants.PHOTO_CLAIM_TYPE_URI)) {
				byte[] photoData = (byte[]) this.attributeMap
						.get(AttributeConstants.PHOTO_CLAIM_TYPE_URI);
				this.session.setAttribute(PhotoServlet.PHOTO_SESSION_ATTRIBUTE,
						photoData);
			} else if (this.attributeMap
					.containsKey(OpenIDAXConstants.AX_PHOTO_TYPE)) {
				String encodedPhotoData = (String) this.attributeMap
						.get(OpenIDAXConstants.AX_PHOTO_TYPE);
				byte[] photoData = Base64.decodeBase64(encodedPhotoData);
				this.session.setAttribute(PhotoServlet.PHOTO_SESSION_ATTRIBUTE,
						photoData);
			} else {
				this.session
						.removeAttribute(PhotoServlet.PHOTO_SESSION_ATTRIBUTE);
			}
		}
		cleanupSession();

	}

	public Map getAttributeMap() {

		return this.attributeMap;
	}

	public void setAttributeMap(Map value) {
		// empty
	}

	public String getIdentifier() {
		return this.identifier;
	}

	public void setIdentifier(String identifier) {
		// empty
	}

	private void cleanupSession() {
		this.session.removeAttribute("Identifier");
		this.session.removeAttribute("AttributeMap");
		this.session.removeAttribute("Response");
	}

	public String getPolicy() {
		return this.policy;
	}

	public void setPolicy(String policy) {
		// empty
	}
}

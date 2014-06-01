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

package be.fedict.eid.idp.sp.protocol.saml2.post;

import java.security.cert.CertificateException;

import javax.servlet.http.HttpServletRequest;

import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.saml2.binding.decoding.HTTPPostDecoder;
import org.opensaml.saml2.core.Response;
import org.opensaml.ws.message.decoder.MessageDecodingException;
import org.opensaml.ws.transport.http.HttpServletRequestAdapter;
import org.opensaml.xml.validation.ValidationException;

import be.fedict.eid.idp.common.saml2.Saml2Util;
import be.fedict.eid.idp.sp.protocol.saml2.AbstractAuthenticationResponseProcessor;
import be.fedict.eid.idp.sp.protocol.saml2.AuthenticationResponseProcessorException;
import be.fedict.eid.idp.sp.protocol.saml2.spi.AuthenticationResponseService;

/**
 * SAML v2.0 Authentication response processor for the Browser HTTP POST
 * binding.
 * 
 * @author Wim Vandenhaute
 */
public class AuthenticationResponseProcessor extends
		AbstractAuthenticationResponseProcessor {

	private final AuthenticationResponseService service;

	/**
	 * Main Constructor
	 * 
	 * @param service
	 *            optional {@link AuthenticationResponseService} for validation
	 *            of certificate chain in returned SAML v2.0 Response.
	 */
	public AuthenticationResponseProcessor(AuthenticationResponseService service) {

		this.service = service;
	}

	/**
	 * Parses the SAML v2.0 Authentication Response out of the HTTP Servlet
	 * Request and validates any signatures on it.
	 * 
	 * @param request
	 *            HTTP Servlet Request
	 * @return the SAML v2.0 Authentication Response
	 * @throws AuthenticationResponseProcessorException
	 *             something went wrong getting or validating the SAML v2.0
	 *             Authentication Response.
	 */
	@Override
	protected Response getSamlResponse(HttpServletRequest request)
			throws AuthenticationResponseProcessorException {

		BasicSAMLMessageContext<SAMLObject, SAMLObject, SAMLObject> messageContext = new BasicSAMLMessageContext<SAMLObject, SAMLObject, SAMLObject>();
		messageContext
				.setInboundMessageTransport(new HttpServletRequestAdapter(
						request));

		SAMLMessageDecoder decoder = new HTTPPostDecoder();
		try {
			decoder.decode(messageContext);
		} catch (MessageDecodingException e) {
			throw new AuthenticationResponseProcessorException(
					"OpenSAML message decoding error", e);
		} catch (org.opensaml.xml.security.SecurityException e) {
			throw new AuthenticationResponseProcessorException(
					"OpenSAML security error: " + e.getMessage(), e);
		}

		SAMLObject samlObject = messageContext.getInboundSAMLMessage();
		LOG.debug("SAML object class: " + samlObject.getClass().getName());
		if (!(samlObject instanceof Response)) {
			throw new AuthenticationResponseProcessorException(
					"expected a SAML2 Response document");
		}
		Response response = (Response) samlObject;

		try {
			// validate response signature if any
			if (null != response.getSignature()) {
				Saml2Util.validateSignature(response.getSignature());
			}

			// validate assertion signature if any
			if (!response.getAssertions().isEmpty()
					&& null != response.getAssertions().get(0).getSignature()) {
				Saml2Util.validateSignature(response.getAssertions().get(0)
						.getSignature());
			}

		} catch (ValidationException e) {
			throw new AuthenticationResponseProcessorException(e);
		} catch (CertificateException e) {
			throw new AuthenticationResponseProcessorException(e);
		}

		return response;
	}

	/**
	 * @return the optional {@link AuthenticationResponseService}
	 */
	@Override
	protected AuthenticationResponseService getAuthenticationResponseService() {

		return this.service;
	}
}

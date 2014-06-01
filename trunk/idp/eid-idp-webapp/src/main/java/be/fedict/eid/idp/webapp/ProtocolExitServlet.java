/*
 * eID Identity Provider Project.
 * Copyright (C) 2010 FedICT.
 * Copyright (C) 2014 e-Contract.be BVBA.
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

package be.fedict.eid.idp.webapp;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.ejb.EJB;
import javax.security.auth.x500.X500Principal;
import javax.servlet.ServletConfig;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.applet.service.Address;
import be.fedict.eid.applet.service.Identity;
import be.fedict.eid.applet.service.impl.handler.AuthenticationDataMessageHandler;
import be.fedict.eid.applet.service.impl.handler.IdentityDataMessageHandler;
import be.fedict.eid.idp.common.Attribute;
import be.fedict.eid.idp.entity.RPAttributeEntity;
import be.fedict.eid.idp.entity.RPEntity;
import be.fedict.eid.idp.model.AttributeService;
import be.fedict.eid.idp.model.AttributeServiceManager;
import be.fedict.eid.idp.model.Constants;
import be.fedict.eid.idp.model.CryptoUtil;
import be.fedict.eid.idp.model.IdentityService;
import be.fedict.eid.idp.model.Statistics;
import be.fedict.eid.idp.spi.DefaultAttribute;
import be.fedict.eid.idp.spi.IdentityProviderAttributeService;
import be.fedict.eid.idp.spi.IdentityProviderProtocolService;
import be.fedict.eid.idp.spi.IdpUtil;
import be.fedict.eid.idp.spi.ReturnResponse;

/**
 * Protocol Exit Servlet. Operates as a broker towards protocol services.
 * 
 * @author Frank Cornelis
 */
public class ProtocolExitServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;

	private static final Log LOG = LogFactory.getLog(ProtocolExitServlet.class);

	private String protocolErrorPageInitParam;

	private String protocolErrorMessageSessionAttributeInitParam;

	private String protocolResponsePostPageInitParam;

	private String responseActionSessionAttributeInitParam;

	private String responseAttributesSessionAttributeInitParam;

	@EJB
	IdentityService identityService;

	@EJB
	AttributeService attributeService;

	@EJB
	AttributeServiceManager attributeServiceManager;

	@EJB
	private Statistics statistics;

	@Override
	public void init(ServletConfig config) throws ServletException {
		this.protocolErrorPageInitParam = getRequiredInitParameter(config,
				"ProtocolErrorPage");
		this.protocolErrorMessageSessionAttributeInitParam = getRequiredInitParameter(
				config, "ProtocolErrorMessageSessionAttribute");
		this.protocolResponsePostPageInitParam = getRequiredInitParameter(
				config, "ProtocolResponsePostPage");
		this.responseActionSessionAttributeInitParam = getRequiredInitParameter(
				config, "ResponseActionSessionAttribute");
		this.responseAttributesSessionAttributeInitParam = getRequiredInitParameter(
				config, "ResponseAttributesSessionAttribute");
	}

	private String getRequiredInitParameter(ServletConfig config,
			String initParamName) throws ServletException {
		String value = config.getInitParameter(initParamName);
		if (null == value) {
			throw new ServletException(initParamName + " init-param required");
		}
		return value;
	}

	@Override
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		LOG.debug("doGet");
		HttpSession httpSession = request.getSession();
		IdentityProviderProtocolService protocolService;
		try {
			protocolService = ProtocolEntryServlet.getProtocolService(request);
		} catch (ServletException e) {
			httpSession.setAttribute(
					this.protocolErrorMessageSessionAttributeInitParam,
					e.getMessage());
			response.sendRedirect(request.getContextPath()
					+ this.protocolErrorPageInitParam);
			return;
		}

		String protocolId = protocolService.getId();
		this.statistics.countAuthentication(protocolId);

		// get optional RP from Http Session
		RPEntity rp = (RPEntity) request.getSession().getAttribute(
				Constants.RP_SESSION_ATTRIBUTE);

		// get eID data from Http Session
		Identity identity = (Identity) httpSession
				.getAttribute(IdentityDataMessageHandler.IDENTITY_SESSION_ATTRIBUTE);
		Address address = (Address) httpSession
				.getAttribute(IdentityDataMessageHandler.ADDRESS_SESSION_ATTRIBUTE);
		String authenticatedIdentifier = (String) httpSession
				.getAttribute(AuthenticationDataMessageHandler.AUTHENTICATED_USER_IDENTIFIER_SESSION_ATTRIBUTE);
		X509Certificate authnCertificate = (X509Certificate) httpSession
				.getAttribute(IdentityDataMessageHandler.AUTHN_CERT_SESSION_ATTRIBUTE);
		byte[] photo = (byte[]) httpSession
				.getAttribute(IdentityDataMessageHandler.PHOTO_SESSION_ATTRIBUTE);

		// get userID + attributes
		String userId;
		if (null != identity) {
			userId = getUniqueId(identity.getNationalNumber(), rp);
		} else {
			userId = getUniqueId(authenticatedIdentifier, rp);
		}
		Map<String, Attribute> attributes = getAttributes(userId, identity,
				address, authnCertificate, photo);

		// add derived attributes
		for (IdentityProviderAttributeService attributeService : this.attributeServiceManager
				.getAttributeServices()) {

			attributeService.addAttribute(attributes);
		}

		// filter out attributes if RP was authenticated
		if (null != rp) {
			attributes = filterAttributes(rp, attributes);
		}

		// get RP SecretKey and/or PublicKey
		SecretKey secretKey = null;
		PublicKey publicKey = null;
		if (null != rp) {

			try {
				if (null != rp.getAttributeSecretKey()) {
					secretKey = CryptoUtil.getSecretKey(
							rp.getAttributeSecretAlgorithm(),
							rp.getAttributeSecretKey());
				}

				if (null != rp.getAttributePublicKey()) {
					publicKey = CryptoUtil.getPublicKey(rp
							.getAttributePublicKey());
				}
			} catch (Exception e) {
				LOG.error("protocol error: " + e.getMessage(), e);
				httpSession.setAttribute(
						this.protocolErrorMessageSessionAttributeInitParam,
						e.getMessage());
				response.sendRedirect(request.getContextPath()
						+ this.protocolErrorPageInitParam);
				return;
			}
		}

		// set encryption info if needed
		if (null != rp) {
			setEncryptionInfo(rp, attributes);
		}

		// set protocol specific URIs if possible
		for (Attribute attribute : attributes.values()) {
			attribute
					.setUri(getUri(protocolService.getId(), attribute.getUri()));
		}

		String targetURL = null;
		if (null != rp) {
			targetURL = rp.getTargetURL();
		}

		// return protocol specific response
		ReturnResponse returnResponse;
		try {
			returnResponse = protocolService.handleReturnResponse(httpSession,
					userId, attributes, secretKey, publicKey, targetURL,
					request, response);
		} catch (Exception e) {
			LOG.error("protocol error: " + e.getMessage(), e);
			httpSession.setAttribute(
					this.protocolErrorMessageSessionAttributeInitParam,
					e.getMessage());
			response.sendRedirect(request.getContextPath()
					+ this.protocolErrorPageInitParam);
			return;
		}
		if (null != returnResponse) {
			/*
			 * This means that the protocol service wants us to construct some
			 * Browser POST response towards the Service Provider landing site.
			 */
			if (null == returnResponse.getActionUrl()) {

				LOG.error("No action URL specified");
				httpSession.setAttribute(
						this.protocolErrorMessageSessionAttributeInitParam,
						"No action URL specified");
				response.sendRedirect(request.getContextPath()
						+ this.protocolErrorPageInitParam);
				return;
			}

			LOG.debug("constructing generic Browser POST response...");
			httpSession.setAttribute(
					this.responseActionSessionAttributeInitParam,
					returnResponse.getActionUrl());
			httpSession.setAttribute(
					this.responseAttributesSessionAttributeInitParam,
					returnResponse.getAttributes());
			response.sendRedirect(request.getContextPath()
					+ this.protocolResponsePostPageInitParam);
			return;
		}

		/*
		 * Clean-up the session here as it is no longer used after this point.
		 */
		httpSession.invalidate();
	}

	/*
	 * Encrypt attributes configured so in the RP.
	 */
	private void setEncryptionInfo(RPEntity rp,
			Map<String, Attribute> attributes) {

		// encrypt when needed
		for (RPAttributeEntity rpAttribute : rp.getAttributes()) {

			Attribute attribute = attributes.get(rpAttribute.getAttribute()
					.getUri());
			if (null != attribute) {
				attribute.setEncrypted(rpAttribute.isEncrypted());
			}
		}
	}

	/*
	 * Filter out attributes not specified in the RP's configuration
	 */
	private Map<String, Attribute> filterAttributes(RPEntity rp,
			Map<String, Attribute> attributes) {

		Map<String, Attribute> filteredAttributes = new HashMap<String, Attribute>();
		for (RPAttributeEntity rpAttribute : rp.getAttributes()) {

			if (attributes.keySet().contains(
					rpAttribute.getAttribute().getUri())) {
				filteredAttributes.put(rpAttribute.getAttribute().getUri(),
						attributes.get(rpAttribute.getAttribute().getUri()));
			}
		}
		return filteredAttributes;
	}

	/**
	 * Optionally encrypt the user ID
	 * 
	 * @param userId
	 *            user ID to encrypt ( or not )
	 * @param rp
	 *            rp, can be null
	 * @return (encrypted) user ID
	 */
	private String getUniqueId(String userId, RPEntity rp) {

		String uniqueId = userId;

		byte[] hmacSecret = getIdentifierSecret(rp);

		if (null != hmacSecret) {

			Mac mac;
			try {
				mac = CryptoUtil.getMac(hmacSecret);
			} catch (InvalidKeyException e) {
				throw new RuntimeException("Invalid key", e);
			}
			mac.update(uniqueId.getBytes());
			byte[] resultHMac = mac.doFinal();
			uniqueId = new String(Hex.encodeHex(resultHMac)).toUpperCase();
		}
		return uniqueId;
	}

	private byte[] getIdentifierSecret(RPEntity rp) {

		if (null == rp || null == rp.getIdentifierSecretKey()
				|| rp.getIdentifierSecretKey().trim().isEmpty()) {
			// RP dont have one, go to IdP default
			return this.identityService.getHmacSecret();
		}

		try {
			return Hex.decodeHex(rp.getIdentifierSecretKey().toCharArray());
		} catch (DecoderException e) {
			throw new RuntimeException("HEX decoder error: " + e.getMessage(),
					e);
		}

	}

	/**
	 * @param protocolId
	 *            ID of authn protocol
	 * @param attributeUri
	 *            attribute's default URI
	 * @return the protocol specific URI if any ( or else default URI )
	 */
	private String getUri(String protocolId, String attributeUri) {

		return this.attributeService.getUri(protocolId, attributeUri);
	}

	private Attribute getAttribute(DefaultAttribute defaultAttribute,
			Object value) {

		return new Attribute(defaultAttribute.getUri(),
				defaultAttribute.getAttributeType(), value);
	}

	/*
	 * Construct list of attributes given the eID data.
	 */
	private Map<String, Attribute> getAttributes(String userId,
			Identity identity, Address address,
			X509Certificate authnCertificate, byte[] photo) {

		Map<String, Attribute> attributes = new HashMap<String, Attribute>();

		String givenName;
		String surName;
		if (null != identity) {
			givenName = identity.getFirstName();
			surName = identity.getName();
		} else {
			givenName = getGivenName(authnCertificate);
			surName = getSurName(authnCertificate);
		}

		attributes.put(DefaultAttribute.LAST_NAME.getUri(),
				getAttribute(DefaultAttribute.LAST_NAME, surName));

		attributes.put(DefaultAttribute.FIRST_NAME.getUri(),
				getAttribute(DefaultAttribute.FIRST_NAME, givenName));

		attributes.put(DefaultAttribute.NAME.getUri(),
				getAttribute(DefaultAttribute.NAME, givenName + " " + surName));

		attributes.put(DefaultAttribute.IDENTIFIER.getUri(),
				getAttribute(DefaultAttribute.IDENTIFIER, userId));

		if (null != authnCertificate) {
			/*
			 * authnCertificate can be null for recent eID cards that can have
			 * no certificates embedded at all.
			 */
			try {
				attributes.put(
						DefaultAttribute.AUTHN_CERT.getUri(),
						getAttribute(DefaultAttribute.AUTHN_CERT,
								authnCertificate.getEncoded()));
			} catch (CertificateEncodingException e) {
				throw new RuntimeException("X509 encoding error: "
						+ e.getMessage(), e);
			}
		}

		if (null != address) {

			attributes.put(
					DefaultAttribute.ADDRESS.getUri(),
					getAttribute(DefaultAttribute.ADDRESS,
							address.getStreetAndNumber()));
			attributes.put(
					DefaultAttribute.LOCALITY.getUri(),
					getAttribute(DefaultAttribute.LOCALITY,
							address.getMunicipality()));
			attributes
					.put(DefaultAttribute.POSTAL_CODE.getUri(),
							getAttribute(DefaultAttribute.POSTAL_CODE,
									address.getZip()));
		}

		if (null != identity) {

			attributes.put(
					DefaultAttribute.GENDER.getUri(),
					getAttribute(DefaultAttribute.GENDER,
							IdpUtil.getGenderValue(identity)));
			attributes.put(
					DefaultAttribute.DATE_OF_BIRTH.getUri(),
					getAttribute(DefaultAttribute.DATE_OF_BIRTH,
							identity.getDateOfBirth()));
			attributes.put(
					DefaultAttribute.NATIONALITY.getUri(),
					getAttribute(DefaultAttribute.NATIONALITY,
							identity.getNationality()));
			attributes.put(
					DefaultAttribute.PLACE_OF_BIRTH.getUri(),
					getAttribute(DefaultAttribute.PLACE_OF_BIRTH,
							identity.getPlaceOfBirth()));

			attributes.put(
					DefaultAttribute.CARD_NUMBER.getUri(),
					getAttribute(DefaultAttribute.CARD_NUMBER,
							identity.cardNumber));

			attributes.put(
					DefaultAttribute.CARD_VALIDITY_BEGIN.getUri(),
					getAttribute(DefaultAttribute.CARD_VALIDITY_BEGIN,
							identity.cardValidityDateBegin));

			attributes.put(
					DefaultAttribute.CARD_VALIDITY_END.getUri(),
					getAttribute(DefaultAttribute.CARD_VALIDITY_END,
							identity.cardValidityDateEnd));
		}

		if (null != photo) {

			attributes.put(DefaultAttribute.PHOTO.getUri(),
					getAttribute(DefaultAttribute.PHOTO, photo));
		}

		return attributes;
	}

	private static String getGivenName(X509Certificate authnCertificate) {

		X500Principal subjectPrincipal = authnCertificate
				.getSubjectX500Principal();
		String subjectName = subjectPrincipal.toString();
		return getAttributeFromSubjectName(subjectName, "GIVENNAME");
	}

	private static String getSurName(X509Certificate authnCertificate) {

		X500Principal subjectPrincipal = authnCertificate
				.getSubjectX500Principal();
		String subjectName = subjectPrincipal.toString();
		return getAttributeFromSubjectName(subjectName, "SURNAME");
	}

	private static String getAttributeFromSubjectName(String subjectName,
			String attributeName) {

		int attributeBegin = subjectName.indexOf(attributeName + '=');
		if (-1 == attributeBegin) {
			throw new IllegalArgumentException(
					"attribute name does not occur in subject: "
							+ attributeName);
		}
		attributeBegin += attributeName.length() + 1; // "attributeName="
		int attributeEnd = subjectName.indexOf(',', attributeBegin);
		if (-1 == attributeEnd)
		// last field has no trailing ","
		{
			attributeEnd = subjectName.length();
		}
		return subjectName.substring(attributeBegin, attributeEnd);
	}

}

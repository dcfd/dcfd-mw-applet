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

package be.fedict.eid.idp.model.applet;

import java.security.cert.X509Certificate;
import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Local;
import javax.ejb.Stateless;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jboss.ejb3.annotation.LocalBinding;

import be.fedict.eid.applet.service.spi.IdentityIntegrityService;
import be.fedict.eid.idp.entity.RPEntity;
import be.fedict.eid.idp.model.ConfigProperty;
import be.fedict.eid.idp.model.Configuration;
import be.fedict.eid.idp.model.Constants;
import be.fedict.trust.client.XKMS2Client;
import be.fedict.trust.client.exception.ValidationFailedException;

/**
 * eID Applet Service Identity Integrity Service implementation.
 * 
 * @author Frank Cornelis
 */
@Stateless
@Local(IdentityIntegrityService.class)
@LocalBinding(jndiBinding = Constants.IDP_JNDI_CONTEXT
		+ "IdentityIntegrityServiceBean")
public class IdentityIntegrityServiceBean implements IdentityIntegrityService {

	private static final Log LOG = LogFactory
			.getLog(IdentityIntegrityServiceBean.class);

	@EJB
	private Configuration configuration;

	public void checkNationalRegistrationCertificate(
			List<X509Certificate> certificateChain) throws SecurityException {
		LOG.debug("validate national registry certificate: "
				+ certificateChain.get(0).getSubjectX500Principal());

		String xkmsUrl = this.configuration.getValue(ConfigProperty.XKMS_URL,
				String.class);
		if (null == xkmsUrl || xkmsUrl.trim().isEmpty()) {
			LOG.warn("no XKMS URL configured!");
			return;
		}

		RPEntity rp = AppletUtil
				.getSessionAttribute(Constants.RP_SESSION_ATTRIBUTE);
		String xkmsTrustDomain = null;
		if (null != rp) {
			xkmsTrustDomain = rp.getIdentityTrustDomain();
		}
		if (null == xkmsTrustDomain || xkmsTrustDomain.trim().isEmpty()) {
			xkmsTrustDomain = this.configuration.getValue(
					ConfigProperty.XKMS_IDENT_TRUST_DOMAIN, String.class);
		}
		if (null != xkmsTrustDomain) {
			if (xkmsTrustDomain.trim().isEmpty()) {
				xkmsTrustDomain = null;
			}
		}
		LOG.debug("Trust domain=" + xkmsTrustDomain);

		XKMS2Client xkms2Client = new XKMS2Client(xkmsUrl);

		Boolean useHttpProxy = this.configuration.getValue(
				ConfigProperty.HTTP_PROXY_ENABLED, Boolean.class);
		if (null != useHttpProxy && useHttpProxy) {
			String httpProxyHost = this.configuration.getValue(
					ConfigProperty.HTTP_PROXY_HOST, String.class);
			int httpProxyPort = this.configuration.getValue(
					ConfigProperty.HTTP_PROXY_PORT, Integer.class);
			LOG.debug("use proxy: " + httpProxyHost + ":" + httpProxyPort);
			xkms2Client.setProxy(httpProxyHost, httpProxyPort);
		} else {
			// disable previously set proxy
			xkms2Client.setProxy(null, 0);
		}

		try {
			LOG.debug("validating certificate chain");
			if (null != xkmsTrustDomain) {
				xkms2Client.validate(xkmsTrustDomain, certificateChain);
			} else {
				xkms2Client.validate(certificateChain);
			}
		} catch (ValidationFailedException e) {
			LOG.warn("invalid certificate");
			throw new SecurityException("invalid certificate");
		} catch (Exception e) {
			LOG.warn("eID Trust Service error: " + e.getMessage(), e);
			throw new SecurityException("eID Trust Service error");
		}
	}
}

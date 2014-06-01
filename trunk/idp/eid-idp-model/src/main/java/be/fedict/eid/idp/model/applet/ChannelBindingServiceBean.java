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

package be.fedict.eid.idp.model.applet;

import java.security.cert.X509Certificate;

import javax.ejb.EJB;
import javax.ejb.Local;
import javax.ejb.Stateless;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jboss.ejb3.annotation.LocalBinding;

import be.fedict.eid.applet.service.spi.ChannelBindingService;
import be.fedict.eid.idp.model.ConfigProperty;
import be.fedict.eid.idp.model.Configuration;
import be.fedict.eid.idp.model.Constants;

/**
 * eID Applet Channel Binding Service implementation.
 * 
 * @author Wim Vandenhaute
 * @author Frank Cornelis
 */
@Stateless
@Local(ChannelBindingService.class)
@LocalBinding(jndiBinding = Constants.IDP_JNDI_CONTEXT
		+ "ChannelBindingServiceBean")
public class ChannelBindingServiceBean implements ChannelBindingService {

	private static final Log LOG = LogFactory
			.getLog(ChannelBindingServiceBean.class);

	@EJB
	private Configuration configuration;

	@Override
	public X509Certificate getServerCertificate() {
		Boolean omitSecureChannelBinding = this.configuration.getValue(
				ConfigProperty.OMIT_SECURE_CHANNEL_BINDING, Boolean.class);
		if (null != omitSecureChannelBinding) {
			if (omitSecureChannelBinding.equals(Boolean.TRUE)) {
				LOG.warn("omitting secure channel binding");
				return null;
			}
		}
		X509Certificate serverCertificate = this.configuration
				.getAppletConfig().getServerCertificate();
		if (null == serverCertificate) {
			LOG.warn("secure channel binding not yet configured");
		}
		return serverCertificate;
	}
}

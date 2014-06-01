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

import javax.ejb.EJB;
import javax.ejb.Local;
import javax.ejb.Stateless;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jboss.ejb3.annotation.LocalBinding;

import be.fedict.eid.applet.service.spi.IdentityRequest;
import be.fedict.eid.applet.service.spi.IdentityService;
import be.fedict.eid.idp.entity.RPEntity;
import be.fedict.eid.idp.model.ConfigProperty;
import be.fedict.eid.idp.model.Configuration;
import be.fedict.eid.idp.model.Constants;
import be.fedict.eid.idp.spi.IdentityProviderFlow;

@Stateless
@Local(IdentityService.class)
@LocalBinding(jndiBinding = Constants.IDP_JNDI_CONTEXT
		+ "AppletIdentityServiceBean")
public class AppletIdentityServiceBean implements IdentityService {

	private static final Log LOG = LogFactory
			.getLog(AppletIdentityServiceBean.class);

	@EJB
	private Configuration configuration;

	@Override
	public IdentityRequest getIdentityRequest() {

		boolean includeIdentity = false;
		boolean includeAddress = false;
		boolean includePhoto = false;
		boolean includeCertificates = true;

		RPEntity relyingPartyEntity = AppletUtil
				.getSessionAttribute(Constants.RP_SESSION_ATTRIBUTE);
		Boolean removeCard;
		if (null != relyingPartyEntity) {
			String idx = relyingPartyEntity.getId().toString();
			Boolean overrideRemoveCard = this.configuration.getValue(
					ConfigProperty.OVERRIDE_REMOVE_CARD, idx, Boolean.class);
			if (null != overrideRemoveCard && true == overrideRemoveCard) {
				removeCard = this.configuration.getValue(
						ConfigProperty.REMOVE_CARD, idx, Boolean.class);
			} else {
				removeCard = this.configuration.getValue(
						ConfigProperty.REMOVE_CARD, Boolean.class);
			}
		} else {
			removeCard = this.configuration.getValue(
					ConfigProperty.REMOVE_CARD, Boolean.class);
		}
		if (null == removeCard) {
			removeCard = false;
		}
		LOG.debug("remove card: " + removeCard);

		IdentityProviderFlow idpFlow = AppletUtil
				.getSessionAttribute(Constants.IDP_FLOW_SESSION_ATTRIBUTE);
		switch (idpFlow) {
		case IDENTIFICATION:
		case AUTHENTICATION_WITH_IDENTIFICATION:
			includeIdentity = true;
			includeAddress = true;
			includePhoto = true;
			break;
		case AUTHENTICATION:
			includeIdentity = false;
			includeAddress = false;
			includePhoto = false;
		}

		return new IdentityRequest(includeIdentity, includeAddress,
				includePhoto, includeCertificates, removeCard);
	}
}

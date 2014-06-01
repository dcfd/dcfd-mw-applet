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

import java.util.Calendar;

import javax.ejb.EJB;
import javax.ejb.Local;
import javax.ejb.Stateless;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jboss.ejb3.annotation.LocalBinding;

import be.fedict.eid.applet.service.spi.SecureCardReaderService;
import be.fedict.eid.idp.entity.RPEntity;
import be.fedict.eid.idp.model.ConfigProperty;
import be.fedict.eid.idp.model.Configuration;
import be.fedict.eid.idp.model.Constants;

/**
 * Implementation of eID Applet Service SecureCardReaderService SPI.
 * 
 * @author Frank Cornelis
 * 
 */
@Stateless
@Local(SecureCardReaderService.class)
@LocalBinding(jndiBinding = Constants.IDP_JNDI_CONTEXT
		+ "SecureCardReaderServiceBean")
public class SecureCardReaderServiceBean implements SecureCardReaderService {

	private static final Log LOG = LogFactory
			.getLog(SecureCardReaderServiceBean.class);

	@EJB
	private Configuration configuration;

	@Override
	public String getTransactionMessage() {
		Boolean transactionMessageSigning = this.configuration.getValue(
				ConfigProperty.TRANSACTION_MESSAGE_SIGNING, Boolean.class);
		if (null == transactionMessageSigning) {
			return null;
		}
		if (Boolean.FALSE.equals(transactionMessageSigning)) {
			return null;
		}
		RPEntity relyingPartyEntity = AppletUtil
				.getSessionAttribute(Constants.RP_SESSION_ATTRIBUTE);
		String applicationName;
		if (null != relyingPartyEntity) {
			applicationName = relyingPartyEntity.getName();
		} else {
			applicationName = AppletUtil
					.getSessionAttribute(Constants.RP_DOMAIN_SESSION_ATTRIBUTE);
		}
		Calendar calendar = Calendar.getInstance();
		String transactionMessage = applicationName + " @ "
				+ calendar.get(Calendar.DAY_OF_MONTH) + "/"
				+ (calendar.get(Calendar.MONTH) + 1) + "/"
				+ calendar.get(Calendar.YEAR) + " "
				+ calendar.get(Calendar.HOUR_OF_DAY) + ":"
				+ calendar.get(Calendar.MINUTE) + ":"
				+ calendar.get(Calendar.SECOND);
		LOG.debug("transaction message: " + transactionMessage);
		return transactionMessage;
	}
}

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

package be.fedict.eid.idp.admin.webapp;

import java.io.IOException;
import java.util.List;

import javax.ejb.Local;
import javax.faces.model.SelectItem;

import org.richfaces.event.UploadEvent;

import be.fedict.eid.idp.entity.AppletConfigEntity;

@Local
public interface Config {

	/*
	 * Accessors.
	 */
	String getXkmsUrl();

	void setXkmsUrl(String xkmsUrl);

	String getXkmsAuthTrustDomain();

	void setXkmsAuthTrustDomain(String xkmsAuthTrustDomain);

	String getXkmsIdentTrustDomain();

	void setXkmsIdentTrustDomain(String xkmsIdentTrustDomain);

	String getHmacSecret();

	void setHmacSecret(String hmacSecret);

	Boolean getHttpProxy();

	void setHttpProxy(Boolean httpProxy);

	String getHttpProxyHost();

	void setHttpProxyHost(String httpProxyHost);

	Integer getHttpProxyPort();

	void setHttpProxyPort(Integer httpProxyPort);

	String getIssuer();

	void setIssuer(String issuer);

	AppletConfigEntity getAppletConfig();

	void setAppletConfig(AppletConfigEntity appletConfig);

	String getSelectedTab();

	void setSelectedTab(String selectedTab);

	Integer getTokenValidity();

	void setTokenValidity(Integer tokenValidity);

	Boolean getRemoveCard();

	void setRemoveCard(Boolean removeCard);

	Boolean getTransactionMessageSigning();

	void setTransactionMessageSigning(Boolean transactionMessageSigning);

	void setOmitSecureChannelBinding(Boolean omitSecureChannelBinding);

	Boolean getOmitSecureChannelBinding();

	Boolean getHsts();

	void setHsts(Boolean hsts);

	Boolean getXssProtection();

	void setXssProtection(Boolean xssProtection);

	String getXFrameOptions();

	void setXFrameOptions(String xFrameOptions);

	/*
	 * Listeners.
	 */
	void uploadListener(UploadEvent event) throws IOException;

	/*
	 * Factories
	 */
	List<SelectItem> keyStoreTypeFactory();

	List<SelectItem> xFrameOptionsFactory();

	/*
	 * Actions.
	 */
	String saveIdP();

	String saveXkms();

	String saveNetwork();

	String saveApplet();

	String removeApplet();

	String saveSecurity();

	/*
	 * Lifecycle.
	 */
	void destroy();

	void postConstruct();
}

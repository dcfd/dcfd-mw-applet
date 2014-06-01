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
import java.io.OutputStream;
import java.security.PublicKey;
import java.util.List;

import javax.ejb.Local;
import javax.faces.model.SelectItem;

import org.richfaces.event.UploadEvent;

@Local
public interface RP {

	/*
	 * Accessors
	 */
	List<String> getSourceAttributes();

	void setSourceAttributes(List<String> sourceAttributes);

	List<String> getSelectedAttributes();

	void setSelectedAttributes(List<String> selectedAttributes);

	String getSelectedTab();

	void setSelectedTab(String selectedTab);

	PublicKey getAttributePublicKey();

	void paint(OutputStream stream, Object object) throws IOException;

	long getTimeStamp();

	Boolean getRemoveCard();

	void setRemoveCard(Boolean removeCard);

	Boolean getOverrideRemoveCard();

	void setOverrideRemoveCard(Boolean overrideRemoveCard);

	Boolean getBlocked();

	void setBlocked(Boolean blocked);

	String getBlockedMessage();

	void setBlockedMessage(String blockedMessage);

	/*
	 * Listeners.
	 */
	void uploadListener(UploadEvent event) throws IOException;

	void uploadListenerPublic(UploadEvent event) throws IOException;

	void uploadListenerLogo(UploadEvent event) throws IOException;

	/*
	 * Factories
	 */
	void rpListFactory();

	List<SelectItem> secretAlgorithmsFactory();

	/*
	 * Actions.
	 */
	String add();

	String modify();

	String save();

	void select();

	String remove();

	String removeAttributePublic();

	String removeCertificate();

	String back();

	String selectAttributes();

	String saveSelect();

	void initSelect();

	/*
	 * Lifecycle.
	 */
	void destroy();

	void postConstruct();
}

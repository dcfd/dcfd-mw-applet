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

package be.fedict.eid.idp.admin.webapp.bean;

import java.util.LinkedList;
import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Remove;
import javax.ejb.Stateful;
import javax.faces.model.SelectItem;

import org.jboss.ejb3.annotation.LocalBinding;
import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.Create;
import org.jboss.seam.annotations.Destroy;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Out;
import org.jboss.seam.faces.FacesMessages;
import org.jboss.seam.international.StatusMessage;
import org.jboss.seam.log.Log;

import be.fedict.eid.idp.admin.webapp.AdminConstants;
import be.fedict.eid.idp.admin.webapp.Identity;
import be.fedict.eid.idp.model.IdPIdentityConfig;
import be.fedict.eid.idp.model.IdentityService;
import be.fedict.eid.idp.model.KeyStoreType;
import be.fedict.eid.idp.model.exception.KeyStoreLoadException;

@Stateful
@Name("idpIdentity")
@LocalBinding(jndiBinding = AdminConstants.ADMIN_JNDI_CONTEXT + "IdentityBean")
public class IdentityBean implements Identity {

	private static final String ADD_IDENTITY_LABEL = "Add...";

	@Logger
	private Log log;

	@EJB
	private IdentityService identityService;

	@In
	FacesMessages facesMessages;

	@In(value = "idp.identity.name", required = false, scope = ScopeType.SESSION)
	@Out(value = "idp.identity.name", required = false, scope = ScopeType.SESSION)
	private String name;

	private boolean nameReadOnly = true;

	private List<String> identityNames;
	private IdPIdentityConfig idPIdentityConfig;

	@Override
	@Create
	public void create() {

		// Identity Config
		if (null != this.name) {
			this.idPIdentityConfig = this.identityService
					.findIdentityConfig(this.name);
			if (null == this.idPIdentityConfig) {
				this.idPIdentityConfig = new IdPIdentityConfig(this.name);
			}
		} else {
			this.idPIdentityConfig = this.identityService.findIdentityConfig();
			if (null == this.idPIdentityConfig) {
				this.idPIdentityConfig = new IdPIdentityConfig("");
			}
		}
		this.name = this.idPIdentityConfig.getName();
		this.identityNames = this.identityService.getIdentities();

		this.nameReadOnly = !this.name.isEmpty();
	}

	@Override
	@Remove
	@Destroy
	public void destroy() {
	}

	@Override
	public String save() {
		this.log.debug("save");

		try {
			// Identity Config
			this.identityService.setIdentity(this.idPIdentityConfig);

			if (this.idPIdentityConfig.isActive()) {
				this.identityService.reloadIdentity();
			}
			this.identityNames = this.identityService.getIdentities();
			return "success";
		} catch (KeyStoreLoadException e) {
			this.facesMessages.add(StatusMessage.Severity.ERROR,
					"Failed to load keystore: " + e.getMessage());
			return null;
		}
	}

	@Override
	public String activate() {
		this.log.debug("activate: " + this.name);

		try {
			this.idPIdentityConfig.setActive(true);
			this.identityService.setActiveIdentity(this.name);
			return "success";
		} catch (KeyStoreLoadException e) {
			this.facesMessages.add(StatusMessage.Severity.ERROR,
					"Failed to load keystore: " + e.getMessage());
			return null;
		}
	}

	@Override
	public String remove() {
		this.log.debug("remove: " + this.name);

		// disallow removing currently active
		if (this.idPIdentityConfig.isActive() && this.identityNames.size() != 1) {
			this.facesMessages.add(StatusMessage.Severity.ERROR,
					"Identity is currently active, cannot remove.");
			return null;
		}

		// remove
		this.identityService.removeIdentityConfig(this.name);

		// load default config and list of identities
		this.idPIdentityConfig = this.identityService.findIdentityConfig();
		if (null == this.idPIdentityConfig) {
			this.idPIdentityConfig = new IdPIdentityConfig("");
		}
		this.name = this.idPIdentityConfig.getName();
		this.identityNames = this.identityService.getIdentities();
		return "success";
	}

	@Override
	public String test() {

		this.log.debug("test " + this.name);
		try {
			this.identityService.loadIdentity(this.idPIdentityConfig);
		} catch (KeyStoreLoadException e) {
			this.facesMessages.add(StatusMessage.Severity.ERROR,
					"Failed to load keystore: " + e.getMessage());
			return null;
		}
		this.facesMessages.add(StatusMessage.Severity.INFO,
				"Keystore loaded ok.");
		return "success";
	}

	@Override
	public List<SelectItem> getIdentityNames() {

		List<SelectItem> selectItems = new LinkedList<SelectItem>();
		selectItems.add(new SelectItem(ADD_IDENTITY_LABEL));
		for (String identityName : identityNames) {
			selectItems.add(new SelectItem(identityName));
		}
		return selectItems;
	}

	@Override
	public String getIdentityLabel() {
		return "Identity"
				+ (this.idPIdentityConfig.isActive() ? " (Active)" : "");
	}

	@Override
	public String getName() {

		return this.name;
	}

	@Override
	public void setName(String name) {

		if (name.equals(ADD_IDENTITY_LABEL)) {
			this.idPIdentityConfig = new IdPIdentityConfig("");
			this.nameReadOnly = false;
			this.name = this.idPIdentityConfig.getName();
		} else {
			IdPIdentityConfig idPIdentityConfig = this.identityService
					.findIdentityConfig(name);
			if (null != idPIdentityConfig) {
				this.idPIdentityConfig = idPIdentityConfig;
				this.name = this.idPIdentityConfig.getName();
			} else {
				this.name = name;
				this.idPIdentityConfig.setName(name);
			}
		}
	}

	@Override
	public Boolean isNameReadOnly() {
		return this.nameReadOnly;
	}

	@Override
	public String getKeyStoreType() {
		return idPIdentityConfig.getKeyStoreType().name();
	}

	@Override
	public void setKeyStoreType(String keyStoreType) {
		this.idPIdentityConfig.setKeyStoreType(KeyStoreType
				.valueOf(keyStoreType));
	}

	@Override
	public String getKeyStorePath() {
		return this.idPIdentityConfig.getKeyStorePath();
	}

	@Override
	public void setKeyStorePath(String keyStorePath) {
		this.idPIdentityConfig.setKeyStorePath(keyStorePath);
	}

	@Override
	public String getKeyStorePassword() {
		return this.idPIdentityConfig.getKeyStorePassword();
	}

	@Override
	public void setKeyStorePassword(String keyStorePassword) {
		this.idPIdentityConfig.setKeyStorePassword(keyStorePassword);
	}

	@Override
	public String getKeyEntryPassword() {
		return this.idPIdentityConfig.getKeyEntryPassword();
	}

	@Override
	public void setKeyEntryPassword(String keyEntryPassword) {
		this.idPIdentityConfig.setKeyEntryPassword(keyEntryPassword);
	}

	@Override
	public String getKeyEntryAlias() {
		return this.idPIdentityConfig.getKeyEntryAlias();
	}

	@Override
	public void setKeyEntryAlias(String keyEntryAlias) {
		this.idPIdentityConfig.setKeyEntryAlias(keyEntryAlias);
	}

	@Override
	public boolean isActive() {
		return this.idPIdentityConfig.isActive();
	}
}

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

import java.util.List;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.Remove;
import javax.ejb.Stateful;

import org.jboss.ejb3.annotation.LocalBinding;
import org.jboss.seam.annotations.Destroy;
import org.jboss.seam.annotations.Factory;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.datamodel.DataModel;
import org.jboss.seam.faces.FacesMessages;
import org.jboss.seam.log.Log;

import be.fedict.eid.idp.admin.webapp.Accounting;
import be.fedict.eid.idp.admin.webapp.AdminConstants;
import be.fedict.eid.idp.entity.AccountingEntity;
import be.fedict.eid.idp.model.AccountingService;

@Stateful
@Name("idpAccounting")
@LocalBinding(jndiBinding = AdminConstants.ADMIN_JNDI_CONTEXT
		+ "AccountingBean")
public class AccountingBean implements Accounting {

	private static final String ACCOUNTING_LIST_NAME = "idpAccountingList";

	@Logger
	private Log log;

	@EJB
	private AccountingService accountingService;

	@In
	FacesMessages facesMessages;

	@DataModel(ACCOUNTING_LIST_NAME)
	private List<AccountingEntity> accountingList;

	@Override
	@PostConstruct
	public void postConstruct() {
	}

	@Override
	@Remove
	@Destroy
	public void destroy() {
	}

	@Override
	public int getNumberOfDomains() {
		return this.accountingList.size();
	}

	@Override
	public long getNumberOfRequests() {
		return this.accountingService.getNumberOfRequests();
	}

	@Override
	@Factory(ACCOUNTING_LIST_NAME)
	public void accountingListFactory() {

		this.log.debug("accounting list factory");
		this.accountingList = this.accountingService.listAll();
	}

	@Override
	public String reset() {

		this.log.debug("reset");

		this.accountingService.resetAll();

		accountingListFactory();
		return "success";
	}
}

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

package be.fedict.eid.idp.entity;

import java.io.Serializable;
import java.util.List;

import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.Id;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Table;

/**
 * Accounting entity holding info on eID IdP Usage.
 * <p/>
 * Holds <domain,#requests>.
 */
@Entity
@Table(name = Constants.DATABASE_TABLE_PREFIX + "accounting")
@NamedQueries({
		@NamedQuery(name = AccountingEntity.LIST_ALL, query = "FROM AccountingEntity AS accounting "
				+ "ORDER BY accounting.requests DESC"),
		@NamedQuery(name = AccountingEntity.RESET_ALL, query = "DELETE FROM AccountingEntity"),
		@NamedQuery(name = AccountingEntity.NUMBER_OF_REQUESTS, query = "SELECT SUM(requests) FROM AccountingEntity") })
public class AccountingEntity implements Serializable {

	private static final long serialVersionUID = 1L;

	public static final String LIST_ALL = "idp.accounting.all";
	public static final String RESET_ALL = "idp.accounting.reset.all";
	public static final String NUMBER_OF_REQUESTS = "idp.accounting.nbr.requests";

	private String domain;
	private Long requests;

	public AccountingEntity() {
		super();
	}

	public AccountingEntity(String domain) {
		this.domain = domain;
		this.requests = 1L;
	}

	@Id
	public String getDomain() {
		return domain;
	}

	public void setDomain(String domain) {
		this.domain = domain;
	}

	public Long getRequests() {
		return requests;
	}

	public void setRequests(Long requests) {
		this.requests = requests;
	}

	@SuppressWarnings("unchecked")
	public static List<AccountingEntity> listAll(EntityManager entityManager) {

		return entityManager.createNamedQuery(AccountingEntity.LIST_ALL)
				.getResultList();
	}

	public static int resetAll(EntityManager entityManager) {

		return entityManager.createNamedQuery(AccountingEntity.RESET_ALL)
				.executeUpdate();
	}

	public static Long getNumberOfRequests(EntityManager entityManager) {

		return (Long) entityManager.createNamedQuery(
				AccountingEntity.NUMBER_OF_REQUESTS).getSingleResult();
	}

}

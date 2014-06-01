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

package be.fedict.eid.idp.model.bean;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;

import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.idp.entity.AccountingEntity;
import be.fedict.eid.idp.model.AccountingService;

@Stateless
public class AccountingServiceBean implements AccountingService {

	private static Log LOG = LogFactory.getLog(AccountingServiceBean.class);

	@PersistenceContext
	private EntityManager entityManager;

	@Override
	public List<AccountingEntity> listAll() {
		LOG.debug("list all");
		return AccountingEntity.listAll(this.entityManager);
	}

	@Override
	public void resetAll() {
		LOG.debug("reset all: #deleted="
				+ AccountingEntity.resetAll(this.entityManager));
	}

	@Override
	public void addRequest(String domain) {
		if (null == domain) {
			return;
		}

		LOG.debug("Add request: " + domain);
		domain = normalize(domain);
		LOG.debug("normalized domain: " + domain);

		AccountingEntity accountingEntity = this.entityManager.find(
				AccountingEntity.class, domain);
		if (null == accountingEntity) {
			accountingEntity = new AccountingEntity(domain);
			this.entityManager.persist(accountingEntity);
		} else {
			accountingEntity.setRequests(accountingEntity.getRequests() + 1);
		}
	}

	private String normalize(String domain) {
		URI uri;
		try {
			uri = new URI(domain);
		} catch (URISyntaxException e) {
			return domain;
		}
		String scheme = uri.getScheme();
		if ("http".equals(scheme) || "https".equals(scheme)) {
			return uri.getScheme() + "://" + uri.getHost() + uri.getPath();
		}
		return domain;
	}

	@Override
	public long getNumberOfRequests() {
		LOG.debug("get # of requests");
		return AccountingEntity.getNumberOfRequests(this.entityManager);
	}
}

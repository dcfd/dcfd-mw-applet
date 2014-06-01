/*
 * eID Identity Provider Project.
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

package test.unit.be.fedict.eid.idp.model.bean;

import java.lang.reflect.Field;

import javax.persistence.EntityManager;

import org.easymock.EasyMock;
import org.junit.Test;

import be.fedict.eid.idp.entity.AccountingEntity;
import be.fedict.eid.idp.model.bean.AccountingServiceBean;

public class AccountingServiceBeanTest {

	@Test
	public void testAddRequest() throws Exception {
		// setup
		AccountingServiceBean testedInstance = new AccountingServiceBean();

		EntityManager mockEntityManger = EasyMock
				.createMock(EntityManager.class);

		// inject
		Field entityManagerField = AccountingServiceBean.class
				.getDeclaredField("entityManager");
		entityManagerField.setAccessible(true);
		entityManagerField.set(testedInstance, mockEntityManger);

		// expectations
		AccountingEntity accountingEntity = new AccountingEntity(
				"https://www.e-contract.be/landing");
		EasyMock.expect(
				mockEntityManger.find(AccountingEntity.class,
						"https://www.e-contract.be/landing")).andStubReturn(
				accountingEntity);

		// prepare
		EasyMock.replay(mockEntityManger);

		// operate
		testedInstance
				.addRequest("https://www.e-contract.be/landing?param=1234");

		// verify
		EasyMock.verify(mockEntityManger);
	}

	@Test
	public void testAddRequestUrn() throws Exception {
		// setup
		AccountingServiceBean testedInstance = new AccountingServiceBean();

		EntityManager mockEntityManger = EasyMock
				.createMock(EntityManager.class);

		// inject
		Field entityManagerField = AccountingServiceBean.class
				.getDeclaredField("entityManager");
		entityManagerField.setAccessible(true);
		entityManagerField.set(testedInstance, mockEntityManger);

		// expectations
		AccountingEntity accountingEntity = new AccountingEntity("urn:be:test");
		EasyMock.expect(
				mockEntityManger.find(AccountingEntity.class, "urn:be:test"))
				.andStubReturn(accountingEntity);

		// prepare
		EasyMock.replay(mockEntityManger);

		// operate
		testedInstance.addRequest("urn:be:test");

		// verify
		EasyMock.verify(mockEntityManger);
	}
}

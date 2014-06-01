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

package be.fedict.eid.idp.model.admin;

import java.security.cert.X509Certificate;
import java.util.List;

import javax.ejb.Local;

import be.fedict.eid.idp.entity.AdministratorEntity;
import be.fedict.eid.idp.model.exception.RemoveLastAdminException;

@Local
public interface AdminManager {

	/**
	 * @param certificate
	 *            certificate
	 * @return whether the (already authenticated) admin identifier indeed
	 *         belongs to an admin.
	 */
	boolean isAdmin(X509Certificate certificate);

	List<AdministratorEntity> listAdmins();

	void register(AdministratorEntity admin);

	void remove(AdministratorEntity admin) throws RemoveLastAdminException;
}

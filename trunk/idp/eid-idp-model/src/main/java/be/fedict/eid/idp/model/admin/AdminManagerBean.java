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

import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.idp.entity.AdministratorEntity;
import be.fedict.eid.idp.model.exception.RemoveLastAdminException;

@Stateless
public class AdminManagerBean implements AdminManager {

	private static final Log LOG = LogFactory.getLog(AdminManagerBean.class);

	@PersistenceContext
	private EntityManager entityManager;

	public boolean isAdmin(X509Certificate certificate) {

		String id = getId(certificate);
		AdministratorEntity adminEntity = this.entityManager.find(
				AdministratorEntity.class, id);
		if (null != adminEntity && !adminEntity.isPending()) {
			return true;
		} else if (null != adminEntity) {
			// admin exist but is not yet approvied
			return false;
		}
		if (AdministratorEntity.hasAdmins(this.entityManager)) {
			/*
			 * We register a 'pending' admin.
			 */
			String name = certificate.getSubjectX500Principal().toString();
			adminEntity = new AdministratorEntity(id, name, true);
			this.entityManager.persist(adminEntity);
			return false;
		}
		/*
		 * Else we bootstrap the admin.
		 */
		String name = certificate.getSubjectX500Principal().toString();
		adminEntity = new AdministratorEntity(id, name);
		this.entityManager.persist(adminEntity);
		return true;
	}

	@Override
	public List<AdministratorEntity> listAdmins() {

		return AdministratorEntity.listAdmins(this.entityManager);
	}

	@Override
	public void register(AdministratorEntity admin) {

		LOG.debug("register pending admin: " + admin.getName());

		AdministratorEntity attachedAdmin = this.entityManager.find(
				AdministratorEntity.class, admin.getId());
		attachedAdmin.setPending(false);
	}

	@Override
	public void remove(AdministratorEntity admin)
			throws RemoveLastAdminException {

		LOG.debug("remove admin: " + admin.getName());

		// check not last administrator
		if (listAdmins().size() == 1) {
			LOG.error("cannot remove last administrator");
			throw new RemoveLastAdminException();
		}

		AdministratorEntity attachedAdmin = this.entityManager.find(
				AdministratorEntity.class, admin.getId());
		this.entityManager.remove(attachedAdmin);
	}

	private String getId(X509Certificate certificate) {
		PublicKey publicKey = certificate.getPublicKey();
		return DigestUtils.shaHex(publicKey.getEncoded());
	}

}

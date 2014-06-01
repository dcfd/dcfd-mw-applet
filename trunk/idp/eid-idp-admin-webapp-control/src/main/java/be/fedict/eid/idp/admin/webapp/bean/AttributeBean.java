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

import be.fedict.eid.idp.admin.webapp.AdminConstants;
import be.fedict.eid.idp.admin.webapp.Attribute;
import be.fedict.eid.idp.entity.AttributeProtocolUriEntity;
import be.fedict.eid.idp.model.AttributeService;

@Stateful
@Name("idpAttribute")
@LocalBinding(jndiBinding = AdminConstants.ADMIN_JNDI_CONTEXT + "AttributeBean")
public class AttributeBean implements Attribute {

	private static final String ATTRIBUTE_URI_LIST_NAME = "idpAttributeUriList";

	@Logger
	private Log log;

	@EJB
	private AttributeService attributeService;

	@In
	FacesMessages facesMessages;

	@DataModel(ATTRIBUTE_URI_LIST_NAME)
	private List<AttributeProtocolUriEntity> attributeUriList;

	@Override
	@PostConstruct
	public void postConstruct() {

	}

	@Override
	@Factory(ATTRIBUTE_URI_LIST_NAME)
	public void attributeUriFactory() {

		this.attributeUriList = this.attributeService.listAttributeUris();
	}

	@Override
	public String save() {

		this.log.debug("save");
		this.attributeService.saveAttributeUris(this.attributeUriList);
		return "success";
	}

	@Override
	@Remove
	@Destroy
	public void destroy() {

		this.attributeUriList = null;
	}
}

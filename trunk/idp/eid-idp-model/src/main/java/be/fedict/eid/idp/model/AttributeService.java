/*
 * eID Digital Signature Service Project.
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

package be.fedict.eid.idp.model;

import java.util.List;

import javax.ejb.Local;

import be.fedict.eid.idp.entity.AttributeEntity;
import be.fedict.eid.idp.entity.AttributeProtocolUriEntity;
import be.fedict.eid.idp.entity.RPEntity;

@Local
public interface AttributeService {

	List<AttributeEntity> listAttributes();

	List<AttributeProtocolUriEntity> listAttributeUris();

	AttributeEntity saveAttribute(String name, String description, String uri);

	RPEntity setAttributes(RPEntity rp, List<String> attributes);

	AttributeProtocolUriEntity createAttributeUri(String protocolId,
			String attributeUri, String protocolUri);

	String getUri(String protocolId, String attributeUri);

	AttributeEntity findAttribute(String protocolId, String attributeUri);

	void saveAttributeUris(List<AttributeProtocolUriEntity> attributeUris);
}

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
import java.util.Set;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.FetchType;
import javax.persistence.Id;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.OneToMany;
import javax.persistence.Query;
import javax.persistence.Table;

import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;
import org.apache.commons.lang.builder.ToStringBuilder;
import org.apache.commons.lang.builder.ToStringStyle;

@Entity
@Table(name = Constants.DATABASE_TABLE_PREFIX + "attributes")
@NamedQueries(@NamedQuery(name = AttributeEntity.LIST_ALL, query = "FROM AttributeEntity"))
public class AttributeEntity implements Serializable {

	private static final long serialVersionUID = 1L;

	public static final String LIST_ALL = "idp.attr.all";

	private String uri;
	private String name;
	private String description;
	private Set<AttributeProtocolUriEntity> protocolUris;

	public AttributeEntity() {
		super();
	}

	public AttributeEntity(String name, String description, String uri) {
		this.name = name;
		this.description = description;
		this.uri = uri;
	}

	@Id
	public String getUri() {
		return this.uri;
	}

	public void setUri(String uri) {
		this.uri = uri;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	@Column(nullable = true)
	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	@OneToMany(fetch = FetchType.EAGER, cascade = CascadeType.REMOVE, mappedBy = AttributeProtocolUriEntity.ATTRIBUTE_COLUMN_NAME)
	public Set<AttributeProtocolUriEntity> getProtocolUris() {
		return this.protocolUris;
	}

	public void setProtocolUris(Set<AttributeProtocolUriEntity> protocolUris) {
		this.protocolUris = protocolUris;
	}

	@SuppressWarnings("unchecked")
	public static List<AttributeEntity> listAttributes(
			EntityManager entityManager) {

		Query query = entityManager.createNamedQuery(LIST_ALL);
		return query.getResultList();
	}

	@Override
	public boolean equals(Object obj) {

		if (this == obj) {
			return true;
		}
		if (null == obj) {
			return false;
		}
		if (!(obj instanceof AttributeEntity)) {
			return false;
		}
		AttributeEntity rhs = (AttributeEntity) obj;
		return new EqualsBuilder().append(this.uri, rhs.uri).isEquals();
	}

	@Override
	public int hashCode() {

		return new HashCodeBuilder().append(this.uri).toHashCode();
	}

	@Override
	public String toString() {

		return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
				.append("uri", this.uri).append("name", this.name)
				.append("description", this.description).toString();
	}

}

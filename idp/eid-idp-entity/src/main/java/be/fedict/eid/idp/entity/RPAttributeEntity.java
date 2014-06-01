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

import javax.persistence.AttributeOverride;
import javax.persistence.AttributeOverrides;
import javax.persistence.Column;
import javax.persistence.EmbeddedId;
import javax.persistence.Entity;
import javax.persistence.JoinColumn;
import javax.persistence.ManyToOne;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Table;

import org.apache.commons.lang.builder.EqualsBuilder;
import org.apache.commons.lang.builder.HashCodeBuilder;
import org.apache.commons.lang.builder.ToStringBuilder;
import org.apache.commons.lang.builder.ToStringStyle;

/**
 * Relying Party (RP) Attribute Entity.
 * <p/>
 * These entities specify the custom set of attributes to be returned for a
 * specific RP along with whether they need to be returned encrypted or not.
 */
@Entity
@Table(name = Constants.DATABASE_TABLE_PREFIX + "attribute_rp")
@NamedQueries(@NamedQuery(name = RPAttributeEntity.LIST_ALL, query = "FROM RPAttributeEntity"))
public class RPAttributeEntity implements Serializable {

	private static final long serialVersionUID = 1L;

	public static final String LIST_ALL = "idp.attr.rp.all";

	public static final String RP_COLUMN_NAME = "rp";
	public static final String ATTRIBUTE_COLUMN_NAME = "attribute";

	private RPAttributePK pk;

	private RPEntity rp;
	private AttributeEntity attribute;

	private boolean encrypted;

	public RPAttributeEntity() {
		super();
	}

	public RPAttributeEntity(RPEntity rp, AttributeEntity attribute) {

		this.pk = new RPAttributePK(rp, attribute);
		this.rp = rp;
		this.attribute = attribute;
	}

	@EmbeddedId
	@AttributeOverrides({
			@AttributeOverride(name = RPAttributePK.RP_COLUMN_NAME, column = @Column(name = RP_COLUMN_NAME)), //
			@AttributeOverride(name = RPAttributePK.ATTRIBUTE_COLUMN_NAME, column = @Column(name = ATTRIBUTE_COLUMN_NAME)) })
	public RPAttributePK getPk() {
		return pk;
	}

	public void setPk(RPAttributePK pk) {
		this.pk = pk;
	}

	@ManyToOne(optional = false)
	@JoinColumn(name = RP_COLUMN_NAME, insertable = false, updatable = false)
	public RPEntity getRp() {
		return rp;
	}

	public void setRp(RPEntity rp) {
		this.rp = rp;
	}

	@ManyToOne(optional = false)
	@JoinColumn(name = ATTRIBUTE_COLUMN_NAME, insertable = false, updatable = false)
	public AttributeEntity getAttribute() {
		return attribute;
	}

	public void setAttribute(AttributeEntity attribute) {
		this.attribute = attribute;
	}

	public boolean isEncrypted() {
		return encrypted;
	}

	public void setEncrypted(boolean encrypted) {
		this.encrypted = encrypted;
	}

	@Override
	public boolean equals(Object obj) {

		if (this == obj) {
			return true;
		}
		if (null == obj) {
			return false;
		}
		if (!(obj instanceof RPAttributeEntity)) {
			return false;
		}
		RPAttributeEntity rhs = (RPAttributeEntity) obj;
		return new EqualsBuilder().append(this.pk, rhs.pk).isEquals();
	}

	@Override
	public int hashCode() {

		return new HashCodeBuilder().append(this.pk).toHashCode();
	}

	@Override
	public String toString() {

		return new ToStringBuilder(this, ToStringStyle.SHORT_PREFIX_STYLE)
				.append("pk", this.pk).toString();
	}
}

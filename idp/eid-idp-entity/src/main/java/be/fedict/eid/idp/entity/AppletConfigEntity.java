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

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.Serializable;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.persistence.Basic;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.Transient;

/**
 * Applet configuration entity.
 * <p/>
 * Allows an administrator to specify the SSL certificate to be used for secure
 * channel binding when using the eID Applet.
 */
@Entity
@Table(name = Constants.DATABASE_TABLE_PREFIX + "applet")
@NamedQueries({ @NamedQuery(name = AppletConfigEntity.LIST_ALL, query = "FROM AppletConfigEntity ") })
public class AppletConfigEntity implements Serializable {

	private static final long serialVersionUID = 1L;

	public static final String LIST_ALL = "idp.applet.list.all";

	private Long id;

	private byte[] encodedServerCertificate;

	public AppletConfigEntity(X509Certificate certificate)
			throws CertificateEncodingException {

		this.encodedServerCertificate = certificate.getEncoded();
	}

	public AppletConfigEntity() {
		super();
	}

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	public Long getId() {
		return this.id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	@Column(length = 4 * 1024, nullable = true)
	@Basic(fetch = FetchType.LAZY)
	public byte[] getEncodedServerCertificate() {
		return encodedServerCertificate;
	}

	public void setEncodedServerCertificate(byte[] encodedServerCertificate) {
		this.encodedServerCertificate = encodedServerCertificate;
	}

	@Transient
	public X509Certificate getServerCertificate() {

		if (null == this.encodedServerCertificate) {
			return null;
		}
		try {
			CertificateFactory certificateFactory = CertificateFactory
					.getInstance("X.509");
			InputStream certificateStream = new ByteArrayInputStream(
					this.encodedServerCertificate);
			return (X509Certificate) certificateFactory
					.generateCertificate(certificateStream);
		} catch (CertificateException e) {
			throw new RuntimeException("cert factory error: " + e.getMessage());
		}
	}

	@Transient
	public void setServerCertificate(X509Certificate certificate)
			throws CertificateEncodingException {

		this.encodedServerCertificate = certificate.getEncoded();
	}

	@Transient
	public String getServerCertificateSubject() {

		if (null == this.encodedServerCertificate) {
			return null;
		}
		return getServerCertificate().getSubjectDN().getName();
	}

	@SuppressWarnings("unchecked")
	public static AppletConfigEntity getAppletConfig(EntityManager entityManager) {

		Query query = entityManager.createNamedQuery(LIST_ALL);
		List<AppletConfigEntity> configs = query.getResultList();
		if (configs.isEmpty()) {
			return new AppletConfigEntity();
		}
		return configs.get(0);
	}
}

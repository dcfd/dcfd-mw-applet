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
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import javax.persistence.Basic;
import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.EnumType;
import javax.persistence.Enumerated;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.Lob;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.NoResultException;
import javax.persistence.OneToMany;
import javax.persistence.Query;
import javax.persistence.Table;
import javax.persistence.Transient;

/**
 * Relying Party (RP) entity.
 * <p/>
 * Holds the configuration of a RP.
 * <p/>
 * The domain is used by the authentication protocols for authentication.
 * <p/>
 * The certificate is (optionally, depending on the protocol) used for
 * verification of the signed authentication request token.
 * <p/>
 * The identifier secret key is used for encryption of the user identifier.
 * <p/>
 * <p/>
 * The attribute secret is used for encryption of the attributes if needed. Both
 * symmetric as assymetric encryption is supported. The list of supported
 * algorithms can be found @ {@link SecretKeyAlgorithm}.
 * <p/>
 * <p/>
 * The attributes is the custom set of attributes related to this RP.
 */
@Entity
@Table(name = Constants.DATABASE_TABLE_PREFIX + "rp")
@NamedQueries({
		@NamedQuery(name = RPEntity.LIST_ALL, query = "FROM RPEntity "),
		@NamedQuery(name = RPEntity.FIND_DOMAIN, query = "SELECT rp FROM RPEntity "
				+ "AS rp WHERE rp.domain = :domain") })
public class RPEntity implements Serializable {

	private static final long serialVersionUID = 1L;

	public static final String LIST_ALL = "idp.rp.list.all";
	public static final String FIND_DOMAIN = "idp.rp.find.domain";

	private Long id;

	// configurations
	private String name;
	private String domain;
	private String targetURL;

	// logo
	@Lob
	@Column(length = 500 * 1024, nullable = true)
	protected byte[] logo;

	// signing
	private byte[] encodedCertificate;
	private boolean requestSigningRequired;

	// pki
	private String authnTrustDomain;
	private String identityTrustDomain;

	// identifier secret
	private String identifierSecretKey;

	// attribute secret
	private SecretKeyAlgorithm attributeSecretAlgorithm;
	private String attributeSecretKey;
	private byte[] attributePublicKey;

	// attributes
	private List<RPAttributeEntity> attributes;

	public RPEntity(String name, String domain, String targetURL, byte[] logo,
			X509Certificate certificate, boolean requestSigningRequired,
			String identifierSecretKey,
			SecretKeyAlgorithm attributeSecretAlgorithm,
			String attributeSecretKey, byte[] attributePublicKey)
			throws CertificateEncodingException {

		this.name = name;
		this.domain = domain;
		this.targetURL = targetURL;
		this.logo = logo;
		this.encodedCertificate = certificate.getEncoded();
		this.requestSigningRequired = requestSigningRequired;
		this.identifierSecretKey = identifierSecretKey;
		this.attributeSecretAlgorithm = attributeSecretAlgorithm;
		this.attributeSecretKey = attributeSecretKey;
		this.attributePublicKey = attributePublicKey;
		this.attributes = new LinkedList<RPAttributeEntity>();
	}

	public RPEntity() {
		super();
		this.attributes = new LinkedList<RPAttributeEntity>();
	}

	@Id
	@GeneratedValue(strategy = GenerationType.AUTO)
	public Long getId() {
		return this.id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	@Column(nullable = false)
	public String getName() {
		return this.name;
	}

	public void setName(String name) {
		this.name = name;
	}

	@Column(nullable = true)
	public String getDomain() {
		return this.domain;
	}

	public void setDomain(String domain) {
		this.domain = domain;
	}

	@Column(nullable = true)
	public String getTargetURL() {
		return this.targetURL;
	}

	public void setTargetURL(String targetURL) {
		this.targetURL = targetURL;
	}

	@Column(length = 500 * 1024, nullable = true)
	@Basic(fetch = FetchType.LAZY)
	public byte[] getLogo() {
		return this.logo;
	}

	public void setLogo(byte[] logo) {
		this.logo = logo;
	}

	@Lob
	@Column(length = 4 * 1024, nullable = true)
	@Basic(fetch = FetchType.LAZY)
	public byte[] getEncodedCertificate() {
		return encodedCertificate;
	}

	public void setEncodedCertificate(byte[] encodedCertificate) {
		this.encodedCertificate = encodedCertificate;
	}

	@Transient
	public String getCertificateString() {

		X509Certificate certificate = getCertificate();
		if (null == certificate) {
			return "";
		}

		return certificate.toString().replaceAll("\\n", "<br/>");
	}

	@Transient
	public X509Certificate getCertificate() {

		if (null == this.encodedCertificate) {
			return null;
		}

		try {
			CertificateFactory certificateFactory = CertificateFactory
					.getInstance("X.509");
			InputStream certificateStream = new ByteArrayInputStream(
					this.encodedCertificate);
			return (X509Certificate) certificateFactory
					.generateCertificate(certificateStream);
		} catch (CertificateException e) {
			throw new RuntimeException("cert factory error: " + e.getMessage());
		}
	}

	@Transient
	public void setCertificate(X509Certificate certificate)
			throws CertificateEncodingException {

		this.encodedCertificate = certificate.getEncoded();
	}

	@Transient
	public String getCertificateSubject() {

		if (null == this.encodedCertificate) {
			return null;
		}
		return getCertificate().getSubjectDN().getName();
	}

	public boolean isRequestSigningRequired() {
		return this.requestSigningRequired;
	}

	public void setRequestSigningRequired(boolean requestSigningRequired) {
		this.requestSigningRequired = requestSigningRequired;
	}

	@Column(nullable = true)
	public String getAuthnTrustDomain() {
		return this.authnTrustDomain;
	}

	public void setAuthnTrustDomain(String authnTrustDomain) {
		this.authnTrustDomain = authnTrustDomain;
	}

	@Column(nullable = true)
	public String getIdentityTrustDomain() {
		return this.identityTrustDomain;
	}

	public void setIdentityTrustDomain(String identityTrustDomain) {
		this.identityTrustDomain = identityTrustDomain;
	}

	@Column(nullable = true)
	public String getIdentifierSecretKey() {
		return this.identifierSecretKey;
	}

	public void setIdentifierSecretKey(String identifierSecretKey) {
		this.identifierSecretKey = identifierSecretKey;
	}

	@Column(nullable = false)
	@Enumerated(EnumType.STRING)
	public SecretKeyAlgorithm getAttributeSecretAlgorithm() {
		return this.attributeSecretAlgorithm;
	}

	public void setAttributeSecretAlgorithm(
			SecretKeyAlgorithm attributeSecretAlgorithm) {
		this.attributeSecretAlgorithm = attributeSecretAlgorithm;
	}

	@Column(nullable = true)
	public String getAttributeSecretKey() {
		return this.attributeSecretKey;
	}

	public void setAttributeSecretKey(String attributeSecretKey) {
		this.attributeSecretKey = attributeSecretKey;
	}

	@Column(length = 4 * 1024, nullable = true)
	@Basic(fetch = FetchType.EAGER)
	@Lob
	public byte[] getAttributePublicKey() {
		return this.attributePublicKey;
	}

	public void setAttributePublicKey(byte[] attributePublicKey) {
		this.attributePublicKey = attributePublicKey;
	}

	@Transient
	public void setAttributePublicKey(PublicKey publicKey) {

		this.attributePublicKey = publicKey.getEncoded();
	}

	@OneToMany(fetch = FetchType.EAGER, cascade = CascadeType.REMOVE, mappedBy = RPAttributeEntity.RP_COLUMN_NAME)
	public List<RPAttributeEntity> getAttributes() {
		return this.attributes;
	}

	public void setAttributes(List<RPAttributeEntity> attributes) {
		this.attributes = attributes;
	}

	@SuppressWarnings("unchecked")
	public static List<RPEntity> listRPs(EntityManager entityManager) {

		Query query = entityManager.createNamedQuery(LIST_ALL);
		return query.getResultList();
	}

	public static RPEntity findRP(EntityManager entityManager, String domain) {

		Query query = entityManager.createNamedQuery(FIND_DOMAIN);
		query.setParameter("domain", domain);
		try {
			return (RPEntity) query.getSingleResult();
		} catch (NoResultException e) {
			return null;
		}
	}
}

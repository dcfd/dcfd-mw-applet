/*
 * eID Identity Provider Project.
 * Copyright (C) 2010-2012 FedICT.
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

import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;

import be.fedict.eid.idp.entity.RPAttributeEntity;
import be.fedict.eid.idp.entity.RPEntity;
import be.fedict.eid.idp.entity.SecretKeyAlgorithm;
import be.fedict.eid.idp.model.ConfigProperty;
import be.fedict.eid.idp.model.Configuration;
import be.fedict.eid.idp.model.RPService;

@Stateless
public class RPServiceBean implements RPService {

	@PersistenceContext
	private EntityManager entityManager;

	@EJB
	private Configuration configuration;

	@Override
	public List<RPEntity> listRPs() {
		return RPEntity.listRPs(this.entityManager);
	}

	@Override
	public void remove(RPEntity rp) {
		String index = rp.getId().toString();
		RPEntity attachedRp = this.entityManager.find(RPEntity.class,
				rp.getId());
		this.entityManager.remove(attachedRp);
		this.configuration.removeValue(ConfigProperty.OVERRIDE_REMOVE_CARD,
				index);
		this.configuration.removeValue(ConfigProperty.REMOVE_CARD, index);
		this.configuration.removeValue(ConfigProperty.BLOCKED, index);
		this.configuration.removeValue(ConfigProperty.BLOCKED_MESSAGE);
	}

	@Override
	public RPEntity save(RPEntity rp, Boolean overrideRemoveCard,
			Boolean removeCard, Boolean blocked, String blockedMessage) {
		RPEntity attachedRp = null;
		if (null != rp.getId()) {
			attachedRp = this.entityManager.find(RPEntity.class, rp.getId());
		}
		if (null != attachedRp) {
			// save

			// configuration
			attachedRp.setName(rp.getName());
			attachedRp.setRequestSigningRequired(rp.isRequestSigningRequired());
			if (null != rp.getDomain() && rp.getDomain().trim().isEmpty()) {
				attachedRp.setDomain(null);
			} else {
				attachedRp.setDomain(rp.getDomain().trim());
			}
			if (null != rp.getTargetURL() && rp.getTargetURL().trim().isEmpty()) {
				attachedRp.setTargetURL(null);
			} else {
				attachedRp.setTargetURL(rp.getTargetURL().trim());
			}

			// logo
			if (null != rp.getLogo()) {
				attachedRp.setLogo(rp.getLogo());
			}

			// pki
			if (null != rp.getAuthnTrustDomain()
					&& rp.getAuthnTrustDomain().trim().isEmpty()) {
				attachedRp.setAuthnTrustDomain(null);
			} else {
				attachedRp.setAuthnTrustDomain(rp.getAuthnTrustDomain());
			}

			if (null != rp.getIdentityTrustDomain()
					&& rp.getIdentityTrustDomain().trim().isEmpty()) {
				attachedRp.setIdentityTrustDomain(null);
			} else {
				attachedRp.setIdentityTrustDomain(rp.getIdentityTrustDomain());
			}

			// secrets
			if (null != rp.getIdentifierSecretKey()
					&& rp.getIdentifierSecretKey().trim().isEmpty()) {
				attachedRp.setIdentifierSecretKey(null);
			} else {
				attachedRp.setIdentifierSecretKey(rp.getIdentifierSecretKey()
						.trim());
			}

			attachedRp.setAttributeSecretAlgorithm(rp
					.getAttributeSecretAlgorithm());
			attachedRp.setAttributePublicKey(rp.getAttributePublicKey());
			if (rp.getAttributeSecretAlgorithm() == SecretKeyAlgorithm.NONE) {

				attachedRp.setAttributeSecretKey(null);

			} else {

				if (null != rp.getAttributeSecretKey()
						&& rp.getAttributeSecretKey().trim().isEmpty()) {
					attachedRp.setAttributeSecretKey(null);
				} else {
					attachedRp.setAttributeSecretKey(rp.getAttributeSecretKey()
							.trim());
				}
			}

			// signing
			attachedRp.setEncodedCertificate(rp.getEncodedCertificate());

			// attributes
			for (RPAttributeEntity rpAttribute : rp.getAttributes()) {
				attachedRp.getAttributes()
						.get(attachedRp.getAttributes().indexOf(rpAttribute))
						.setEncrypted(rpAttribute.isEncrypted());
			}
			saveExtraAttribute(attachedRp, overrideRemoveCard, removeCard,
					blocked, blockedMessage);
			return attachedRp;
		} else {
			// add
			if (null != rp.getDomain() && rp.getDomain().trim().isEmpty()) {
				rp.setDomain(null);
			}
			if (null != rp.getTargetURL() && rp.getTargetURL().trim().isEmpty()) {
				rp.setTargetURL(null);
			}
			if (null != rp.getAuthnTrustDomain()
					&& rp.getAuthnTrustDomain().trim().isEmpty()) {
				rp.setAuthnTrustDomain(null);
			}
			if (null != rp.getIdentityTrustDomain()
					&& rp.getIdentityTrustDomain().trim().isEmpty()) {
				rp.setIdentityTrustDomain(null);
			}
			if (null != rp.getIdentifierSecretKey()
					&& rp.getIdentifierSecretKey().trim().isEmpty()) {
				rp.setIdentifierSecretKey(null);
			}

			this.entityManager.persist(rp);
			for (RPAttributeEntity rpAttribute : rp.getAttributes()) {
				RPAttributeEntity newRpAttribute = new RPAttributeEntity(rp,
						rpAttribute.getAttribute());
				this.entityManager.persist(newRpAttribute);
			}
			saveExtraAttribute(rp, overrideRemoveCard, removeCard, blocked,
					blockedMessage);
			return rp;
		}
	}

	private void saveExtraAttribute(RPEntity attachedRp,
			Boolean overrideRemoveCard, Boolean removeCard, Boolean blocked,
			String blockedMessage) {
		String idx = attachedRp.getId().toString();
		this.configuration.setValue(ConfigProperty.OVERRIDE_REMOVE_CARD, idx,
				overrideRemoveCard);
		this.configuration
				.setValue(ConfigProperty.REMOVE_CARD, idx, removeCard);
		this.configuration.setValue(ConfigProperty.BLOCKED, idx, blocked);
		this.configuration.setValue(ConfigProperty.BLOCKED_MESSAGE, idx,
				blockedMessage);
	}

	@Override
	public RPEntity find(String domain) {
		return RPEntity.findRP(this.entityManager, domain);
	}

	@Override
	public Boolean getOverrideRemoveCard(RPEntity rp) {
		String idx = rp.getId().toString();
		return this.configuration.getValue(ConfigProperty.OVERRIDE_REMOVE_CARD,
				idx, Boolean.class);
	}

	@Override
	public Boolean getRemoveCard(RPEntity rp) {
		String idx = rp.getId().toString();
		return this.configuration.getValue(ConfigProperty.REMOVE_CARD, idx,
				Boolean.class);
	}

	@Override
	public Boolean getBlocked(RPEntity rp) {
		String idx = rp.getId().toString();
		return this.configuration.getValue(ConfigProperty.BLOCKED, idx,
				Boolean.class);
	}

	@Override
	public String getBlockedMessage(RPEntity rp) {
		String idx = rp.getId().toString();
		return this.configuration.getValue(ConfigProperty.BLOCKED_MESSAGE, idx,
				String.class);
	}
}

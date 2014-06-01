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

package be.fedict.eid.idp.admin.webapp.bean;

import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.LinkedList;
import java.util.List;

import javax.annotation.PostConstruct;
import javax.ejb.EJB;
import javax.ejb.Remove;
import javax.ejb.Stateful;
import javax.faces.model.SelectItem;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.io.FileUtils;
import org.jboss.ejb3.annotation.LocalBinding;
import org.jboss.seam.ScopeType;
import org.jboss.seam.annotations.Begin;
import org.jboss.seam.annotations.Destroy;
import org.jboss.seam.annotations.End;
import org.jboss.seam.annotations.Factory;
import org.jboss.seam.annotations.In;
import org.jboss.seam.annotations.Logger;
import org.jboss.seam.annotations.Name;
import org.jboss.seam.annotations.Out;
import org.jboss.seam.annotations.datamodel.DataModel;
import org.jboss.seam.annotations.datamodel.DataModelSelection;
import org.jboss.seam.faces.FacesMessages;
import org.jboss.seam.log.Log;
import org.richfaces.event.UploadEvent;
import org.richfaces.model.UploadItem;

import be.fedict.eid.idp.admin.webapp.AdminConstants;
import be.fedict.eid.idp.admin.webapp.RP;
import be.fedict.eid.idp.entity.AttributeEntity;
import be.fedict.eid.idp.entity.RPAttributeEntity;
import be.fedict.eid.idp.entity.RPEntity;
import be.fedict.eid.idp.entity.SecretKeyAlgorithm;
import be.fedict.eid.idp.model.AttributeService;
import be.fedict.eid.idp.model.CryptoUtil;
import be.fedict.eid.idp.model.RPService;
import be.fedict.eid.idp.model.exception.KeyLoadException;

@Stateful
@Name("idpRP")
@LocalBinding(jndiBinding = AdminConstants.ADMIN_JNDI_CONTEXT + "RPBean")
public class RPBean implements RP {

	private static final String RP_LIST_NAME = "idpRPList";
	private static final String SELECTED_RP = "selectedRP";
	private static final String UPLOADED_CERTIFICATE = "uploadedCertificate";

	@Logger
	private Log log;

	@EJB
	private RPService rpService;

	@EJB
	private AttributeService attributeService;

	@In
	FacesMessages facesMessages;

	@DataModel(RP_LIST_NAME)
	private List<RPEntity> rpList;

	@DataModelSelection(RP_LIST_NAME)
	@In(value = SELECTED_RP, required = false)
	@Out(value = SELECTED_RP, required = false, scope = ScopeType.CONVERSATION)
	private RPEntity selectedRP;

	@In(value = UPLOADED_CERTIFICATE, required = false)
	@Out(value = UPLOADED_CERTIFICATE, required = false, scope = ScopeType.CONVERSATION)
	private byte[] certificateBytes;

	@In(value = "selectedTab", required = false)
	@Out(value = "selectedTab", required = false, scope = ScopeType.CONVERSATION)
	private String selectedTab = null;

	private List<String> sourceAttributes;
	private List<String> selectedAttributes;

	private Boolean overrideRemoveCard;

	private Boolean removeCard;

	private Boolean blocked;

	private String blockedMessage;

	enum ConfigurationTab {
		tab_config, tab_logo, tab_pki, tab_secret, tab_signing, tab_attributes, tab_applet, tab_blocked
	}

	@Override
	@PostConstruct
	public void postConstruct() {
		this.sourceAttributes = null;
		this.selectedAttributes = new LinkedList<String>();
	}

	@Override
	@Remove
	@Destroy
	public void destroy() {
	}

	@Override
	@Factory(RP_LIST_NAME)
	public void rpListFactory() {
		this.rpList = this.rpService.listRPs();
	}

	@Override
	@Factory("secretAlgorithms")
	public List<SelectItem> secretAlgorithmsFactory() {
		List<SelectItem> secretAlgorithms = new LinkedList<SelectItem>();
		for (SecretKeyAlgorithm algorithm : SecretKeyAlgorithm.values()) {
			secretAlgorithms.add(new SelectItem(algorithm.name(), algorithm
					.name()));
		}
		return secretAlgorithms;
	}

	@Override
	@Begin(join = true)
	public String add() {
		this.log.debug("add RP");
		this.selectedRP = new RPEntity();
		this.log.debug("RP.id: " + this.selectedRP.getId());
		for (AttributeEntity attribute : this.attributeService.listAttributes()) {
			this.selectedRP.getAttributes().add(
					new RPAttributeEntity(this.selectedRP, attribute));
		}
		return "modify";
	}

	@Override
	@Begin(join = true)
	public String modify() {
		this.log.debug("modify RP: #0", this.selectedRP.getName());
		this.overrideRemoveCard = this.rpService
				.getOverrideRemoveCard(this.selectedRP);
		this.removeCard = this.rpService.getRemoveCard(this.selectedRP);
		this.blocked = this.rpService.getBlocked(this.selectedRP);
		this.blockedMessage = this.rpService.getBlockedMessage(this.selectedRP);
		return "modify";
	}

	@Override
	@End
	public String save() {
		this.log.debug("save RP: #0", this.selectedRP.getName());

		// check identifier secret if any
		if (null != this.selectedRP.getIdentifierSecretKey()
				&& !this.selectedRP.getIdentifierSecretKey().trim().isEmpty()) {
			try {
				CryptoUtil.getMac(this.selectedRP.getIdentifierSecretKey());
			} catch (DecoderException e) {
				this.log.error("Failed to decode HMac: " + e.getMessage(), e);
				this.facesMessages.addToControl("identifier_secret",
						"Failed to decode secret");
				return null;
			} catch (InvalidKeyException e) {
				this.log.error("Invalid HMac: " + e.getMessage(), e);
				this.facesMessages.addToControl("identifier_secret",
						"Invalid secret: " + e.getMessage());
				return null;
			}
		}

		this.rpService.save(this.selectedRP, this.overrideRemoveCard,
				this.removeCard, this.blocked, this.blockedMessage);
		rpListFactory();
		return "success";
	}

	@Override
	@Begin(join = true)
	public void select() {
		this.log.debug("selected RP: #0", this.selectedRP.getName());
	}

	@Override
	@End
	public String remove() {
		this.log.debug("remove RP: #0", this.selectedRP.getName());
		this.rpService.remove(this.selectedRP);
		rpListFactory();
		return "success";
	}

	@Override
	public String removeAttributePublic() {
		this.log.debug("remove rp.attribute public");
		this.selectedRP.setAttributePublicKey((byte[]) null);
		this.rpService.save(this.selectedRP, this.overrideRemoveCard,
				this.removeCard, this.blocked, this.blockedMessage);
		return "success";
	}

	@Override
	public String removeCertificate() {
		this.log.debug("remove rp.certificate");
		this.selectedRP.setEncodedCertificate(null);
		this.rpService.save(this.selectedRP, this.overrideRemoveCard,
				this.removeCard, this.blocked, this.blockedMessage);
		return "success";
	}

	@Override
	@End
	public String back() {
		return "back";
	}

	@Override
	public String selectAttributes() {
		return "select";
	}

	@Override
	public String saveSelect() {
		this.log.debug("save selected attributes: "
				+ this.selectedAttributes.size());
		this.selectedRP = this.attributeService.setAttributes(this.selectedRP,
				this.selectedAttributes);
		this.log.debug("selectedRP.attributes: "
				+ this.selectedRP.getAttributes().size());
		return "success";
	}

	@Override
	public void initSelect() {
		this.log.debug("init select");
		if (null != this.selectedRP) {
			this.selectedAttributes = new LinkedList<String>();
			for (RPAttributeEntity rpAttribute : this.selectedRP
					.getAttributes()) {
				this.selectedAttributes
						.add(rpAttribute.getAttribute().getUri());
			}
		}
	}

	@Override
	@Begin(join = true)
	public void uploadListener(UploadEvent event) throws IOException {
		UploadItem item = event.getUploadItem();
		this.log.debug(item.getContentType());
		this.log.debug(item.getFileSize());
		this.log.debug(item.getFileName());
		if (null == item.getData()) {
			// meaning createTempFiles is set to true in the SeamFilter
			this.certificateBytes = FileUtils.readFileToByteArray(item
					.getFile());
		} else {
			this.certificateBytes = item.getData();
		}

		try {
			X509Certificate certificate = CryptoUtil
					.getCertificate(this.certificateBytes);
			this.log.debug("certificate: " + certificate);
			this.selectedRP.setCertificate(certificate);
		} catch (CertificateException e) {
			this.facesMessages.addToControl("upload", "Invalid certificate");
		}
	}

	@Override
	@Begin(join = true)
	public void uploadListenerPublic(UploadEvent event) throws IOException {
		UploadItem item = event.getUploadItem();
		this.log.debug(item.getContentType());
		this.log.debug(item.getFileSize());
		this.log.debug(item.getFileName());

		byte[] attributePublicKeyBytes;
		if (null == item.getData()) {
			// meaning createTempFiles is set to true in the SeamFilter
			attributePublicKeyBytes = FileUtils.readFileToByteArray(item
					.getFile());
		} else {
			attributePublicKeyBytes = item.getData();
		}

		try {
			this.selectedRP.setAttributePublicKey(CryptoUtil
					.getPublicFromPem(attributePublicKeyBytes));
		} catch (KeyLoadException e) {
			this.log.error(e);
			this.facesMessages.addToControl("upload_secret",
					"Failed to load key");
		}
	}

	@Override
	@Begin(join = true)
	public void uploadListenerLogo(UploadEvent event) throws IOException {
		UploadItem item = event.getUploadItem();
		this.log.debug(item.getContentType());
		this.log.debug(item.getFileSize());
		this.log.debug(item.getFileName());

		byte[] logoBytes;
		if (null == item.getData()) {
			// meaning createTempFiles is set to true in the SeamFilter
			logoBytes = FileUtils.readFileToByteArray(item.getFile());
		} else {
			logoBytes = item.getData();
		}

		this.selectedRP.setLogo(logoBytes);
	}

	@Override
	public List<String> getSourceAttributes() {
		List<AttributeEntity> attributes = this.attributeService
				.listAttributes();
		this.sourceAttributes = new LinkedList<String>();
		this.log.debug("attributes.size: " + attributes.size());
		this.log.debug("sourceAttributes.size: " + sourceAttributes.size());
		for (AttributeEntity attribute : attributes) {
			if (null != this.selectedAttributes
					&& !this.selectedAttributes.contains(attribute.getUri())) {
				this.sourceAttributes.add(attribute.getUri());
			}
		}
		this.log.debug("sourceAttributes.size: " + sourceAttributes.size());
		return this.sourceAttributes;
	}

	@Override
	public void setSourceAttributes(List<String> sourceAttributes) {
		this.sourceAttributes = sourceAttributes;
	}

	@Override
	public List<String> getSelectedAttributes() {
		this.log.debug("get selectedAttributes: " + selectedAttributes.size());
		return this.selectedAttributes;
	}

	@Override
	public void setSelectedAttributes(List<String> selectedAttributes) {
		this.log.debug("set selectedAttributes: " + selectedAttributes.size());
		this.selectedAttributes = selectedAttributes;
	}

	@Override
	public String getSelectedTab() {
		return this.selectedTab;
	}

	@Override
	public void setSelectedTab(String selectedTab) {
		this.selectedTab = selectedTab;
	}

	@Override
	public PublicKey getAttributePublicKey() {
		if (null == this.selectedRP.getAttributePublicKey()) {
			return null;
		}
		try {
			return CryptoUtil.getPublicKey(this.selectedRP
					.getAttributePublicKey());
		} catch (KeyLoadException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public void paint(OutputStream stream, Object object) throws IOException {
		if (null != this.selectedRP && null != this.selectedRP.getLogo()) {
			stream.write(this.selectedRP.getLogo());
			stream.close();
		}
	}

	@Override
	public long getTimeStamp() {
		return System.currentTimeMillis();
	}

	@Override
	public Boolean getRemoveCard() {
		return this.removeCard;
	}

	@Override
	public void setRemoveCard(Boolean removeCard) {
		this.removeCard = removeCard;
	}

	@Override
	public Boolean getOverrideRemoveCard() {
		return this.overrideRemoveCard;
	}

	@Override
	public void setOverrideRemoveCard(Boolean overrideRemoveCard) {
		this.overrideRemoveCard = overrideRemoveCard;
	}

	@Override
	public Boolean getBlocked() {
		return this.blocked;
	}

	@Override
	public void setBlocked(Boolean blocked) {
		this.blocked = blocked;
	}

	@Override
	public String getBlockedMessage() {
		return this.blockedMessage;
	}

	@Override
	public void setBlockedMessage(String blockedMessage) {
		this.blockedMessage = blockedMessage;
	}
}

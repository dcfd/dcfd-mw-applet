/*
 * eID Identity Provider Project.
 * Copyright (C) 2010-1012 FedICT.
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

/**
 * Enumeration of all possible configuration properties. This enumeration also
 * keeps track of the type of each property.
 * 
 * @author Wim Vandenhaute
 */
public enum ConfigProperty {

	ISSUER("default-issuer", String.class),

	TOKEN_VALIDITY("token-validity", Integer.class),

	HSTS("hsts", Boolean.class),

	XKMS_URL("xkms-url", String.class),

	XKMS_AUTH_TRUST_DOMAIN("xkms-auth-trust-domain", String.class),

	XKMS_IDENT_TRUST_DOMAIN("xkms-ident-trust-domain", String.class),

	HTTP_PROXY_ENABLED("http-proxy", Boolean.class),

	HTTP_PROXY_HOST("http-proxy-host", String.class),

	HTTP_PROXY_PORT("http-proxy-port", Integer.class),

	HMAC_SECRET("hmac-secret", String.class),

	ACTIVE_IDENTITY("active-identity", String.class),

	KEY_STORE_TYPE("key-store-type", KeyStoreType.class),

	KEY_STORE_PATH("key-store-path", String.class),

	KEY_STORE_SECRET("key-store-secret", String.class),

	KEY_ENTRY_SECRET("key-entry-secret", String.class),

	KEY_ENTRY_ALIAS("key-entry-alias", String.class),

	REMOVE_CARD("remove-card", Boolean.class),

	OVERRIDE_REMOVE_CARD("override-remove-card", Boolean.class),

	TRANSACTION_MESSAGE_SIGNING("transaction-message-signing", Boolean.class),

	BLOCKED("blocked", Boolean.class),

	BLOCKED_MESSAGE("blocked-message", String.class),

	OMIT_SECURE_CHANNEL_BINDING("omit-secure-channel-binding", Boolean.class),

	XSS_PROTECTION("xss-protection", Boolean.class),

	X_FRAME_OPTIONS("x-frame-options", XFrameOptions.class);

	private final String name;

	private final Class<?> type;

	private ConfigProperty(String name, Class<?> type) {
		this.name = name;
		this.type = type;
	}

	public String getName() {
		return this.name;
	}

	public Class<?> getType() {
		return this.type;
	}
}

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

package be.fedict.eid.idp.model;

public abstract class Constants {

	public static final String IDP_JNDI_CONTEXT = "be/fedict/eid/idp/";

	public static final String IDP_FLOW_SESSION_ATTRIBUTE = Constants.class
			.getName() + ".IdpFlow";
	public static final String RP_SESSION_ATTRIBUTE = Constants.class.getName()
			+ ".RP";
	public static final String RP_DOMAIN_SESSION_ATTRIBUTE = Constants.class
			.getName() + ".relyingPartyDomain";
}

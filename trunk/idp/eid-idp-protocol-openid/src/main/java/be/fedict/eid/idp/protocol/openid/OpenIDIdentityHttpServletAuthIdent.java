/*
 * eID Identity Provider Project.
 * Copyright (C) 2010-2011 FedICT.
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

package be.fedict.eid.idp.protocol.openid;

import java.util.List;

public class OpenIDIdentityHttpServletAuthIdent extends
		AbstractOpenIDIdentityHttpServlet {

	private static final long serialVersionUID = 1L;

	@Override
	protected String getPath() {
		return new OpenIDProtocolServiceAuthIdent().getPath();
	}

	@Override
	protected List<String> getAdditionalServiceTypes() {
		List<String> additionalServiceTypes = super.getAdditionalServiceTypes();
		additionalServiceTypes.add("http://openid.net/srv/ax/1.0");
		return additionalServiceTypes;
	}
}

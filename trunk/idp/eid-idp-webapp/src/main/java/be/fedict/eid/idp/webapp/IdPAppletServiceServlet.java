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

package be.fedict.eid.idp.webapp;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import be.fedict.eid.applet.service.AppletServiceServlet;
import be.fedict.eid.idp.spi.IdentityProviderProtocolService;

public class IdPAppletServiceServlet extends AppletServiceServlet {

	private static final long serialVersionUID = -3390647246478622619L;

	private static final Log LOG = LogFactory
			.getLog(IdPAppletServiceServlet.class);

	@Override
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		LOG.debug("doGet");

		response.sendRedirect("./main");
	}

	@Override
	protected void doPost(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		LOG.debug("doPost");

		IdentityProviderProtocolService protocolService = ProtocolEntryServlet
				.findProtocolService(request);
		if (null == protocolService) {
			// user navigated directly here without a processed authentication
			// request, abort...
			return;
		}

		super.doPost(request, response);
	}
}

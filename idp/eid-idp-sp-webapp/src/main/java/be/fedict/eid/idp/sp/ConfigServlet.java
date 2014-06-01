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

package be.fedict.eid.idp.sp;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public class ConfigServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;

	private static final Log LOG = LogFactory.getLog(ConfigServlet.class);

	private static final String PATH = "configuration";
	private static final String IDENTITY = "identity";
	private static final String IDP_BASE_LOCATION = "idpBaseLocation";
	private static final String ENCRYPT = "encrypt";
	private static final String USE_KEK = "useKeK";

	private static String idpIdentity = null;
	private static String idpBaseLocation = null;
	private static boolean encrypt = false;
	private static boolean useKeK = false;

	public static String getIdpIdentity() {
		return idpIdentity;
	}

	public static String getIdpBaseLocation(HttpServletRequest request) {

		String baseLocation = idpBaseLocation;
		if (null == baseLocation || baseLocation.trim().isEmpty()) {
			baseLocation = "https://" + request.getServerName() + ":"
					+ request.getServerPort() + "/eid-idp/";
		}
		if (!baseLocation.endsWith("/")) {
			baseLocation += '/';
		}
		idpBaseLocation = baseLocation;
		return baseLocation;
	}

	public static boolean isEncrypt() {
		return encrypt;
	}

	public static boolean isUseKeK() {
		return useKeK;
	}

	@Override
	protected void doPost(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		LOG.debug("doPost");

		onSaveConfig(request);

		doGet(request, response);
	}

	private void onSaveConfig(HttpServletRequest request) {

		LOG.debug("save config");

		idpIdentity = request.getParameter(IDENTITY);
		idpBaseLocation = request.getParameter(IDP_BASE_LOCATION);
		if (idpBaseLocation.trim().isEmpty()) {
			idpBaseLocation = null;
		}
		encrypt = null != request.getParameter(ENCRYPT);
		useKeK = null != request.getParameter(USE_KEK);
	}

	@Override
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		LOG.debug("doGet");

		response.setContentType("text/html");
		PrintWriter out = response.getWriter();

		out.println("<title>Test SP Configuration</title>");
		out.println("<body>");

		out.println("<h1>Test SP Configuration</h1>");

		out.println("<hr/>");

		out.println("<form action=\"" + PATH + "\" method=\"POST\">");

		// IdP Identity Thumbprint
		addTextInput(out, "IdP Identity Thumbprint", IDENTITY, idpIdentity);

		// IdP Base Location
		addTextInput(
				out,
				"IdP Base Location ( e.g. https://www.e-contract.be/eid-idp/ )",
				IDP_BASE_LOCATION, getIdpBaseLocation(request));

		// Encryption Configuration
		addCheckbox(out, "Encrypt", ENCRYPT, encrypt);
		addCheckbox(out, "Use KeK", USE_KEK, useKeK);

		// Submit
		addSubmit(out);

		// Home link
		out.println("<p />");
		out.println("<a href=\"./\">Home</a>");

		out.println("</body>");
		out.close();
	}

	private void addTextInput(PrintWriter out, String label, String name,
			String value) {

		out.print(label + "&nbsp; &nbsp;");
		String valueString = null != value ? value : "";
		out.println("<input type=\"text\" size=\"40\" name=\"" + name
				+ "\" value=\"" + valueString + "\" />");
		out.println("<br />");
	}

	private void addCheckbox(PrintWriter out, String label, String name,
			boolean checked) {

		out.print(label + "&nbsp; &nbsp;");
		if (checked) {
			out.println("<input type=\"checkbox\" name=\"" + name
					+ "\" value=\"" + name + "\" checked=\"yes\" />");
		} else {
			out.println("<input type=\"checkbox\" name=\"" + name
					+ "\" value=\"" + name + "\" />");
		}
		out.println("<br />");
	}

	private void addSubmit(PrintWriter out) {
		out.println("<input name=\"action\" type=\"submit\" value=\"save\"/>");
		out.println("<br />");
	}
}

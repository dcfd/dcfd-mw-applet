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
import java.io.StringWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.io.IOUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.openssl.PEMWriter;

public class PublicKeyServlet extends HttpServlet {

	private static final long serialVersionUID = 1L;

	private static final Log LOG = LogFactory.getLog(PublicKeyServlet.class);

	@Override
	protected void doGet(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		LOG.debug("doGet");
		String pemPrivate;
		try {
			pemPrivate = toPem(PkiServlet.getPrivateKeyEntry().getCertificate()
					.getPublicKey());
		} catch (Exception e) {
			LOG.error(e);
			return;
		}

		response.setContentType("text/plain");
		PrintWriter out = response.getWriter();
		out.print(pemPrivate);
		out.close();
	}

	private static String toPem(Object object) {

		StringWriter buffer = new StringWriter();
		try {
			PEMWriter writer = new PEMWriter(buffer);
			LOG.debug("toPem: " + object.getClass().getName());
			writer.writeObject(object);
			writer.close();
			return buffer.toString();
		} catch (Exception e) {
			throw new RuntimeException("Cannot convert object to "
					+ "PEM format: " + e.getMessage(), e);
		} finally {
			IOUtils.closeQuietly(buffer);
		}
	}

}

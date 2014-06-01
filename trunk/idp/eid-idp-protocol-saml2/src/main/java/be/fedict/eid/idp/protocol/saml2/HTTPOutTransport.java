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

package be.fedict.eid.idp.protocol.saml2;

import java.io.OutputStream;
import java.util.List;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.xml.security.credential.Credential;

import be.fedict.eid.idp.spi.ReturnResponse;

public class HTTPOutTransport implements
		org.opensaml.ws.transport.http.HTTPOutTransport {

	private static final Log LOG = LogFactory.getLog(HTTPOutTransport.class);

	private final ReturnResponse returnResponse;

	public HTTPOutTransport(ReturnResponse returnResponse) {
		this.returnResponse = returnResponse;
	}

	public void addParameter(String name, String value) {
		LOG.debug("addParameter: " + name);
		this.returnResponse.addAttribute(name, value);
	}

	public void sendRedirect(String url) {
		throw new UnsupportedOperationException();
	}

	public void setHeader(String name, String value) {
		throw new UnsupportedOperationException();
	}

	public void setStatusCode(int statusCode) {
		throw new UnsupportedOperationException();
	}

	public void setVersion(HTTP_VERSION version) {
		throw new UnsupportedOperationException();
	}

	public OutputStream getOutgoingStream() {
		throw new UnsupportedOperationException();
	}

	public void setAttribute(String name, Object value) {
		throw new UnsupportedOperationException();
	}

	public void setCharacterEncoding(String encoding) {
		throw new UnsupportedOperationException();
	}

	public Object getAttribute(String name) {
		throw new UnsupportedOperationException();
	}

	public String getCharacterEncoding() {
		throw new UnsupportedOperationException();
	}

	public Credential getLocalCredential() {
		throw new UnsupportedOperationException();
	}

	public Credential getPeerCredential() {
		throw new UnsupportedOperationException();
	}

	public boolean isAuthenticated() {
		throw new UnsupportedOperationException();
	}

	public boolean isConfidential() {
		throw new UnsupportedOperationException();
	}

	public boolean isIntegrityProtected() {
		throw new UnsupportedOperationException();
	}

	public void setAuthenticated(boolean authn) {
		throw new UnsupportedOperationException();
	}

	public void setConfidential(boolean conf) {
		throw new UnsupportedOperationException();
	}

	public void setIntegrityProtected(boolean integrity) {
		throw new UnsupportedOperationException();
	}

	public String getHTTPMethod() {
		throw new UnsupportedOperationException();
	}

	public String getHeaderValue(String name) {
		throw new UnsupportedOperationException();
	}

	public String getParameterValue(String name) {
		throw new UnsupportedOperationException();
	}

	public List<String> getParameterValues(String name) {
		throw new UnsupportedOperationException();
	}

	public int getStatusCode() {
		throw new UnsupportedOperationException();
	}

	public HTTP_VERSION getVersion() {
		throw new UnsupportedOperationException();
	}
}

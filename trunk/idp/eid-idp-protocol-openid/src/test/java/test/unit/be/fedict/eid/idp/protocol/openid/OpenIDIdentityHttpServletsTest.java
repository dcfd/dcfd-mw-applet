/*
 * eID Identity Provider Project.
 * Copyright (C) 2011 FedICT.
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

package test.unit.be.fedict.eid.idp.protocol.openid;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.InputStream;

import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.methods.GetMethod;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xpath.XPathAPI;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mortbay.jetty.testing.ServletTester;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.tidy.Tidy;

import be.fedict.eid.idp.protocol.openid.OpenIDIdentityHttpServletAuth;
import be.fedict.eid.idp.protocol.openid.OpenIDIdentityHttpServletAuthIdent;
import be.fedict.eid.idp.protocol.openid.OpenIDIdentityHttpServletIdent;

public class OpenIDIdentityHttpServletsTest {

	private static final Log LOG = LogFactory
			.getLog(OpenIDIdentityHttpServletsTest.class);

	private ServletTester servletTester;

	private String location;

	@After
	public void tearDown() throws Exception {
		if (null != this.servletTester) {
			this.servletTester.stop();
		}
	}

	@Before
	public void before() throws Exception {
		this.servletTester = new ServletTester();
		this.servletTester.addServlet(OpenIDIdentityHttpServletIdent.class,
				"/eid-idp/endpoints/openid/ident/*");
		this.servletTester.addServlet(OpenIDIdentityHttpServletAuth.class,
				"/eid-idp/endpoints/openid/auth/*");
		this.servletTester.addServlet(OpenIDIdentityHttpServletAuthIdent.class,
				"/eid-idp/endpoints/openid/auth-ident/*");
		this.servletTester.start();
		location = this.servletTester.createSocketConnector(true);
		LOG.debug("location: " + location);
	}

	@Test
	public void testHTMLIdentity() throws Exception {
		HttpClient httpClient = new HttpClient();
		String identLocation = this.location
				+ "/eid-idp/endpoints/openid/ident";
		GetMethod getMethod = new GetMethod(identLocation);

		int statusCode = httpClient.executeMethod(getMethod);
		LOG.debug("status code: " + statusCode);
		assertEquals(HttpServletResponse.SC_OK, statusCode);
		LOG.debug("result HTML: " + getMethod.getResponseBodyAsString());

		Tidy tidy = new Tidy();
		Document document = tidy.parseDOM(getMethod.getResponseBodyAsStream(),
				null);

		Node xrdsLocationNode = XPathAPI.selectSingleNode(document,
				"/html/head/meta[@http-equiv='X-XRDS-Location']/@content");
		assertNotNull(xrdsLocationNode);
		String xrdsLocation = xrdsLocationNode.getNodeValue();
		LOG.debug("XRDS location: " + xrdsLocation);

		getMethod = new GetMethod(identLocation + "/xrds");
		statusCode = httpClient.executeMethod(getMethod);
		assertEquals(HttpServletResponse.SC_OK, statusCode);
		LOG.debug("result XRDS: " + getMethod.getResponseBodyAsString());
		document = parseDocument(getMethod.getResponseBodyAsStream());

	}

	private Document parseDocument(InputStream inputStream) throws Exception {
		DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory
				.newInstance();
		documentBuilderFactory.setNamespaceAware(true);
		DocumentBuilder documentBuilder = documentBuilderFactory
				.newDocumentBuilder();
		Document document = documentBuilder.parse(inputStream);
		return document;
	}
}
